#include "SquadCookedMount.h"

#include "AssetRegistry/AssetRegistryModule.h"
#include "Async/UniqueLock.h"
#include "AssetRegistry/AssetRegistryState.h"
#include "AssetRegistry/IAssetRegistry.h"
#include "AssetRegistry/AssetData.h"
#include "AssetRegistry/AssetIdentifier.h"
#include "AssetRegistry/ARFilter.h"
#include "BlueprintActionDatabase.h"
#include "BlueprintNodeSpawner.h"
#include "Containers/Ticker.h"
#include "K2Node_CallFunction.h"
#include "EdGraphSchema_K2.h"
#include "Editor.h"
#include "Engine/Blueprint.h"
#include "Engine/BlueprintGeneratedClass.h"
#include "Engine/AssetManager.h"
#include "GenericPlatform/GenericPlatformFile.h"
#include "Hash/CityHash.h"
#include "HAL/FileManager.h"
#include "HAL/PlatformFileManager.h"
#include "HAL/PlatformTime.h"
#include "HAL/PlatformTLS.h"
#include "HAL/IConsoleManager.h"
#include "HAL/PlatformMisc.h"
#include "HAL/PlatformMemory.h"
#include "IO/IoChunkId.h"
#include "IO/IoContainerHeader.h"
#include "IO/IoDispatcher.h"
#include "IO/IoDispatcherBackend.h"
#include "IO/IoStatus.h"
#include "IO/PackageId.h"
#include "Interfaces/IPluginManager.h"
#include "IPlatformFilePak.h"
#include "Misc/App.h"
#include "Misc/AES.h"
#include "Misc/Compression.h"
#include "Misc/CommandLine.h"
#include "Misc/CoreDelegates.h"
#include "Misc/Crc.h"
#include "Misc/ConfigCacheIni.h"
#include "Misc/FileHelper.h"
#include "Misc/FeedbackContext.h"
#include "Misc/PackageName.h"
#include "Misc/Paths.h"
#include "Misc/ScopeLock.h"
#include "Misc/ScopeExit.h"
#include "Modules/ModuleManager.h"
#include "Serialization/AsyncLoading2.h"
#include "Serialization/AsyncLoadingEvents.h"
#include "Serialization/ArchiveReplaceObjectRef.h"
#include "Serialization/ArchiveUObject.h"
#include "Serialization/BufferArchive.h"
#include "Serialization/MemoryReader.h"
#include "ShaderCodeArchive.h"
#include "ShaderCompilerCore.h"
#include "DataDrivenShaderPlatformInfo.h"
#include "Serialization/PackageStore.h"
#include "UObject/Class.h"
#include "UObject/LinkerLoad.h"
#include "UObject/UObjectGlobals.h"
#include "UObject/UObjectThreadContext.h"
#include "Misc/OutputDeviceRedirector.h"
#include "UObject/Package.h"
#include "UObject/Script.h"
#include "UObject/UObjectHash.h"
#include "UObject/UObjectIterator.h"
#include "UObject/StrongObjectPtr.h"
#include "UObject/UnrealType.h"
#include "Materials/MaterialInterface.h"
#include "ShaderCodeLibrary.h"
#include "RHI.h"

DEFINE_LOG_CATEGORY_STATIC(LogSquadCookedMount, Log, All);

namespace SquadCookedMount
{
    static const TCHAR* CookedModsFolderName = TEXT("CookedMods");

    static bool IsCookAgainstFixedBaseEffective()
    {
        return FParse::Param(FCommandLine::Get(), TEXT("CookAgainstFixedBase"));
    }

    class FFindAssetRegistryVisitor final : public IPlatformFile::FDirectoryVisitor
    {
    public:
        TArray<FString> Matches;

        virtual bool Visit(const TCHAR* FilenameOrDirectory, bool bIsDirectory) override
        {
            if (!bIsDirectory)
            {
                const FString Path(FilenameOrDirectory);

                if (Path.EndsWith(TEXT("AssetRegistry.bin"), ESearchCase::IgnoreCase) ||
                    Path.EndsWith(TEXT("DevelopmentAssetRegistry.bin"), ESearchCase::IgnoreCase))
                {
                    Matches.AddUnique(Path);
                }
            }
            return true;
        }
    };

    static FString NormalizeFilename(FString In)
    {
        FPaths::NormalizeFilename(In);
        return In;
    }

    static FString NormalizeDirectory(FString In)
    {
        FPaths::NormalizeDirectoryName(In);
        if (!In.EndsWith(TEXT("/")))
        {
            In += TEXT("/");
        }
        return In;
    }

    static void AddUniqueCandidate(TArray<FString>& Candidates, const FString& Candidate)
    {
        if (!Candidate.IsEmpty())
        {
            Candidates.AddUnique(NormalizeFilename(Candidate));
        }
    }

    static bool DecryptPakBuffer(uint8* Data, int64 Size, const FGuid& EncryptionKeyGuid)
    {
        if (Size <= 0)
        {
            return true;
        }

        if (!IsAligned(Size, static_cast<int64>(FAES::AESBlockSize)) ||
            Size > MAX_uint32)
        {
            return false;
        }

        FPakCustomEncryptionDelegate& CustomEncryption =
            FPakPlatformFile::GetPakCustomEncryptionDelegate();
        if (CustomEncryption.IsBound())
        {
            CustomEncryption.Execute(
                Data,
                static_cast<uint32>(Size),
                EncryptionKeyGuid);
            return true;
        }

        FAES::FAESKey Key;
        FPakPlatformFile::GetPakEncryptionKey(Key, EncryptionKeyGuid);
        if (!Key.IsValid())
        {
            return false;
        }

        FAES::DecryptData(Data, static_cast<uint32>(Size), Key);
        return true;
    }

    // Read one UFS entry directly from an FPakFile without mounting the pak in
    // FPakPlatformFile and without touching IoStore/FPackageStore. This mirrors
    // the public pak metadata rules used by FPakPlatformFile for compressed and
    // encrypted entries, but does not call its private CreatePakFileHandle().
    static bool ReadPakEntryBytesPassive(
        FPakFile& PakFile,
        IPlatformFile* LowerLevel,
        const FPakEntry& Entry,
        TArray<uint8>& OutBytes)
    {
        OutBytes.Reset();

        if (!LowerLevel || Entry.Offset < 0 || Entry.IsDeleteRecord())
        {
            return false;
        }

        const FPakInfo& Info = PakFile.GetInfo();

        // Verify the payload's serialized entry header against the index entry,
        // matching FPakFileHandle's corruption check before reading the payload.
        {
            FSharedPakReader Reader = PakFile.GetSharedReader(LowerLevel);
            if (!Reader)
            {
                return false;
            }

            Reader->Seek(Entry.Offset);
            FPakEntry PayloadEntry;
            PayloadEntry.Serialize(Reader.GetArchive(), Info.Version);
            if (Reader->IsError() || !Entry.IndexDataEquals(PayloadEntry))
            {
                return false;
            }
        }

        if (Entry.CompressionMethodIndex == 0)
        {
            if (Entry.Size < 0 || Entry.Size > MAX_int32)
            {
                return false;
            }

            const int64 PayloadOffset =
                Entry.Offset + Entry.GetSerializedSize(Info.Version);
            const int64 RawReadSize = Entry.IsEncrypted()
                ? Align(Entry.Size, static_cast<int64>(FAES::AESBlockSize))
                : Entry.Size;

            if (RawReadSize < Entry.Size || RawReadSize > MAX_int32)
            {
                return false;
            }

            TArray<uint8> Raw;
            Raw.SetNumUninitialized(static_cast<int32>(RawReadSize));

            if (RawReadSize > 0)
            {
                FSharedPakReader Reader = PakFile.GetSharedReader(LowerLevel);
                if (!Reader)
                {
                    return false;
                }
                Reader->Seek(PayloadOffset);
                Reader->Serialize(Raw.GetData(), RawReadSize);
                if (Reader->IsError())
                {
                    return false;
                }
            }

            if (Entry.IsEncrypted() &&
                !DecryptPakBuffer(Raw.GetData(), RawReadSize, Info.EncryptionKeyGuid))
            {
                return false;
            }

            OutBytes.SetNumUninitialized(static_cast<int32>(Entry.Size));
            if (Entry.Size > 0)
            {
                FMemory::Memcpy(
                    OutBytes.GetData(),
                    Raw.GetData(),
                    static_cast<SIZE_T>(Entry.Size));
            }
            return true;
        }

        if (Entry.UncompressedSize < 0 ||
            Entry.UncompressedSize > MAX_int32 ||
            Entry.CompressionBlockSize == 0 ||
            Entry.CompressionBlocks.IsEmpty())
        {
            return false;
        }

        const TOptional<FName> CompressionMethodOptional =
            Info.TryGetCompressionMethod(Entry.CompressionMethodIndex);
        if (!CompressionMethodOptional.IsSet() ||
            CompressionMethodOptional.GetValue().IsNone())
        {
            return false;
        }
        const FName CompressionMethod = CompressionMethodOptional.GetValue();

        OutBytes.SetNumUninitialized(static_cast<int32>(Entry.UncompressedSize));
        int64 OutputOffset = 0;

        for (const FPakCompressedBlock& Block : Entry.CompressionBlocks)
        {
            if (Block.CompressedEnd < Block.CompressedStart)
            {
                OutBytes.Reset();
                return false;
            }

            const int64 CompressedSize = Block.CompressedEnd - Block.CompressedStart;
            if (CompressedSize <= 0 || CompressedSize > MAX_int32)
            {
                OutBytes.Reset();
                return false;
            }

            const int64 RawReadSize = Entry.IsEncrypted()
                ? Align(CompressedSize, static_cast<int64>(FAES::AESBlockSize))
                : CompressedSize;
            if (RawReadSize < CompressedSize || RawReadSize > MAX_int32)
            {
                OutBytes.Reset();
                return false;
            }

            const int64 BlockFileOffset =
                Block.CompressedStart +
                (Info.HasRelativeCompressedChunkOffsets() ? Entry.Offset : 0);

            TArray<uint8> Raw;
            Raw.SetNumUninitialized(static_cast<int32>(RawReadSize));
            {
                FSharedPakReader Reader = PakFile.GetSharedReader(LowerLevel);
                if (!Reader)
                {
                    OutBytes.Reset();
                    return false;
                }
                Reader->Seek(BlockFileOffset);
                Reader->Serialize(Raw.GetData(), RawReadSize);
                if (Reader->IsError())
                {
                    OutBytes.Reset();
                    return false;
                }
            }

            if (Entry.IsEncrypted() &&
                !DecryptPakBuffer(Raw.GetData(), RawReadSize, Info.EncryptionKeyGuid))
            {
                OutBytes.Reset();
                return false;
            }

            const int64 Remaining = Entry.UncompressedSize - OutputOffset;
            if (Remaining <= 0)
            {
                OutBytes.Reset();
                return false;
            }

            const int32 DecompressedSize = static_cast<int32>(FMath::Min<int64>(
                static_cast<int64>(Entry.CompressionBlockSize),
                Remaining));

            if (!FCompression::UncompressMemory(
                    CompressionMethod,
                    OutBytes.GetData() + OutputOffset,
                    DecompressedSize,
                    Raw.GetData(),
                    static_cast<int32>(CompressedSize)))
            {
                OutBytes.Reset();
                return false;
            }

            OutputOffset += DecompressedSize;
        }

        if (OutputOffset != Entry.UncompressedSize)
        {
            OutBytes.Reset();
            return false;
        }

        return true;
    }

    static FString ExtractPluginNameFromPakMountPoint(const FString& InMountPoint)
    {
        FString MountPoint = NormalizeDirectory(InMountPoint);

        const FString ModsMarker = TEXT("/Plugins/Mods/");
        int32 MarkerIndex =
            MountPoint.Find(ModsMarker, ESearchCase::IgnoreCase, ESearchDir::FromStart);

        int32 StartIndex = INDEX_NONE;

        if (MarkerIndex != INDEX_NONE)
        {
            StartIndex = MarkerIndex + ModsMarker.Len();
        }
        else
        {
            const FString PluginsMarker = TEXT("/Plugins/");
            MarkerIndex =
                MountPoint.Find(PluginsMarker, ESearchCase::IgnoreCase, ESearchDir::FromStart);

            if (MarkerIndex != INDEX_NONE)
            {
                StartIndex = MarkerIndex + PluginsMarker.Len();
            }
        }

        if (StartIndex == INDEX_NONE || StartIndex >= MountPoint.Len())
        {
            return FString();
        }

        FString Remainder = MountPoint.Mid(StartIndex);
        Remainder.RemoveFromEnd(TEXT("/"));

        TArray<FString> Segments;
        Remainder.ParseIntoArray(Segments, TEXT("/"), true);


        return Segments.Num() > 0 ? Segments.Last() : FString();
    }

    static FString RemoveUtocExtension(const FString& UtocPath)
    {
        FString Result = NormalizeFilename(UtocPath);
        Result.RemoveFromEnd(TEXT(".utoc"), ESearchCase::IgnoreCase);
        return Result;
    }

    static FString GetShaderFormatAndPlatform()
    {
        const FName PlatformName =
            FDataDrivenShaderPlatformInfo::GetName(GMaxRHIShaderPlatform);

        const FName ShaderFormatName =
            LegacyShaderPlatformToShaderFormat(GMaxRHIShaderPlatform);

        return ShaderFormatName.ToString() + TEXT("-") + PlatformName.ToString();
    }

    static FString GetLegacyShaderArchiveFilename(const FString& LogicalName)
    {
        return FString::Printf(
            TEXT("ShaderArchive-%s-%s.ushaderbytecode"),
            *LogicalName,
            *GetShaderFormatAndPlatform());
    }

    static bool IsLegacyShaderArchiveV2(const FString& Filename)
    {
        TArray<uint8> Bytes;
        if (!FFileHelper::LoadFileToArray(Bytes, *Filename) ||
            Bytes.Num() < static_cast<int32>(sizeof(uint32)))
        {
            return false;
        }

        uint32 Version = 0;
        FMemory::Memcpy(&Version, Bytes.GetData(), sizeof(Version));
        return Version == 2;
    }

    static FString ParseLogicalShaderLibraryName(const FString& Filename)
    {
        FString Clean = FPaths::GetCleanFilename(Filename);
        const FString Prefix = TEXT("ShaderArchive-");
        const FString Suffix =
            FString::Printf(
                TEXT("-%s.ushaderbytecode"),
                *GetShaderFormatAndPlatform());

        if (!Clean.StartsWith(Prefix, ESearchCase::IgnoreCase) ||
            !Clean.EndsWith(Suffix, ESearchCase::IgnoreCase))
        {
            return FString();
        }

        FString Logical =
            Clean.Mid(Prefix.Len(), Clean.Len() - Prefix.Len() - Suffix.Len());

        return Logical;
    }

    struct FShaderIoStoreReaderSet
    {
        struct FReaderEntry
        {
            FString UtocPath;
            TUniquePtr<FIoStoreReader> Reader;
        };

        TArray<FReaderEntry> Readers;

        bool AddUtoc(const FString& UtocPath)
        {
            FReaderEntry Entry;
            Entry.UtocPath = NormalizeFilename(UtocPath);
            Entry.Reader = MakeUnique<FIoStoreReader>();

            TMap<FGuid, FAES::FAESKey> DecryptionKeys;
            const FIoStatus Status =
                Entry.Reader->Initialize(
                    RemoveUtocExtension(Entry.UtocPath),
                    DecryptionKeys);

            if (!Status.IsOk())
            {
                UE_LOG(
                    LogSquadCookedMount,
                    VeryVerbose,
                    TEXT("Shader rebuild: skip UTOC '%s': %s"),
                    *Entry.UtocPath,
                    *Status.ToString()
                );
                return false;
            }

            Readers.Add(MoveTemp(Entry));
            return true;
        }

        bool ReadChunk(
            const FIoChunkId& ChunkId,
            TArray<uint8>& OutBytes,
            FString* OutSourceUtoc = nullptr) const
        {
            OutBytes.Reset();

            for (const FReaderEntry& Entry : Readers)
            {
                if (!Entry.Reader)
                {
                    continue;
                }

                const TIoStatusOr<FIoStoreTocChunkInfo> InfoResult =
                    Entry.Reader->GetChunkInfo(ChunkId);

                if (!InfoResult.IsOk())
                {
                    continue;
                }

                TIoStatusOr<FIoBuffer> ReadResult =
                    Entry.Reader->Read(ChunkId, FIoReadOptions());

                if (!ReadResult.IsOk())
                {
                    continue;
                }

                FIoBuffer Buffer = ReadResult.ConsumeValueOrDie();

                if (Buffer.DataSize() == 0 ||
                    Buffer.DataSize() > static_cast<uint64>(MAX_int32))
                {
                    return false;
                }

                OutBytes.SetNumUninitialized(
                    static_cast<int32>(Buffer.DataSize()));

                FMemory::Memcpy(
                    OutBytes.GetData(),
                    Buffer.Data(),
                    Buffer.DataSize());

                if (OutSourceUtoc)
                {
                    *OutSourceUtoc = Entry.UtocPath;
                }

                return true;
            }

            return false;
        }
    };

    struct FShaderLibraryCandidate
    {
        FIoChunkId ChunkId;
        FString LogicalName;
        FString SourceUtoc;
    };

    static void DiscoverShaderLibraries(
        const FShaderIoStoreReaderSet& ReaderSet,
        const TArray<FString>& FallbackLogicalNames,
        TArray<FShaderLibraryCandidate>& OutCandidates)
    {
        OutCandidates.Reset();

        const FName ShaderFormatName =
            LegacyShaderPlatformToShaderFormat(GMaxRHIShaderPlatform);

        for (const FShaderIoStoreReaderSet::FReaderEntry& Entry : ReaderSet.Readers)
        {
            if (!Entry.Reader)
            {
                continue;
            }

            Entry.Reader->EnumerateChunks(
                [&OutCandidates, &Entry, &FallbackLogicalNames, ShaderFormatName]
                (FIoStoreTocChunkInfo&& Info)
                {
                    if (Info.ChunkType != EIoChunkType::ShaderCodeLibrary)
                    {
                        return true;
                    }

                    FString LogicalName;

                    if (Info.bHasValidFileName)
                    {
                        LogicalName =
                            ParseLogicalShaderLibraryName(Info.FileName);
                    }

                    if (LogicalName.IsEmpty())
                    {
                        for (const FString& FallbackName : FallbackLogicalNames)
                        {
                            const FIoChunkId Expected =
                                FIoStoreShaderCodeArchive::GetShaderCodeArchiveChunkId(
                                    FallbackName,
                                    ShaderFormatName);

                            if (Expected == Info.Id)
                            {
                                LogicalName = FallbackName;
                                break;
                            }
                        }
                    }

                    FShaderLibraryCandidate Candidate;
                    Candidate.ChunkId = Info.Id;
                    Candidate.LogicalName = LogicalName;
                    Candidate.SourceUtoc = Entry.UtocPath;
                    OutCandidates.Add(MoveTemp(Candidate));

                    return true;
                });
        }
    }

    static bool RebuildLegacyShaderArchive(
        const FShaderIoStoreReaderSet& ReaderSet,
        const FShaderLibraryCandidate& Candidate,
        const FString& OutputDirectory,
        FString& OutFilename)
    {
        OutFilename.Reset();

        if (Candidate.LogicalName.IsEmpty())
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Shader rebuild: ShaderCodeLibrary chunk has no resolvable logical name | source='%s'"),
                *Candidate.SourceUtoc
            );
            return false;
        }

        const FString OutputPath =
            NormalizeFilename(
                FPaths::Combine(
                    OutputDirectory,
                    GetLegacyShaderArchiveFilename(Candidate.LogicalName)));

        const FDateTime SourceTime =
            IFileManager::Get().GetTimeStamp(*Candidate.SourceUtoc);

        const FDateTime OutputTime =
            IFileManager::Get().GetTimeStamp(*OutputPath);

        if (IsLegacyShaderArchiveV2(OutputPath) &&
            OutputTime >= SourceTime)
        {
            OutFilename = OutputPath;

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("Shader cache HIT | logical='%s' | file='%s'"),
                *Candidate.LogicalName,
                *OutputPath
            );
            return true;
        }

        TArray<uint8> LibraryBytes;
        if (!ReaderSet.ReadChunk(Candidate.ChunkId, LibraryBytes))
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Shader rebuild: failed to read ShaderCodeLibrary chunk | logical='%s'"),
                *Candidate.LogicalName
            );
            return false;
        }

        FMemoryReader LibraryReader(LibraryBytes, true);

        uint32 IoStoreShaderLibraryVersion = 0;
        LibraryReader << IoStoreShaderLibraryVersion;

        if (IoStoreShaderLibraryVersion != 1)
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Shader rebuild: unsupported IoStore shader library version=%u | logical='%s'"),
                IoStoreShaderLibraryVersion,
                *Candidate.LogicalName
            );
            return false;
        }

        FIoStoreShaderCodeArchiveHeader IoHeader;
        LibraryReader << IoHeader;

        if (LibraryReader.IsError() ||
            IoHeader.ShaderEntries.Num() != IoHeader.ShaderHashes.Num() ||
            IoHeader.ShaderMapEntries.Num() != IoHeader.ShaderMapHashes.Num() ||
            IoHeader.ShaderGroupEntries.Num() != IoHeader.ShaderGroupIoHashes.Num())
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Shader rebuild: invalid IoStore shader header | logical='%s' | shaders=%d hashes=%d maps=%d groups=%d groupIds=%d"),
                *Candidate.LogicalName,
                IoHeader.ShaderEntries.Num(),
                IoHeader.ShaderHashes.Num(),
                IoHeader.ShaderMapEntries.Num(),
                IoHeader.ShaderGroupEntries.Num(),
                IoHeader.ShaderGroupIoHashes.Num()
            );
            return false;
        }

        TArray<TArray<uint8>> ShaderCode;
        ShaderCode.SetNum(IoHeader.ShaderEntries.Num());

        int64 TotalUncompressedShaderBytes = 0;

        for (int32 GroupIndex = 0;
             GroupIndex < IoHeader.ShaderGroupEntries.Num();
             ++GroupIndex)
        {
            const FIoStoreShaderGroupEntry& GroupEntry =
                IoHeader.ShaderGroupEntries[GroupIndex];

            if (GroupEntry.ShaderIndicesOffset + GroupEntry.NumShaders >
                static_cast<uint32>(IoHeader.ShaderIndices.Num()))
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("Shader rebuild: invalid shader group index range | logical='%s' | group=%d"),
                    *Candidate.LogicalName,
                    GroupIndex
                );
                return false;
            }

            TArray<uint8> GroupStoredBytes;
            FString GroupSourceUtoc;

            if (!ReaderSet.ReadChunk(
                    IoHeader.ShaderGroupIoHashes[GroupIndex],
                    GroupStoredBytes,
                    &GroupSourceUtoc))
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("Shader rebuild: missing ShaderCode group chunk | logical='%s' | group=%d"),
                    *Candidate.LogicalName,
                    GroupIndex
                );
                return false;
            }

            TArray<uint8> GroupUncompressedBytes;

            if (GroupStoredBytes.Num() ==
                static_cast<int32>(GroupEntry.UncompressedSize))
            {
                // Some readers/builds can expose an already decompressed group.
                GroupUncompressedBytes = MoveTemp(GroupStoredBytes);
            }
            else if (GroupEntry.IsGroupCompressed())
            {
                if (GroupStoredBytes.Num() !=
                    static_cast<int32>(GroupEntry.CompressedSize))
                {
                    UE_LOG(
                        LogSquadCookedMount,
                        Warning,
                        TEXT("Shader rebuild: compressed group size mismatch | logical='%s' | group=%d | header=%u | read=%d | source='%s'"),
                        *Candidate.LogicalName,
                        GroupIndex,
                        GroupEntry.CompressedSize,
                        GroupStoredBytes.Num(),
                        *GroupSourceUtoc
                    );
                }

                GroupUncompressedBytes.SetNumUninitialized(
                    static_cast<int32>(GroupEntry.UncompressedSize));

                // UE 5.7 UnrealPak groups IoStore shader code with the shader
                // archive's Oodle path. Use the engine's own exported decoder
                // rather than reimplementing retoc's codec probing.
                ShaderCodeArchive::DecompressShaderWithOodle(
                    GroupUncompressedBytes.GetData(),
                    GroupEntry.UncompressedSize,
                    GroupStoredBytes.GetData(),
                    GroupStoredBytes.Num());
            }
            else
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("Shader rebuild: uncompressed group has unexpected byte count | logical='%s' | group=%d | expected=%u | read=%d"),
                    *Candidate.LogicalName,
                    GroupIndex,
                    GroupEntry.UncompressedSize,
                    GroupStoredBytes.Num()
                );
                return false;
            }

            if (GroupUncompressedBytes.Num() !=
                static_cast<int32>(GroupEntry.UncompressedSize))
            {
                return false;
            }

            for (uint32 Member = 0;
                 Member < GroupEntry.NumShaders;
                 ++Member)
            {
                const uint32 ShaderIndicesIndex =
                    GroupEntry.ShaderIndicesOffset + Member;

                const uint32 ShaderIndex =
                    IoHeader.ShaderIndices[ShaderIndicesIndex];

                if (ShaderIndex >=
                    static_cast<uint32>(IoHeader.ShaderEntries.Num()))
                {
                    return false;
                }

                const FIoStoreShaderCodeEntry& IoShaderEntry =
                    IoHeader.ShaderEntries[ShaderIndex];

                if (IoShaderEntry.ShaderGroupIndex !=
                    static_cast<uint64>(GroupIndex))
                {
                    UE_LOG(
                        LogSquadCookedMount,
                        Warning,
                        TEXT("Shader rebuild: group ownership mismatch | logical='%s' | shader=%u | expectedGroup=%d | actualGroup=%" UINT64_FMT),
                        *Candidate.LogicalName,
                        ShaderIndex,
                        GroupIndex,
                        static_cast<uint64>(IoShaderEntry.ShaderGroupIndex)
                    );
                    return false;
                }

                const uint64 ShaderSize =
                    IoHeader.GetShaderUncompressedSize(ShaderIndex);

                const uint64 ShaderOffset =
                    IoShaderEntry.UncompressedOffsetInGroup;

                if (ShaderSize == 0 ||
                    ShaderOffset + ShaderSize >
                        static_cast<uint64>(GroupUncompressedBytes.Num()) ||
                    ShaderSize > static_cast<uint64>(MAX_int32))
                {
                    UE_LOG(
                        LogSquadCookedMount,
                        Warning,
                        TEXT("Shader rebuild: invalid shader range | logical='%s' | shader=%u | offset=%" UINT64_FMT " | size=%" UINT64_FMT " | groupSize=%d"),
                        *Candidate.LogicalName,
                        ShaderIndex,
                        static_cast<uint64>(ShaderOffset),
                        static_cast<uint64>(ShaderSize),
                        GroupUncompressedBytes.Num()
                    );
                    return false;
                }

                TArray<uint8>& Dest = ShaderCode[ShaderIndex];
                Dest.SetNumUninitialized(static_cast<int32>(ShaderSize));

                FMemory::Memcpy(
                    Dest.GetData(),
                    GroupUncompressedBytes.GetData() + ShaderOffset,
                    ShaderSize);

                TotalUncompressedShaderBytes += ShaderSize;
            }
        }

        for (int32 ShaderIndex = 0;
             ShaderIndex < ShaderCode.Num();
             ++ShaderIndex)
        {
            if (ShaderCode[ShaderIndex].IsEmpty())
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("Shader rebuild: shader %d has no reconstructed code | logical='%s'"),
                    ShaderIndex,
                    *Candidate.LogicalName
                );
                return false;
            }
        }

        FSerializedShaderArchive Legacy;
        Legacy.ShaderMapHashes = IoHeader.ShaderMapHashes;
        Legacy.ShaderHashes = IoHeader.ShaderHashes;
        Legacy.ShaderIndices = IoHeader.ShaderIndices;
        Legacy.ShaderEntries.SetNum(IoHeader.ShaderEntries.Num());
        Legacy.ShaderMapEntries.SetNum(IoHeader.ShaderMapEntries.Num());

        TArray<uint8> FlatShaderCode;
        if (TotalUncompressedShaderBytes > 0 &&
            TotalUncompressedShaderBytes <= MAX_int32)
        {
            FlatShaderCode.Reserve(
                static_cast<int32>(TotalUncompressedShaderBytes));
        }

        for (int32 ShaderIndex = 0;
             ShaderIndex < ShaderCode.Num();
             ++ShaderIndex)
        {
            const int64 Offset = FlatShaderCode.Num();

            const TArray<uint8>& Code = ShaderCode[ShaderIndex];

            FShaderCodeEntry& LegacyEntry =
                Legacy.ShaderEntries[ShaderIndex];

            LegacyEntry.Offset = Offset;
            LegacyEntry.Size = Code.Num();
            LegacyEntry.UncompressedSize = Code.Num();
            LegacyEntry.Frequency =
                static_cast<uint8>(
                    IoHeader.ShaderEntries[ShaderIndex].Frequency);

            FlatShaderCode.Append(Code);
        }

        // Keep the legacy archive simple and robust: every shader referenced
        // by a shader map gets its own preload range. retoc optimizes this by
        // grouping unique shaders, but individual ranges are semantically
        // equivalent and avoid recompressing shader code.
        for (int32 ShaderMapIndex = 0;
             ShaderMapIndex < IoHeader.ShaderMapEntries.Num();
             ++ShaderMapIndex)
        {
            const FIoStoreShaderMapEntry& IoMapEntry =
                IoHeader.ShaderMapEntries[ShaderMapIndex];

            if (IoMapEntry.ShaderIndicesOffset + IoMapEntry.NumShaders >
                static_cast<uint32>(IoHeader.ShaderIndices.Num()))
            {
                return false;
            }

            FShaderMapEntry& LegacyMapEntry =
                Legacy.ShaderMapEntries[ShaderMapIndex];

            LegacyMapEntry.ShaderIndicesOffset =
                IoMapEntry.ShaderIndicesOffset;
            LegacyMapEntry.NumShaders =
                IoMapEntry.NumShaders;
            LegacyMapEntry.FirstPreloadIndex =
                Legacy.PreloadEntries.Num();

            TSet<uint32> SeenShaders;

            for (uint32 I = 0; I < IoMapEntry.NumShaders; ++I)
            {
                const uint32 ShaderIndex =
                    IoHeader.ShaderIndices[
                        IoMapEntry.ShaderIndicesOffset + I];

                if (!Legacy.ShaderEntries.IsValidIndex(
                        static_cast<int32>(ShaderIndex)) ||
                    SeenShaders.Contains(ShaderIndex))
                {
                    continue;
                }

                SeenShaders.Add(ShaderIndex);

                const FShaderCodeEntry& ShaderEntry =
                    Legacy.ShaderEntries[ShaderIndex];

                FFileCachePreloadEntry& Preload =
                    Legacy.PreloadEntries.AddDefaulted_GetRef();

                Preload.Offset =
                    static_cast<int64>(ShaderEntry.Offset);
                Preload.Size =
                    static_cast<int64>(ShaderEntry.Size);
            }

            LegacyMapEntry.NumPreloadEntries =
                Legacy.PreloadEntries.Num() -
                LegacyMapEntry.FirstPreloadIndex;
        }

        IFileManager::Get().MakeDirectory(*OutputDirectory, true);

        FBufferArchive Output;

        uint32 LegacyVersion = 2;
        Output << LegacyVersion;

        // Serialize exactly the six runtime arrays used by the UE 5.7
        // FShaderCodeArchive loose format. This mirrors retoc's to-legacy
        // writer while using Squad's own UE structs/operators.
        Output << Legacy.ShaderMapHashes;
        Output << Legacy.ShaderHashes;
        Output << Legacy.ShaderMapEntries;
        Output << Legacy.ShaderEntries;
        Output << Legacy.PreloadEntries;
        Output << Legacy.ShaderIndices;

        if (!FlatShaderCode.IsEmpty())
        {
            Output.Serialize(
                FlatShaderCode.GetData(),
                FlatShaderCode.Num());
        }

        if (Output.IsError() ||
            !FFileHelper::SaveArrayToFile(Output, *OutputPath))
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Shader rebuild: failed to write '%s'"),
                *OutputPath
            );
            return false;
        }

        OutFilename = OutputPath;

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Shader cache BUILT | logical='%s' | shaders=%d | maps=%d | groups=%d | code=%.2f MiB | file='%s'"),
            *Candidate.LogicalName,
            Legacy.ShaderEntries.Num(),
            Legacy.ShaderMapEntries.Num(),
            IoHeader.ShaderGroupEntries.Num(),
            static_cast<double>(FlatShaderCode.Num()) / (1024.0 * 1024.0),
            *OutputPath
        );

        return true;
    }

    static int32 RebuildLibrariesFromReaderSet(
        const FShaderIoStoreReaderSet& ReaderSet,
        const TArray<FString>& DesiredLogicalNames,
        const FString& FallbackRootName,
        const FString& OutputDirectory)
    {
        TArray<FString> FallbackNames = DesiredLogicalNames;

        if (!FallbackRootName.IsEmpty())
        {
            FallbackNames.AddUnique(FallbackRootName);
        }

        TArray<FShaderLibraryCandidate> Candidates;
        DiscoverShaderLibraries(
            ReaderSet,
            FallbackNames,
            Candidates);

        // If a mod container has exactly one unnamed shader library, the
        // plugin mount root is a safe fallback for that library's logical name.
        if (!FallbackRootName.IsEmpty())
        {
            int32 UnnamedCount = 0;
            int32 UnnamedIndex = INDEX_NONE;

            for (int32 I = 0; I < Candidates.Num(); ++I)
            {
                if (Candidates[I].LogicalName.IsEmpty())
                {
                    ++UnnamedCount;
                    UnnamedIndex = I;
                }
            }

            if (UnnamedCount == 1)
            {
                Candidates[UnnamedIndex].LogicalName =
                    FallbackRootName;
            }
        }

        int32 BuiltOrCached = 0;

        for (const FShaderLibraryCandidate& Candidate : Candidates)
        {
            if (Candidate.LogicalName.IsEmpty())
            {
                continue;
            }

            if (!DesiredLogicalNames.IsEmpty() &&
                !DesiredLogicalNames.Contains(Candidate.LogicalName))
            {
                bool bMatchesChunkedDesired = false;

                for (const FString& Desired : DesiredLogicalNames)
                {
                    if (Candidate.LogicalName.StartsWith(
                            Desired + TEXT("_Chunk"),
                            ESearchCase::IgnoreCase))
                    {
                        bMatchesChunkedDesired = true;
                        break;
                    }
                }

                if (!bMatchesChunkedDesired)
                {
                    continue;
                }
            }

            FString OutputFilename;
            if (RebuildLegacyShaderArchive(
                    ReaderSet,
                    Candidate,
                    OutputDirectory,
                    OutputFilename))
            {
                ++BuiltOrCached;
            }
        }

        return BuiltOrCached;
    }

    static FString NormalizeDumpClassPath(FString InPath)
    {
        InPath.TrimStartAndEndInline();
        InPath.TrimQuotesInline();

        if (InPath.IsEmpty())
        {
            return InPath;
        }

        // Accept export-text paths such as:
        // /Script/Engine.BlueprintGeneratedClass'/ExternalCookedMod/...Foo.Foo_C'
        const FString ObjectPath = FPackageName::ExportTextPathToObjectPath(InPath);
        if (!ObjectPath.IsEmpty())
        {
            InPath = ObjectPath;
        }

        // Also accept a long package name and derive the generated-class object path.
        if (!InPath.Contains(TEXT(".")) && InPath.StartsWith(TEXT("/")))
        {
            const FString AssetName = FPackageName::GetLongPackageAssetName(InPath);
            if (!AssetName.IsEmpty())
            {
                InPath = FString::Printf(TEXT("%s.%s_C"), *InPath, *AssetName);
            }
        }

        return InPath;
    }

    static FString DescribeFunctionFlags(const UFunction* Function)
    {
        if (!Function)
        {
            return TEXT("<null>");
        }

        TArray<FString> Flags;

        const auto AddFlag = [&Flags, Function](EFunctionFlags Flag, const TCHAR* Name)
        {
            if (Function->HasAnyFunctionFlags(Flag))
            {
                Flags.Emplace(Name);
            }
        };

        AddFlag(FUNC_Public, TEXT("Public"));
        AddFlag(FUNC_Protected, TEXT("Protected"));
        AddFlag(FUNC_Private, TEXT("Private"));
        AddFlag(FUNC_Static, TEXT("Static"));
        AddFlag(FUNC_Const, TEXT("Const"));
        AddFlag(FUNC_Native, TEXT("Native"));
        AddFlag(FUNC_Event, TEXT("Event"));
        AddFlag(FUNC_BlueprintEvent, TEXT("BlueprintEvent"));
        AddFlag(FUNC_BlueprintCallable, TEXT("BlueprintCallable"));
        AddFlag(FUNC_BlueprintPure, TEXT("BlueprintPure"));
        AddFlag(FUNC_Exec, TEXT("Exec"));
        AddFlag(FUNC_Net, TEXT("Net"));
        AddFlag(FUNC_NetServer, TEXT("NetServer"));
        AddFlag(FUNC_NetClient, TEXT("NetClient"));
        AddFlag(FUNC_NetMulticast, TEXT("NetMulticast"));
        AddFlag(FUNC_NetReliable, TEXT("NetReliable"));

        return Flags.IsEmpty() ? TEXT("None") : FString::Join(Flags, TEXT("|"));
    }

    static FString DescribeParameterFlags(const FProperty* Property)
    {
        if (!Property)
        {
            return TEXT("<null>");
        }

        TArray<FString> Flags;
        if (Property->HasAnyPropertyFlags(CPF_ReturnParm)) Flags.Emplace(TEXT("Return"));
        if (Property->HasAnyPropertyFlags(CPF_OutParm)) Flags.Emplace(TEXT("Out"));
        if (Property->HasAnyPropertyFlags(CPF_ReferenceParm)) Flags.Emplace(TEXT("Ref"));
        if (Property->HasAnyPropertyFlags(CPF_ConstParm)) Flags.Emplace(TEXT("Const"));

        return Flags.IsEmpty() ? TEXT("In") : FString::Join(Flags, TEXT("|"));
    }

    static void DumpSingleFunction(const UClass* RequestedClass, const UFunction* Function)
    {
        if (!Function)
        {
            return;
        }

        const UClass* DeclaringClass = Cast<UClass>(Function->GetOuter());
        const bool bDeclaredHere = DeclaringClass == RequestedClass;

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("  Function '%s' | declared=%s | owner='%s' | flags=0x%08X [%s] | parms=%d | returnOffset=%d"),
            *Function->GetName(),
            bDeclaredHere ? TEXT("HERE") : TEXT("INHERITED"),
            DeclaringClass ? *DeclaringClass->GetPathName() : TEXT("<unknown>"),
            static_cast<uint32>(Function->FunctionFlags),
            *DescribeFunctionFlags(Function),
            Function->NumParms,
            Function->ReturnValueOffset
        );

        const FString Category = Function->GetMetaData(FName(TEXT("Category")));
        const FString DisplayName = Function->GetMetaData(FName(TEXT("DisplayName")));
        const bool bInternalOnly = Function->HasMetaData(FName(TEXT("BlueprintInternalUseOnly")));
        const bool bBlueprintProtected = Function->HasMetaData(FName(TEXT("BlueprintProtected")));
        const bool bDeprecated = Function->HasMetaData(FName(TEXT("DeprecatedFunction")));

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("    metadata | Category='%s' | DisplayName='%s' | InternalOnly=%s | BlueprintProtected=%s | Deprecated=%s"),
            *Category,
            *DisplayName,
            bInternalOnly ? TEXT("YES") : TEXT("NO"),
            bBlueprintProtected ? TEXT("YES") : TEXT("NO"),
            bDeprecated ? TEXT("YES") : TEXT("NO")
        );

        int32 ParameterIndex = 0;
        for (TFieldIterator<FProperty> It(Function); It; ++It)
        {
            const FProperty* Property = *It;
            if (!Property || !Property->HasAnyPropertyFlags(CPF_Parm))
            {
                continue;
            }

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("    Param[%d] '%s' | type='%s' | flags=%s | propertyFlags=0x%016llX"),
                ParameterIndex++,
                *Property->GetName(),
                *Property->GetCPPType(),
                *DescribeParameterFlags(Property),
                static_cast<unsigned long long>(Property->GetPropertyFlags())
            );
        }
    }

    static UClass* ResolveDumpClass(const FString& RawPath, FString& OutResolvedPath)
    {
        OutResolvedPath = NormalizeDumpClassPath(RawPath);
        if (OutResolvedPath.IsEmpty())
        {
            return nullptr;
        }

        UClass* Class = FindObject<UClass>(nullptr, *OutResolvedPath);
        if (!Class)
        {
            Class = LoadObject<UClass>(nullptr, *OutResolvedPath);
        }

        // If the user supplied the Blueprint asset object path rather than _C,
        // retry as the generated class object path.
        if (!Class && OutResolvedPath.Contains(TEXT(".")) && !OutResolvedPath.EndsWith(TEXT("_C")))
        {
            FString PackagePart;
            FString ObjectPart;
            if (OutResolvedPath.Split(TEXT("."), &PackagePart, &ObjectPart, ESearchCase::CaseSensitive, ESearchDir::FromEnd))
            {
                const FString GeneratedClassPath =
                    FString::Printf(TEXT("%s.%s_C"), *PackagePart, *ObjectPart);

                Class = FindObject<UClass>(nullptr, *GeneratedClassPath);
                if (!Class)
                {
                    Class = LoadObject<UClass>(nullptr, *GeneratedClassPath);
                }

                if (Class)
                {
                    OutResolvedPath = GeneratedClassPath;
                }
            }
        }

        return Class;
    }

    static void HandleDumpClassCommand(const TArray<FString>& Args)
    {
        if (Args.IsEmpty())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("Usage: SquadCookedMount.DumpClass <ClassPath> [Function Name Filter]")
            );
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("Example: SquadCookedMount.DumpClass /ExternalCookedMod/Blueprints/BP_Example.BP_Example_C ExampleFunction")
            );
            return;
        }

        const FString RawClassPath = Args[0];

        FString FunctionFilter;
        if (Args.Num() > 1)
        {
            TArray<FString> FilterParts;
            for (int32 Index = 1; Index < Args.Num(); ++Index)
            {
                FilterParts.Add(Args[Index]);
            }
            FunctionFilter = FString::Join(FilterParts, TEXT(" "));
            FunctionFilter.TrimStartAndEndInline();
        }

        FString ResolvedPath;
        UClass* Class = ResolveDumpClass(RawClassPath, ResolvedPath);

        if (!Class)
        {
            UE_LOG(
                LogSquadCookedMount,
                Error,
                TEXT("DumpClass: failed to resolve/load UClass | input='%s' | normalized='%s'"),
                *RawClassPath,
                *ResolvedPath
            );
            return;
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("================ SquadCookedMount.DumpClass ================")
        );
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Class='%s' | input='%s' | super='%s' | flags=0x%08X | filter='%s'"),
            *Class->GetPathName(),
            *RawClassPath,
            Class->GetSuperClass() ? *Class->GetSuperClass()->GetPathName() : TEXT("<none>"),
            static_cast<uint32>(Class->GetClassFlags()),
            *FunctionFilter
        );

        if (!FunctionFilter.IsEmpty())
        {
            UFunction* Exact = Class->FindFunctionByName(FName(*FunctionFilter));
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("Exact FindFunctionByName('%s') = %s%s"),
                *FunctionFilter,
                Exact ? TEXT("FOUND: ") : TEXT("MISSING"),
                Exact ? *Exact->GetPathName() : TEXT("")
            );

            if (Exact)
            {
                DumpSingleFunction(Class, Exact);
            }
        }

        int32 TotalFunctions = 0;
        int32 DeclaredFunctions = 0;
        int32 MatchingFunctions = 0;

        for (TFieldIterator<UFunction> It(Class); It; ++It)
        {
            UFunction* Function = *It;
            if (!Function)
            {
                continue;
            }

            ++TotalFunctions;
            if (Function->GetOuter() == Class)
            {
                ++DeclaredFunctions;
            }

            if (!FunctionFilter.IsEmpty())
            {
                if (!Function->GetName().Contains(FunctionFilter, ESearchCase::IgnoreCase))
                {
                    continue;
                }

                // Exact result was already dumped above.
                if (Function->GetFName() == FName(*FunctionFilter))
                {
                    ++MatchingFunctions;
                    continue;
                }
            }

            ++MatchingFunctions;
            DumpSingleFunction(Class, Function);
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("DumpClass summary | total(include super)=%d | declaredHere=%d | displayedMatches=%d | exact='%s'"),
            TotalFunctions,
            DeclaredFunctions,
            MatchingFunctions,
            FunctionFilter.IsEmpty() ? TEXT("<not requested>") : *FunctionFilter
        );
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("============================================================")
        );
    }

    static FAutoConsoleCommand GDumpClassConsoleCommand(
        TEXT("SquadCookedMount.DumpClass"),
        TEXT("Dump a loaded/cooked UClass and reflected UFunctions. Usage: SquadCookedMount.DumpClass <ClassPath> [Function Name Filter]"),
        FConsoleCommandWithArgsDelegate::CreateStatic(&HandleDumpClassCommand)
    );

    // Generic function-call spawners for cooked UFunctions. These intentionally
    // do NOT carry a UFunction field association in the spawner itself. The stock
    // Blueprint action filter treats external member actions as non-target members
    // before pin/template compatibility is evaluated. A plain UBlueprintNodeSpawner
    // avoids that early member-owner rejection while still producing a completely
    // normal UK2Node_CallFunction whose FunctionReference points at the real cooked
    // UFunction.
    static TMap<UFunction*, UBlueprintNodeSpawner*> GCookedNeutralFunctionSpawners;

    // Cooked roots mounted by this plugin (for example "/ExternalCookedMod/").
    // The automatic Blueprint action watcher only scans classes under these roots,
    // so stock /Game and native /Script classes are never touched.
    static TSet<FString> GCookedBlueprintActionRoots;

    // Signature of the callable reflected functions last registered for a class.
    // This lets the watcher be cheap: unchanged classes are ignored.
    static TMap<TWeakObjectPtr<UClass>, uint32> GCookedBlueprintActionSignatures;

    static void AddCookedBlueprintActionRoot(const FString& InRoot)
    {
        FString Root = InRoot;
        Root.TrimStartAndEndInline();

        if (Root.IsEmpty())
        {
            return;
        }

        if (!Root.StartsWith(TEXT("/")))
        {
            Root = TEXT("/") + Root;
        }
        if (!Root.EndsWith(TEXT("/")))
        {
            Root += TEXT("/");
        }

        GCookedBlueprintActionRoots.Add(Root);

        UE_LOG(
            LogSquadCookedMount,
            Verbose,
            TEXT("Blueprint action auto-refresh root registered: '%s'"),
            *Root);
    }

    static bool IsCookedBlueprintActionClass(const UClass* Class)
    {
        if (!Class ||
            !Cast<UBlueprintGeneratedClass>(Class) ||
            Class->HasAnyClassFlags(CLASS_NewerVersionExists | CLASS_Hidden))
        {
            return false;
        }

        const FString ClassPath = Class->GetPathName();

        for (const FString& Root : GCookedBlueprintActionRoots)
        {
            if (ClassPath.StartsWith(Root, ESearchCase::IgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    static uint32 ComputeCookedBlueprintActionSignature(UClass* Class)
    {
        uint32 Signature = 0x811C9DC5u;
        uint32 CallableCount = 0;

        if (!Class)
        {
            return 0;
        }

        for (TFieldIterator<UFunction> It(Class, EFieldIteratorFlags::ExcludeSuper); It; ++It)
        {
            UFunction* Function = *It;
            if (!Function)
            {
                continue;
            }

            const bool bCallable =
                Function->HasAnyFunctionFlags(FUNC_BlueprintCallable) &&
                FBlueprintActionDatabase::IsFunctionAllowed(
                    Function,
                    FBlueprintActionDatabase::EPermissionsContext::Node) &&
                UEdGraphSchema_K2::CanUserKismetCallFunction(Function);

            if (!bCallable)
            {
                continue;
            }

            ++CallableCount;
            Signature = HashCombineFast(Signature, GetTypeHash(Function->GetFName()));
            Signature = HashCombineFast(
                Signature,
                static_cast<uint32>(Function->FunctionFlags));
        }

        Signature = HashCombineFast(Signature, CallableCount);
        return Signature;
    }

    static TSet<UBlueprintNodeSpawner*> GCookedNeutralFunctionSpawnerSet;

    static FString MakeCookedNeutralActionCategory(const UFunction* Function)
    {
        FString ClassName =
            (Function && Function->GetOwnerClass())
                ? Function->GetOwnerClass()->GetName()
                : TEXT("UnknownClass");
        ClassName.RemoveFromEnd(TEXT("_C"), ESearchCase::CaseSensitive);
        ClassName.ReplaceInline(TEXT("_"), TEXT(" "));
        return FString::Printf(TEXT("Cooked|%s"), *ClassName);
    }

    static int32 RegisterCookedNeutralFunctionActions(UClass* Class)
    {
        if (!Class)
        {
            return 0;
        }

        FBlueprintActionDatabase& ActionDatabase = FBlueprintActionDatabase::Get();

        // GetAllActions() is deliberately const in the public API. There is no
        // public registration API for arbitrary late actions, so this is the one
        // contained editor-only bridge: append our transient spawners to the same
        // registry that the menu consumes. We only touch the UK2Node_CallFunction
        // node-class bucket and remove exactly our own pointers on shutdown.
        FBlueprintActionDatabase::FActionRegistry& Registry =
            const_cast<FBlueprintActionDatabase::FActionRegistry&>(ActionDatabase.GetAllActions());

        const FObjectKey HostKey(UK2Node_CallFunction::StaticClass());
        FBlueprintActionDatabase::FActionList& HostActions = Registry.FindOrAdd(HostKey);

        int32 Added = 0;
        int32 Existing = 0;

        for (TFieldIterator<UFunction> It(Class, EFieldIteratorFlags::ExcludeSuper); It; ++It)
        {
            UFunction* Function = *It;
            if (!Function)
            {
                continue;
            }

            if (!FBlueprintActionDatabase::IsFunctionAllowed(
                    Function,
                    FBlueprintActionDatabase::EPermissionsContext::Node) ||
                !UEdGraphSchema_K2::CanUserKismetCallFunction(Function))
            {
                continue;
            }

            if (UBlueprintNodeSpawner** ExistingSpawner =
                    GCookedNeutralFunctionSpawners.Find(Function))
            {
                if (IsValid(*ExistingSpawner))
                {
                    ++Existing;
                    continue;
                }
                GCookedNeutralFunctionSpawners.Remove(Function);
            }

            UBlueprintNodeSpawner* Spawner =
                UBlueprintNodeSpawner::Create(UK2Node_CallFunction::StaticClass());
            if (!Spawner)
            {
                continue;
            }

            Spawner->DefaultMenuSignature.MenuName =
                FText::FromString(Function->GetName());
            Spawner->DefaultMenuSignature.Category =
                FText::FromString(MakeCookedNeutralActionCategory(Function));
            Spawner->DefaultMenuSignature.Tooltip =
                FText::FromString(Function->GetPathName());
            Spawner->DefaultMenuSignature.Keywords =
                FText::FromString(
                    FString::Printf(
                        TEXT("%s %s cooked"),
                        *Function->GetName(),
                        Function->GetOwnerClass()
                            ? *Function->GetOwnerClass()->GetName()
                            : TEXT("")));

            const TWeakObjectPtr<UFunction> WeakFunction(Function);
            Spawner->CustomizeNodeDelegate =
                UBlueprintNodeSpawner::FCustomizeNodeDelegate::CreateLambda(
                    [WeakFunction](UEdGraphNode* NewNode, bool /*bIsTemplateNode*/)
                    {
                        UFunction* TargetFunction = WeakFunction.Get();
                        UK2Node_CallFunction* CallNode =
                            Cast<UK2Node_CallFunction>(NewNode);

                        if (TargetFunction && CallNode)
                        {
                            // SpawnEdGraphNode executes this customization before
                            // AllocateDefaultPins(), so the stock call node allocates
                            // its real cooked function signature including the Target pin.
                            CallNode->SetFromFunction(TargetFunction);
                        }
                    });

            // The action registry normally participates in GC collection, but root
            // these tiny transient spawners as well because we are mutating the
            // registry outside its normal registrar/priming path.
            Spawner->AddToRoot();

            HostActions.Add(Spawner);
            GCookedNeutralFunctionSpawners.Add(Function, Spawner);
            GCookedNeutralFunctionSpawnerSet.Add(Spawner);
            ++Added;
        }

        if (Added > 0)
        {
            ActionDatabase.OnEntryUpdated().Broadcast(UK2Node_CallFunction::StaticClass());
        }

        UE_LOG(
            LogSquadCookedMount,
            VeryVerbose,
            TEXT("Cooked neutral actions | class='%s' | new=%d | existing=%d | hostBucketTotal=%d"),
            *Class->GetPathName(),
            Added,
            Existing,
            HostActions.Num());

        return Added;
    }

    static void CleanupCookedNeutralFunctionActions()
    {
        if (FBlueprintActionDatabase* ActionDatabase = FBlueprintActionDatabase::TryGet())
        {
            FBlueprintActionDatabase::FActionRegistry& Registry =
                const_cast<FBlueprintActionDatabase::FActionRegistry&>(ActionDatabase->GetAllActions());

            const FObjectKey HostKey(UK2Node_CallFunction::StaticClass());
            if (FBlueprintActionDatabase::FActionList* HostActions = Registry.Find(HostKey))
            {
                HostActions->RemoveAllSwap(
                    [](const TObjectPtr<UBlueprintNodeSpawner>& Action)
                    {
                        return GCookedNeutralFunctionSpawnerSet.Contains(Action.Get());
                    });
            }

            ActionDatabase->OnEntryUpdated().Broadcast(UK2Node_CallFunction::StaticClass());
        }

        for (const TPair<UFunction*, UBlueprintNodeSpawner*>& Pair :
             GCookedNeutralFunctionSpawners)
        {
            if (IsValid(Pair.Value) && Pair.Value->IsRooted())
            {
                Pair.Value->RemoveFromRoot();
            }
        }

        GCookedNeutralFunctionSpawnerSet.Empty();
        GCookedNeutralFunctionSpawners.Empty();
    }

    static TMap<UClass*, UBlueprint*> GCookedBlueprintActionProxies;

    static FString MakeCookedActionProxyName(const UClass* Class)
    {
        const uint32 PathHash = GetTypeHash(Class ? Class->GetPathName() : FString());
        FString BaseName = Class ? Class->GetName() : TEXT("UnknownClass");
        BaseName.ReplaceInline(TEXT("_C"), TEXT(""), ESearchCase::CaseSensitive);
        return FString::Printf(TEXT("BP_SquadCookedActionProxy_%s_%08X"), *BaseName, PathHash);
    }

    static UBlueprint* FindOrCreateCookedActionProxy(UClass* Class)
    {
        if (!Class)
        {
            return nullptr;
        }

        if (UBlueprint** Existing = GCookedBlueprintActionProxies.Find(Class))
        {
            if (IsValid(*Existing))
            {
                (*Existing)->GeneratedClass = Class;
                (*Existing)->SkeletonGeneratedClass = Class;
                return *Existing;
            }
        }

        const FString ProxyObjectName = MakeCookedActionProxyName(Class);
        const FString ProxyPackageName =
            FString::Printf(TEXT("/SquadCookedMount/TransientActions/%s"), *ProxyObjectName);

        UPackage* ProxyPackage = CreatePackage(*ProxyPackageName);
        if (!ProxyPackage)
        {
            UE_LOG(
                LogSquadCookedMount,
                Error,
                TEXT("Cooked action proxy: failed to create package '%s'."),
                *ProxyPackageName
            );
            return nullptr;
        }

        UBlueprint* ProxyBlueprint =
            FindObject<UBlueprint>(ProxyPackage, *ProxyObjectName);

        if (!ProxyBlueprint)
        {
            ProxyBlueprint = NewObject<UBlueprint>(
                ProxyPackage,
                FName(*ProxyObjectName),
                RF_Public | RF_Standalone);
        }

        if (!ProxyBlueprint)
        {
            UE_LOG(
                LogSquadCookedMount,
                Error,
                TEXT("Cooked action proxy: failed to create UBlueprint '%s'."),
                *ProxyObjectName
            );
            return nullptr;
        }

        // RefreshAssetActions() builds Blueprint member spawners from the
        // SkeletonGeneratedClass. A cooked BlueprintGeneratedClass normally
        // has no editor UBlueprint/SkeletonGeneratedClass owner, so give the
        // action database a lightweight editor-only proxy that points both
        // class slots at the real cooked UClass. The cooked UClass itself is
        // never modified.
        ProxyBlueprint->GeneratedClass = Class;
        ProxyBlueprint->SkeletonGeneratedClass = Class;
        ProxyBlueprint->BlueprintType = BPTYPE_Normal;
        ProxyBlueprint->AddToRoot();

        GCookedBlueprintActionProxies.Add(Class, ProxyBlueprint);
        return ProxyBlueprint;
    }

    static bool RegisterCookedClassActionsViaProxy(UClass* Class, const FString& FunctionFilter)
    {
        if (!Class)
        {
            return false;
        }

        FBlueprintActionDatabase& ActionDatabase = FBlueprintActionDatabase::Get();
        ActionDatabase.GetAllActions();

        const bool bGeneratedClass = Cast<UBlueprintGeneratedClass>(Class) != nullptr;
        UBlueprint* RealGeneratingBlueprint = Cast<UBlueprint>(Class->ClassGeneratedBy);

        UE_LOG(
            LogSquadCookedMount,
            VeryVerbose,
            TEXT("Cooked action registration | class='%s' | BPGC=%s | ClassGeneratedBy='%s'"),
            *Class->GetPathName(),
            bGeneratedClass ? TEXT("YES") : TEXT("NO"),
            RealGeneratingBlueprint ? *RealGeneratingBlueprint->GetPathName() : TEXT("<null/non-UBlueprint>")
        );

        int32 DeclaredFunctions = 0;
        int32 BlueprintCallableFunctions = 0;
        int32 KismetCallableFunctions = 0;
        int32 FunctionAllowedCount = 0;

        for (TFieldIterator<UFunction> It(Class, EFieldIteratorFlags::ExcludeSuper); It; ++It)
        {
            UFunction* Function = *It;
            ++DeclaredFunctions;

            if (Function->HasAnyFunctionFlags(FUNC_BlueprintCallable))
            {
                ++BlueprintCallableFunctions;
            }

            const bool bFunctionAllowed =
                FBlueprintActionDatabase::IsFunctionAllowed(
                    Function,
                    FBlueprintActionDatabase::EPermissionsContext::Node);

            const bool bKismetCallable =
                UEdGraphSchema_K2::CanUserKismetCallFunction(Function);

            if (bFunctionAllowed)
            {
                ++FunctionAllowedCount;
            }
            if (bKismetCallable)
            {
                ++KismetCallableFunctions;
            }

            if (!FunctionFilter.IsEmpty() &&
                Function->GetName().Contains(FunctionFilter, ESearchCase::IgnoreCase))
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Display,
                    TEXT("Cooked action function check | '%s' | flags=0x%08X | FunctionAllowed=%s | CanUserKismetCallFunction=%s | BlueprintCallable=%s"),
                    *Function->GetName(),
                    static_cast<uint32>(Function->FunctionFlags),
                    bFunctionAllowed ? TEXT("YES") : TEXT("NO"),
                    bKismetCallable ? TEXT("YES") : TEXT("NO"),
                    Function->HasAnyFunctionFlags(FUNC_BlueprintCallable) ? TEXT("YES") : TEXT("NO")
                );
            }
        }

        UBlueprint* ProxyBlueprint = FindOrCreateCookedActionProxy(Class);
        if (!ProxyBlueprint)
        {
            return false;
        }

        UE_LOG(
            LogSquadCookedMount,
            VeryVerbose,
            TEXT("Cooked action proxy | blueprint='%s' | IsAsset=%s | GeneratedClass='%s' | SkeletonGeneratedClass='%s'"),
            *ProxyBlueprint->GetPathName(),
            ProxyBlueprint->IsAsset() ? TEXT("YES") : TEXT("NO"),
            ProxyBlueprint->GeneratedClass ? *ProxyBlueprint->GeneratedClass->GetPathName() : TEXT("<null>"),
            ProxyBlueprint->SkeletonGeneratedClass ? *ProxyBlueprint->SkeletonGeneratedClass->GetPathName() : TEXT("<null>")
        );

        ActionDatabase.RefreshAssetActions(ProxyBlueprint);

        // The proxy path proves the stock function spawners can be built, but
        // those spawners still retain their external member association and can
        // be rejected by IsNonTargetMember before pin matching. Add a second,
        // neutral generic action for each callable cooked function.
        const int32 NeutralActionsAdded =
            RegisterCookedNeutralFunctionActions(Class);

        const FBlueprintActionDatabase::FActionRegistry& Registry =
            ActionDatabase.GetAllActions();
        const FBlueprintActionDatabase::FActionList* ProxyActions =
            Registry.Find(FObjectKey(ProxyBlueprint));
        const int32 RegisteredActions = ProxyActions ? ProxyActions->Num() : 0;

        UE_LOG(
            LogSquadCookedMount,
            VeryVerbose,
            TEXT("Cooked action proxy RESULT | class='%s' | declared=%d | BlueprintCallable=%d | FunctionAllowed=%d | CanUserKismetCallFunction=%d | registeredActions=%d | neutralNew=%d | neutralKnown=%d"),
            *Class->GetPathName(),
            DeclaredFunctions,
            BlueprintCallableFunctions,
            FunctionAllowedCount,
            KismetCallableFunctions,
            RegisteredActions,
            NeutralActionsAdded,
            GCookedNeutralFunctionSpawners.Num()
        );

        return RegisteredActions > 0 || NeutralActionsAdded > 0 ||
               GCookedNeutralFunctionSpawners.Num() > 0;
    }


    static int32 RefreshChangedCookedBlueprintActions(bool bForce = false)
    {
        if (GCookedBlueprintActionRoots.IsEmpty())
        {
            return 0;
        }

        // Make sure the stock database exists before we mutate its registry.
        FBlueprintActionDatabase::Get().GetAllActions();

        int32 ScannedClasses = 0;
        int32 UpdatedClasses = 0;

        for (TObjectIterator<UClass> It; It; ++It)
        {
            UClass* Class = *It;
            if (!IsCookedBlueprintActionClass(Class))
            {
                continue;
            }

            ++ScannedClasses;

            const uint32 Signature = ComputeCookedBlueprintActionSignature(Class);
            const TWeakObjectPtr<UClass> WeakClass(Class);
            const uint32* PreviousSignature =
                GCookedBlueprintActionSignatures.Find(WeakClass);

            if (!bForce &&
                PreviousSignature != nullptr &&
                *PreviousSignature == Signature)
            {
                continue;
            }

            if (RegisterCookedClassActionsViaProxy(Class, FString()))
            {
                GCookedBlueprintActionSignatures.Add(WeakClass, Signature);
                ++UpdatedClasses;
            }
        }

        // Prune dead weak keys. Proxies normally keep registered cooked classes
        // alive, but this also handles classes that disappeared before registration.
        for (auto It = GCookedBlueprintActionSignatures.CreateIterator(); It; ++It)
        {
            if (!It.Key().IsValid())
            {
                It.RemoveCurrent();
            }
        }

        if (UpdatedClasses > 0)
        {
            UE_LOG(
                LogSquadCookedMount,
                Verbose,
                TEXT("Blueprint action auto-refresh | updated=%d | scannedCookedClasses=%d | roots=%d"),
                UpdatedClasses,
                ScannedClasses,
                GCookedBlueprintActionRoots.Num());
        }

        return UpdatedClasses;
    }

    static void CleanupCookedActionProxies()
    {
        CleanupCookedNeutralFunctionActions();

        if (FBlueprintActionDatabase* ActionDatabase = FBlueprintActionDatabase::TryGet())
        {
            for (const TPair<UClass*, UBlueprint*>& Pair : GCookedBlueprintActionProxies)
            {
                if (IsValid(Pair.Value))
                {
                    ActionDatabase->ClearAssetActions(Pair.Value);
                }
            }
        }

        for (const TPair<UClass*, UBlueprint*>& Pair : GCookedBlueprintActionProxies)
        {
            if (IsValid(Pair.Value) && Pair.Value->IsRooted())
            {
                Pair.Value->RemoveFromRoot();
            }
        }
        GCookedBlueprintActionProxies.Empty();
        GCookedBlueprintActionSignatures.Empty();
        GCookedBlueprintActionRoots.Empty();
    }

    static void HandleRefreshBlueprintActionsCommand(const TArray<FString>& Args)
    {
        if (Args.IsEmpty())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("Usage: SquadCookedMount.RefreshBlueprintActions <ClassPath> [Function Name Filter]")
            );
            return;
        }

        FString ResolvedPath;
        UClass* Class = ResolveDumpClass(Args[0], ResolvedPath);

        if (!Class)
        {
            UE_LOG(
                LogSquadCookedMount,
                Error,
                TEXT("RefreshBlueprintActions: failed to resolve/load UClass | input='%s' | normalized='%s'"),
                *Args[0],
                *ResolvedPath
            );
            return;
        }

        FString FunctionFilter;
        for (int32 Index = 1; Index < Args.Num(); ++Index)
        {
            if (!FunctionFilter.IsEmpty())
            {
                FunctionFilter += TEXT(" ");
            }
            FunctionFilter += Args[Index];
        }
        FunctionFilter.TrimStartAndEndInline();
        FunctionFilter.TrimQuotesInline();

        const bool bRegistered =
            RegisterCookedClassActionsViaProxy(Class, FunctionFilter);

        if (bRegistered)
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("RefreshBlueprintActions: proxy + neutral registration SUCCEEDED for '%s'. Re-open the Blueprint palette/context menu."),
                *Class->GetPathName()
            );
        }
        else
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("RefreshBlueprintActions: proxy registration FAILED for '%s'."),
                *Class->GetPathName()
            );
        }
    }

    static void HandleRefreshBlueprintActionsLoadedCommand(const TArray<FString>& Args)
    {
        FString RootFilter;
        if (!Args.IsEmpty())
        {
            RootFilter = Args[0];
            RootFilter.TrimStartAndEndInline();
            RootFilter.TrimQuotesInline();
        }

        FBlueprintActionDatabase& ActionDatabase =
            FBlueprintActionDatabase::Get();

        // Force normal DB initialization first, then refresh only classes that
        // already exist in memory. This intentionally does NOT load every
        // BlueprintGeneratedClass from cooked mods.
        ActionDatabase.GetAllActions();

        int32 ScannedClasses = 0;
        int32 RefreshedClasses = 0;

        for (TObjectIterator<UClass> It; It; ++It)
        {
            UClass* Class = *It;
            if (!Class ||
                Class->HasAnyClassFlags(CLASS_NewerVersionExists))
            {
                continue;
            }

            ++ScannedClasses;

            const FString ClassPath = Class->GetPathName();

            if (!RootFilter.IsEmpty() &&
                !ClassPath.StartsWith(RootFilter, ESearchCase::IgnoreCase))
            {
                continue;
            }

            // We care about late-loaded generated classes. Native /Script/
            // classes are already present during the normal database build.
            if (ClassPath.StartsWith(TEXT("/Script/"), ESearchCase::IgnoreCase))
            {
                continue;
            }

            if (RegisterCookedClassActionsViaProxy(Class, FString()))
            {
                ++RefreshedClasses;
            }
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("RefreshBlueprintActionsLoaded: refreshed=%d | scanned=%d | root='%s'"),
            RefreshedClasses,
            ScannedClasses,
            RootFilter.IsEmpty() ? TEXT("<all non-/Script/ loaded classes>") : *RootFilter
        );
    }

    static FAutoConsoleCommand GRefreshBlueprintActionsConsoleCommand(
        TEXT("SquadCookedMount.RefreshBlueprintActions"),
        TEXT("Rebuild Blueprint Action Database entries for one late-loaded cooked UClass."),
        FConsoleCommandWithArgsDelegate::CreateStatic(&HandleRefreshBlueprintActionsCommand)
    );

    static FAutoConsoleCommand GRefreshBlueprintActionsLoadedConsoleCommand(
        TEXT("SquadCookedMount.RefreshBlueprintActionsLoaded"),
        TEXT("Refresh Blueprint Action Database entries for already-loaded non-native classes. Optional arg: root prefix such as /ExternalCookedMod/."),
        FConsoleCommandWithArgsDelegate::CreateStatic(&HandleRefreshBlueprintActionsLoadedCommand)
    );

    // ---------------------------------------------------------------------
    // v0.3.17r diagnostic helpers
    // ---------------------------------------------------------------------

    static bool IsVerboseSCMDiagnosticsEnabled()
    {
        static const bool bEnabled =
            FParse::Param(FCommandLine::Get(), TEXT("SCMDiagnostics"));
        return bEnabled;
    }

    static bool IsTargetedProblemPackage(const FString& PackageName)
    {
        static const TArray<FString> Targets = []
        {
            TArray<FString> Result;
            FString Value;
            if (FParse::Value(FCommandLine::Get(), TEXT("SCMDiagPackage="), Value))
            {
                Value.ParseIntoArray(Result, TEXT(","), true);
                for (FString& Item : Result)
                {
                    Item.TrimStartAndEndInline();
                }
                Result.RemoveAll([](const FString& Item) { return Item.IsEmpty(); });
            }
            return Result;
        }();

        for (const FString& Target : Targets)
        {
            if (PackageName.Equals(Target, ESearchCase::IgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    struct FDiagnosticZenHeaderView
    {
        FNameMap NameMap;
        FName PackageName;
        TArrayView<const uint64> ImportedPublicExportHashes;
        TArrayView<const FPackageObjectIndex> ImportMap;
        TArrayView<const FExportMapEntry> ExportMap;
        TArrayView<const FDependencyBundleHeader> DependencyBundleHeaders;
        TArrayView<const FDependencyBundleEntry> DependencyBundleEntries;
        int32 CellExportCount = 0;
        bool bHasDependencyBundles = false;
        TArray<FName> ImportedPackageNames;
    };

    static bool ParseDiagnosticZenHeader(
        const TArray<uint8>& Bytes,
        FDiagnosticZenHeaderView& OutHeader,
        FString& OutError)
    {
        OutError.Reset();
        OutHeader = FDiagnosticZenHeaderView();

        if (Bytes.Num() < static_cast<int32>(sizeof(FZenPackageSummary)))
        {
            OutError = TEXT("package data is smaller than FZenPackageSummary");
            return false;
        }

        const uint8* Data = Bytes.GetData();
        const FZenPackageSummary* Summary =
            reinterpret_cast<const FZenPackageSummary*>(Data);

        if (Summary->HeaderSize < sizeof(FZenPackageSummary) ||
            Summary->HeaderSize > static_cast<uint32>(Bytes.Num()))
        {
            OutError = FString::Printf(
                TEXT("invalid HeaderSize=%u packageBytes=%d"),
                Summary->HeaderSize,
                Bytes.Num());
            return false;
        }

        TArrayView<const uint8> HeaderData(
            Data + sizeof(FZenPackageSummary),
            Summary->HeaderSize - sizeof(FZenPackageSummary));
        FMemoryReaderView Reader(HeaderData);

        FZenPackageVersioningInfo VersioningInfo{};
        const FZenPackageVersioningInfo* LocalVersioning = nullptr;
        if (Summary->bHasVersioningInfo)
        {
            Reader << VersioningInfo;
            LocalVersioning = &VersioningInfo;
        }

        OutHeader.bHasDependencyBundles =
            LocalVersioning == nullptr ||
            LocalVersioning->ZenVersion >= EZenPackageVersion::ExportDependencies;

        FZenPackageCellOffsets CellOffsets;
        if (LocalVersioning == nullptr ||
            LocalVersioning->PackageVersion >= EUnrealEngineObjectUE5Version::VERSE_CELLS)
        {
            Reader << CellOffsets.CellImportMapOffset;
            Reader << CellOffsets.CellExportMapOffset;
        }
        else
        {
            CellOffsets.CellImportMapOffset = Summary->ExportBundleEntriesOffset;
            CellOffsets.CellExportMapOffset = Summary->ExportBundleEntriesOffset;
        }

        OutHeader.NameMap.Load(Reader, FMappedName::EType::Package);
        if (Reader.IsError() || Reader.IsCriticalError())
        {
            OutError = TEXT("failed while reading Zen package name map");
            return false;
        }
        OutHeader.PackageName = OutHeader.NameMap.GetName(Summary->Name);

        auto OffsetInHeader = [Summary](int32 Offset)
        {
            return Offset >= 0 && static_cast<uint32>(Offset) <= Summary->HeaderSize;
        };

        if (!OffsetInHeader(Summary->ImportedPublicExportHashesOffset) ||
            !OffsetInHeader(Summary->ImportMapOffset) ||
            !OffsetInHeader(Summary->ExportMapOffset) ||
            !OffsetInHeader(CellOffsets.CellImportMapOffset) ||
            !OffsetInHeader(Summary->ImportedPackageNamesOffset) ||
            Summary->ImportedPublicExportHashesOffset > Summary->ImportMapOffset ||
            Summary->ImportMapOffset > Summary->ExportMapOffset ||
            Summary->ExportMapOffset > CellOffsets.CellImportMapOffset)
        {
            OutError = TEXT("invalid or non-monotonic Zen header offsets");
            return false;
        }

        // Dependency bundles are optional for the UFunction ScriptImport bridge.
        // If their layout cannot be proven, leave ImportMap dependencies intact
        // and fail closed for ImportMap conversion; direct SuperIndex conversion
        // can still proceed because it does not need local dependency pruning.
        if (OutHeader.bHasDependencyBundles &&
            (!OffsetInHeader(CellOffsets.CellExportMapOffset) ||
             !OffsetInHeader(Summary->ExportBundleEntriesOffset) ||
             !OffsetInHeader(Summary->DependencyBundleHeadersOffset) ||
             !OffsetInHeader(Summary->DependencyBundleEntriesOffset) ||
             CellOffsets.CellImportMapOffset > CellOffsets.CellExportMapOffset ||
             CellOffsets.CellExportMapOffset > Summary->ExportBundleEntriesOffset ||
             Summary->ExportBundleEntriesOffset > Summary->DependencyBundleHeadersOffset ||
             Summary->DependencyBundleHeadersOffset > Summary->DependencyBundleEntriesOffset ||
             Summary->DependencyBundleEntriesOffset > Summary->ImportedPackageNamesOffset))
        {
            OutHeader.bHasDependencyBundles = false;
        }

        const int32 HashBytes =
            Summary->ImportMapOffset - Summary->ImportedPublicExportHashesOffset;
        const int32 ImportBytes =
            Summary->ExportMapOffset - Summary->ImportMapOffset;
        const int32 ExportBytes =
            CellOffsets.CellImportMapOffset - Summary->ExportMapOffset;
        int32 CellExportBytes =
            OutHeader.bHasDependencyBundles
                ? Summary->ExportBundleEntriesOffset -
                    CellOffsets.CellExportMapOffset
                : 0;
        int32 DependencyHeaderBytes =
            OutHeader.bHasDependencyBundles
                ? Summary->DependencyBundleEntriesOffset -
                    Summary->DependencyBundleHeadersOffset
                : 0;
        int32 DependencyEntryBytes =
            OutHeader.bHasDependencyBundles
                ? Summary->ImportedPackageNamesOffset -
                    Summary->DependencyBundleEntriesOffset
                : 0;

        if ((HashBytes % sizeof(uint64)) != 0 ||
            (ImportBytes % sizeof(FPackageObjectIndex)) != 0 ||
            (ExportBytes % sizeof(FExportMapEntry)) != 0)
        {
            OutError = TEXT("Zen header core array offsets are not element-aligned");
            return false;
        }
        if (OutHeader.bHasDependencyBundles &&
            ((CellExportBytes % sizeof(FCellExportMapEntry)) != 0 ||
             (DependencyHeaderBytes % sizeof(FDependencyBundleHeader)) != 0 ||
             (DependencyEntryBytes % sizeof(FDependencyBundleEntry)) != 0))
        {
            OutHeader.bHasDependencyBundles = false;
            CellExportBytes = 0;
            DependencyHeaderBytes = 0;
            DependencyEntryBytes = 0;
        }
        if (OutHeader.bHasDependencyBundles)
        {
            OutHeader.CellExportCount =
                CellExportBytes / sizeof(FCellExportMapEntry);
        }

        OutHeader.ImportedPublicExportHashes = TArrayView<const uint64>(
            reinterpret_cast<const uint64*>(
                Data + Summary->ImportedPublicExportHashesOffset),
            HashBytes / sizeof(uint64));
        OutHeader.ImportMap = TArrayView<const FPackageObjectIndex>(
            reinterpret_cast<const FPackageObjectIndex*>(
                Data + Summary->ImportMapOffset),
            ImportBytes / sizeof(FPackageObjectIndex));
        OutHeader.ExportMap = TArrayView<const FExportMapEntry>(
            reinterpret_cast<const FExportMapEntry*>(
                Data + Summary->ExportMapOffset),
            ExportBytes / sizeof(FExportMapEntry));
        if (OutHeader.bHasDependencyBundles)
        {
            OutHeader.DependencyBundleHeaders =
                TArrayView<const FDependencyBundleHeader>(
                    reinterpret_cast<const FDependencyBundleHeader*>(
                        Data + Summary->DependencyBundleHeadersOffset),
                    DependencyHeaderBytes / sizeof(FDependencyBundleHeader));
            OutHeader.DependencyBundleEntries =
                TArrayView<const FDependencyBundleEntry>(
                    reinterpret_cast<const FDependencyBundleEntry*>(
                        Data + Summary->DependencyBundleEntriesOffset),
                    DependencyEntryBytes / sizeof(FDependencyBundleEntry));
        }

#if WITH_EDITOR
        if (Summary->ImportedPackageNamesOffset < static_cast<int32>(Summary->HeaderSize))
        {
            TArrayView<const uint8> ImportedNamesData(
                Data + Summary->ImportedPackageNamesOffset,
                Summary->HeaderSize - Summary->ImportedPackageNamesOffset);
            FMemoryReaderView ImportedNamesReader(ImportedNamesData);
            FZenPackageImportedPackageNamesContainer Container;
            ImportedNamesReader << Container;
            if (!ImportedNamesReader.IsError() &&
                !ImportedNamesReader.IsCriticalError())
            {
                OutHeader.ImportedPackageNames = MoveTemp(Container.Names);
            }
        }
#endif

        return true;
    }

    static bool ComputeDiagnosticZenExportRelativePath(
        const FDiagnosticZenHeaderView& Header,
        int32 ExportIndex,
        FString& OutRelativePath)
    {
        OutRelativePath.Reset();
        if (ExportIndex < 0 || ExportIndex >= Header.ExportMap.Num())
        {
            return false;
        }

        TArray<int32, TInlineAllocator<64>> FullPath;
        int32 PathIndex = ExportIndex;
        FullPath.Add(PathIndex);
        while (Header.ExportMap[PathIndex].OuterIndex.IsExport())
        {
            PathIndex = static_cast<int32>(
                Header.ExportMap[PathIndex].OuterIndex.ToExport());
            if (PathIndex < 0 || PathIndex >= Header.ExportMap.Num())
            {
                return false;
            }
            FullPath.Add(PathIndex);
        }

        FString RelativePath;
        while (!FullPath.IsEmpty())
        {
            const int32 ComponentIndex = FullPath.Pop(EAllowShrinking::No);
            FString ComponentName = Header.NameMap
                .GetName(Header.ExportMap[ComponentIndex].ObjectName)
                .ToString();
            ComponentName.ToLowerInline();
            RelativePath += TEXT("/");
            RelativePath += ComponentName;
        }

        if (RelativePath.Len() <= 1)
        {
            return false;
        }
        OutRelativePath = MoveTemp(RelativePath);
        return true;
    }

    static bool ReadDiagnosticPackageData(
        const TArray<FString>& PakPaths,
        FPackageId PackageId,
        TArray<uint8>& OutBytes,
        FString& OutSourceUtoc,
        FString& OutError)
    {
        OutBytes.Reset();
        OutSourceUtoc.Reset();
        OutError.Reset();

        TSet<FString> VisitedUtocs;
        const FIoChunkId ChunkId = CreatePackageDataChunkId(PackageId);

        for (const FString& PakPath : PakPaths)
        {
            const FString UtocPath = NormalizeFilename(
                FPaths::ChangeExtension(PakPath, TEXT("utoc")));
            FString Key = UtocPath;
            Key.ToLowerInline();
            if (VisitedUtocs.Contains(Key) ||
                !IFileManager::Get().FileExists(*UtocPath))
            {
                continue;
            }
            VisitedUtocs.Add(Key);

            FIoStoreReader Reader;
            TMap<FGuid, FAES::FAESKey> DecryptionKeys;
            const FIoStatus InitStatus = Reader.Initialize(
                RemoveUtocExtension(UtocPath),
                DecryptionKeys);
            if (!InitStatus.IsOk())
            {
                continue;
            }

            if (!Reader.GetChunkInfo(ChunkId).IsOk())
            {
                continue;
            }

            TIoStatusOr<FIoBuffer> ReadResult =
                Reader.Read(ChunkId, FIoReadOptions());
            if (!ReadResult.IsOk())
            {
                OutError = ReadResult.Status().ToString();
                continue;
            }

            FIoBuffer Buffer = ReadResult.ConsumeValueOrDie();
            if (Buffer.DataSize() == 0 ||
                Buffer.DataSize() > static_cast<uint64>(MAX_int32))
            {
                OutError = TEXT("package data chunk has invalid size");
                return false;
            }

            OutBytes.SetNumUninitialized(static_cast<int32>(Buffer.DataSize()));
            FMemory::Memcpy(OutBytes.GetData(), Buffer.Data(), Buffer.DataSize());
            OutSourceUtoc = UtocPath;
            return true;
        }

        if (OutError.IsEmpty())
        {
            OutError = TEXT("package-data chunk not found in mounted cooked mod UTOCs");
        }
        return false;
    }

    static uint64 ComputeLinkerLoadExportHash(
        FLinkerLoad* Linker,
        int32 ExportIndex,
        FString& OutRelativePath)
    {
        OutRelativePath.Reset();
        if (!Linker || !Linker->ExportMap.IsValidIndex(ExportIndex))
        {
            return 0;
        }

        TArray<int32, TInlineAllocator<128>> FullPath;
        int32 PathIndex = ExportIndex;
        FullPath.Push(PathIndex);
        while (Linker->ExportMap[PathIndex].OuterIndex.IsExport())
        {
            PathIndex = Linker->ExportMap[PathIndex].OuterIndex.ToExport();
            if (!Linker->ExportMap.IsValidIndex(PathIndex))
            {
                return 0;
            }
            FullPath.Push(PathIndex);
        }

        TStringBuilder<256> RelativePath;
        while (!FullPath.IsEmpty())
        {
            TCHAR NameBuffer[FName::StringBufferSize];
            const uint32 NameLen =
                Linker->ExportMap[FullPath.Pop(EAllowShrinking::No)]
                    .ObjectName.ToString(NameBuffer);
            for (uint32 Index = 0; Index < NameLen; ++Index)
            {
                NameBuffer[Index] = TChar<TCHAR>::ToLower(NameBuffer[Index]);
            }
            RelativePath.AppendChar(TEXT('/'));
            RelativePath.Append(FStringView(NameBuffer, NameLen));
        }

        if (RelativePath.Len() <= 1)
        {
            return 0;
        }

        OutRelativePath = RelativePath.ToString();
        return CityHash64(
            reinterpret_cast<const char*>(RelativePath.GetData() + 1),
            (RelativePath.Len() - 1) * sizeof(TCHAR));
    }

    // Hash a live UObject using the exact UE5.7 package-relative public-export
    // path algorithm. Unlike ComputeLinkerLoadExportHash this does not require
    // the object to still have an FObjectExport entry. v6 also uses this to
    // distinguish an editor-regenerated live object from a genuinely absent
    // cooked/SDK symbol. The package name itself is intentionally excluded.
    static uint64 ComputeLiveObjectExportHash(
        UObject* Object,
        UPackage* ExpectedPackage,
        FString& OutRelativePath)
    {
        OutRelativePath.Reset();
        if (!Object || !ExpectedPackage || Object == ExpectedPackage ||
            Object->GetOutermost() != ExpectedPackage)
        {
            return 0;
        }

        TArray<FName, TInlineAllocator<64>> PathComponents;
        UObject* Cursor = Object;
        while (Cursor && Cursor != ExpectedPackage)
        {
            PathComponents.Add(Cursor->GetFName());
            Cursor = Cursor->GetOuter();
        }
        if (Cursor != ExpectedPackage || PathComponents.IsEmpty())
        {
            return 0;
        }

        TStringBuilder<256> RelativePath;
        for (int32 PathIndex = PathComponents.Num() - 1; PathIndex >= 0; --PathIndex)
        {
            TCHAR NameBuffer[FName::StringBufferSize];
            const uint32 NameLen = PathComponents[PathIndex].ToString(NameBuffer);
            for (uint32 Index = 0; Index < NameLen; ++Index)
            {
                NameBuffer[Index] = TChar<TCHAR>::ToLower(NameBuffer[Index]);
            }
            RelativePath.AppendChar(TEXT('/'));
            RelativePath.Append(FStringView(NameBuffer, NameLen));
        }

        if (RelativePath.Len() <= 1)
        {
            return 0;
        }

        OutRelativePath = RelativePath.ToString();
        return CityHash64(
            reinterpret_cast<const char*>(RelativePath.GetData() + 1),
            (RelativePath.Len() - 1) * sizeof(TCHAR));
    }

    static UFunction* FindUniqueLiveUFunctionByExportHash(
        UPackage* Package,
        FLinkerLoad* Linker,
        uint64 PublicExportHash,
        int32& OutMatches,
        FString& OutRelativePath,
        bool& OutLinkerExportLoadFailed,
        bool& OutFoundViaLiveObjectFallback)
    {
        OutMatches = 0;
        OutRelativePath.Reset();
        OutLinkerExportLoadFailed = false;
        OutFoundViaLiveObjectFallback = false;
        if (!Package || PublicExportHash == 0)
        {
            return nullptr;
        }

        TSet<UFunction*> Candidates;
        TMap<UFunction*, FString> CandidatePaths;
        TMap<UFunction*, bool> CandidateLoadFailed;
        TSet<UFunction*> LinkerCandidates;

        if (Linker)
        {
            for (int32 ExportIndex = 0; ExportIndex < Linker->ExportMap.Num(); ++ExportIndex)
            {
                FString RelativePath;
                const uint64 CandidateHash = ComputeLinkerLoadExportHash(
                    Linker,
                    ExportIndex,
                    RelativePath);
                if (CandidateHash != PublicExportHash)
                {
                    continue;
                }

                const FObjectExport& Export = Linker->ExportMap[ExportIndex];
                UFunction* Function = Cast<UFunction>(Export.Object);
                if (!Function || Function->IsUnreachable() ||
                    Function->GetOutermost() != Package)
                {
                    continue;
                }

                Candidates.Add(Function);
                LinkerCandidates.Add(Function);
                CandidatePaths.FindOrAdd(Function) = RelativePath;
                CandidateLoadFailed.FindOrAdd(Function) = Export.bExportLoadFailed;
            }
        }

        // Blueprint regeneration can leave the authoritative UFunction alive
        // with linkerIndex=-1. Hash all live package objects using the same
        // package-relative CityHash algorithm and union them with linker hits.
        ForEachObjectWithOuter(
            Package,
            [Package, PublicExportHash, &Candidates, &CandidatePaths](UObject* Object)
            {
                UFunction* Function = Cast<UFunction>(Object);
                if (!Function || Function->IsUnreachable() ||
                    Function->GetOutermost() != Package)
                {
                    return;
                }

                FString RelativePath;
                const uint64 CandidateHash = ComputeLiveObjectExportHash(
                    Function,
                    Package,
                    RelativePath);
                if (CandidateHash != PublicExportHash)
                {
                    return;
                }

                Candidates.Add(Function);
                if (!CandidatePaths.Contains(Function))
                {
                    CandidatePaths.Add(Function, RelativePath);
                }
            },
            /* bIncludeNestedObjects */ true);

        OutMatches = Candidates.Num();
        if (OutMatches != 1)
        {
            return nullptr;
        }

        UFunction* Result = *Candidates.CreateConstIterator();
        if (const FString* Path = CandidatePaths.Find(Result))
        {
            OutRelativePath = *Path;
        }
        if (const bool* bLoadFailed = CandidateLoadFailed.Find(Result))
        {
            OutLinkerExportLoadFailed = *bLoadFailed;
        }
        OutFoundViaLiveObjectFallback = !LinkerCandidates.Contains(Result);
        return Result;
    }

    // External-package bookkeeping for the JIT cross-loader bridge.
    static TSet<FPackageId> GSCMExternalPackageIds;

    struct FSCMLiveUFunctionScriptBindingDescriptor
    {
        FPackageId ParentPackageId;
        FName ParentPackageName = NAME_None;
        uint64 PublicExportHash = 0;
    };

    // AddScriptObject is designed for script objects with process lifetime.
    // Blueprint-generated UFunctions are not process-lifetime objects, so keep
    // every bridged real function strongly referenced and refresh the binding
    // after Blueprint compilation/reinstancing.
    static TMap<FPackageObjectIndex, TStrongObjectPtr<UObject>>
        GSCMLiveUFunctionScriptPins;
    static TMap<FPackageObjectIndex, FSCMLiveUFunctionScriptBindingDescriptor>
        GSCMLiveUFunctionScriptBindingDescriptors;
    static TSet<FPackageId> GSCMPreparingGenericSuperOverlayPackages;

    // v6.8.10: repair the exact second-order stock Blueprint failure proven
    // by two UEMinidumps. A failed stock UFunction can have a valid
    // SuperStruct while its executable Script still contains:
    //   EX_LocalFinalFunction <nullptr> EX_EndFunctionParms
    //
    // Do not trust FObjectExport::Object identity as the sole proof. Blueprint
    // regeneration can replace the live object while the LinkerLoad still owns
    // the failed cooked export. Bind a live UFunction to that failed export by
    // BOTH the normalized package-relative path and the public-export CityHash.
    // This is the same identity domain used by the generic super overlay.
    static UFunction* FindUniqueLiveUFunctionByExactPathHash(
        UPackage* Package,
        uint64 PublicExportHash,
        const FString& RelativePath,
        int32& OutMatches)
    {
        OutMatches = 0;
        if (!Package || PublicExportHash == 0 || RelativePath.IsEmpty())
        {
            return nullptr;
        }

        UFunction* Result = nullptr;
        ForEachObjectWithOuter(
            Package,
            [Package,
             PublicExportHash,
             &RelativePath,
             &OutMatches,
             &Result](UObject* Object)
            {
                UFunction* Function = Cast<UFunction>(Object);
                if (!Function || Function->IsUnreachable() ||
                    Function->GetOutermost() != Package)
                {
                    return;
                }

                FString CandidateRelativePath;
                const uint64 CandidateHash =
                    ComputeLiveObjectExportHash(
                        Function,
                        Package,
                        CandidateRelativePath);
                if (CandidateHash != PublicExportHash ||
                    !CandidateRelativePath.Equals(
                        RelativePath,
                        ESearchCase::IgnoreCase))
                {
                    return;
                }

                ++OutMatches;
                if (!Result)
                {
                    Result = Function;
                }
            },
            /* bIncludeNestedObjects */ true);

        return OutMatches == 1 ? Result : nullptr;
    }

    static bool FindUniqueFailedLinkerExportForFunction(
        UFunction* Function,
        int32& OutExportIndex,
        uint64& OutPublicExportHash,
        FString& OutRelativePath,
        FString& OutFailureReason)
    {
        OutExportIndex = INDEX_NONE;
        OutPublicExportHash = 0;
        OutRelativePath.Reset();
        OutFailureReason.Reset();

        if (!Function || Function->IsUnreachable())
        {
            OutFailureReason = TEXT("invalid_function");
            return false;
        }

        UPackage* FunctionPackage = Function->GetOutermost();
        if (!FunctionPackage)
        {
            OutFailureReason = TEXT("missing_function_package");
            return false;
        }

        const FPackageId FunctionPackageId =
            FPackageId::FromName(FunctionPackage->GetFName());
        if (GSCMExternalPackageIds.Contains(FunctionPackageId))
        {
            OutFailureReason = TEXT("external_package_not_stock");
            return false;
        }

        FLinkerLoad* Linker = FunctionPackage->GetLinker();
        if (!Linker)
        {
            OutFailureReason = TEXT("missing_linker");
            return false;
        }

        FString LiveRelativePath;
        const uint64 LivePublicExportHash =
            ComputeLiveObjectExportHash(
                Function,
                FunctionPackage,
                LiveRelativePath);
        if (LivePublicExportHash == 0 || LiveRelativePath.IsEmpty())
        {
            OutFailureReason = TEXT("invalid_live_path_hash");
            return false;
        }

        int32 LiveIdentityMatches = 0;
        UFunction* UniqueLiveIdentity =
            FindUniqueLiveUFunctionByExactPathHash(
                FunctionPackage,
                LivePublicExportHash,
                LiveRelativePath,
                LiveIdentityMatches);
        if (LiveIdentityMatches != 1 || UniqueLiveIdentity != Function)
        {
            OutFailureReason = TEXT("ambiguous_live_path_hash_identity");
            return false;
        }

        int32 ExactFailedMatches = 0;
        int32 ExactFailedExportIndex = INDEX_NONE;
        for (int32 ExportIndex = 0;
             ExportIndex < Linker->ExportMap.Num();
             ++ExportIndex)
        {
            const FObjectExport& Export = Linker->ExportMap[ExportIndex];
            if (!Export.bExportLoadFailed)
            {
                continue;
            }

            FString ExportRelativePath;
            const uint64 ExportPublicHash =
                ComputeLinkerLoadExportHash(
                    Linker,
                    ExportIndex,
                    ExportRelativePath);
            if (ExportPublicHash != LivePublicExportHash ||
                !ExportRelativePath.Equals(
                    LiveRelativePath,
                    ESearchCase::IgnoreCase))
            {
                continue;
            }

            ++ExactFailedMatches;
            ExactFailedExportIndex = ExportIndex;
        }

        if (ExactFailedMatches == 0)
        {
            OutFailureReason = TEXT("no_exact_failed_export_path_hash");
            return false;
        }
        if (ExactFailedMatches != 1)
        {
            OutFailureReason = TEXT("ambiguous_failed_export_path_hash");
            return false;
        }
        OutExportIndex = ExactFailedExportIndex;
        OutPublicExportHash = LivePublicExportHash;
        OutRelativePath = MoveTemp(LiveRelativePath);
        return true;
    }

    static void LogStockUFunctionNullSuperSkipped(
        UFunction* Function,
        const FString& TriggerPackageName,
        int32 ChainDepth,
        const FString& Reason,
        int32 FailedExportIndex,
        uint64 PublicExportHash,
        const FString& RelativePath)
    {
        if (!IsVerboseSCMDiagnosticsEnabled())
        {
            return;
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_FIX STOCK_UFUNCTION_NULL_SUPER_REPAIR_SKIPPED | triggerPackage='%s' | depth=%d | function='%s' | functionPackage='%s' | linkerExport=%d | publicHash=0x%016llX | relative='%s' | reason='%s' | mutation=NO"),
            *TriggerPackageName,
            ChainDepth,
            Function ? *Function->GetPathName() : TEXT("<null>"),
            (Function && Function->GetOutermost())
                ? *Function->GetOutermost()->GetName()
                : TEXT("<null>"),
            FailedExportIndex,
            static_cast<unsigned long long>(PublicExportHash),
            RelativePath.IsEmpty() ? TEXT("<none>") : *RelativePath,
            Reason.IsEmpty() ? TEXT("unspecified") : *Reason);
    }

    static bool TryRepairStockUFunctionNullSuperCall(
        UFunction* Function,
        const FString& TriggerPackageName,
        int32 ChainDepth,
        UFunction*& OutSuperFunction,
        FString& OutStopReason)
    {
        OutSuperFunction = nullptr;
        OutStopReason.Reset();

        int32 FailedExportIndex = INDEX_NONE;
        uint64 PublicExportHash = 0;
        FString RelativePath;
        if (!FindUniqueFailedLinkerExportForFunction(
                Function,
                FailedExportIndex,
                PublicExportHash,
                RelativePath,
                OutStopReason))
        {
            LogStockUFunctionNullSuperSkipped(
                Function,
                TriggerPackageName,
                ChainDepth,
                OutStopReason,
                FailedExportIndex,
                PublicExportHash,
                RelativePath);
            return false;
        }

        UFunction* SuperFunction =
            Cast<UFunction>(Function->GetSuperStruct());
        if (!SuperFunction || SuperFunction->IsUnreachable() ||
            SuperFunction == Function)
        {
            OutStopReason = TEXT("missing_or_invalid_super_function");
            LogStockUFunctionNullSuperSkipped(
                Function,
                TriggerPackageName,
                ChainDepth,
                OutStopReason,
                FailedExportIndex,
                PublicExportHash,
                RelativePath);
            return false;
        }
        if (Function->GetFName() != SuperFunction->GetFName())
        {
            OutStopReason = TEXT("super_function_name_mismatch");
            LogStockUFunctionNullSuperSkipped(
                Function,
                TriggerPackageName,
                ChainDepth,
                OutStopReason,
                FailedExportIndex,
                PublicExportHash,
                RelativePath);
            return false;
        }

        TArray<uint8>& Script = Function->Script;
        constexpr int32 OpcodeOffset = 0;
        constexpr int32 PointerOffset = 1;
        const int32 EndParmsOffset =
            PointerOffset + static_cast<int32>(sizeof(UPTRINT));
        if (Script.Num() <= EndParmsOffset)
        {
            OutStopReason = TEXT("script_too_small");
            LogStockUFunctionNullSuperSkipped(
                Function,
                TriggerPackageName,
                ChainDepth,
                OutStopReason,
                FailedExportIndex,
                PublicExportHash,
                RelativePath);
            return false;
        }
        if (Script[OpcodeOffset] != EX_LocalFinalFunction ||
            Script[EndParmsOffset] != EX_EndFunctionParms)
        {
            OutStopReason = TEXT("script_shape_mismatch");
            LogStockUFunctionNullSuperSkipped(
                Function,
                TriggerPackageName,
                ChainDepth,
                OutStopReason,
                FailedExportIndex,
                PublicExportHash,
                RelativePath);
            return false;
        }

        UPTRINT ExistingTarget = 0;
        FMemory::Memcpy(
            &ExistingTarget,
            Script.GetData() + PointerOffset,
            sizeof(ExistingTarget));
        if (ExistingTarget != 0)
        {
            OutStopReason = TEXT("operand_already_nonnull");
            LogStockUFunctionNullSuperSkipped(
                Function,
                TriggerPackageName,
                ChainDepth,
                OutStopReason,
                FailedExportIndex,
                PublicExportHash,
                RelativePath);
            return false;
        }

        if (IsVerboseSCMDiagnosticsEnabled())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_FIX STOCK_UFUNCTION_NULL_SUPER_CANDIDATE | triggerPackage='%s' | depth=%d | function='%s' | functionPackage='%s' | linkerExport=%d | publicHash=0x%016llX | relative='%s' | superFunction='%s' | opcode=EX_LocalFinalFunction | operand=null | endParms=YES | proof=FAILED_EXPORT_PATH_HASH_EXACT"),
                *TriggerPackageName,
                ChainDepth,
                *Function->GetPathName(),
                *Function->GetOutermost()->GetName(),
                FailedExportIndex,
                static_cast<unsigned long long>(PublicExportHash),
                *RelativePath,
                *SuperFunction->GetPathName());
        }

        static_assert(
            sizeof(UPTRINT) == sizeof(UFunction*),
            "SquadCookedMount stock UFunction repair requires platform pointer-sized bytecode operands");
        UPTRINT ReplacementTarget = 0;
        FMemory::Memcpy(
            &ReplacementTarget,
            &SuperFunction,
            sizeof(ReplacementTarget));
        FMemory::Memcpy(
            Script.GetData() + PointerOffset,
            &ReplacementTarget,
            sizeof(ReplacementTarget));

        Function->CollectBytecodeAndPropertyReferencedObjects();
        OutSuperFunction = SuperFunction;

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_FIX STOCK_UFUNCTION_NULL_SUPER_REPAIR_APPLIED | triggerPackage='%s' | depth=%d | function='%s' | functionPackage='%s' | linkerExport=%d | publicHash=0x%016llX | relative='%s' | superFunction='%s' | opcode=EX_LocalFinalFunction | previousOperand=null | replacement=SuperStruct | referencedObjectsRebuilt=YES | mutation=EXACT_FAILED_EXPORT_PATH_HASH_ONLY"),
            *TriggerPackageName,
            ChainDepth,
            *Function->GetPathName(),
            *Function->GetOutermost()->GetName(),
            FailedExportIndex,
            static_cast<unsigned long long>(PublicExportHash),
            *RelativePath,
            *SuperFunction->GetPathName());
        return true;
    }

    static int32 RepairStockUFunctionNullSuperChain(
        UFunction* StartFunction,
        const FString& TriggerPackageName)
    {
        if (!IsInGameThread() || !StartFunction)
        {
            return 0;
        }

        constexpr int32 MaxRepairDepth = 32;
        int32 RepairCount = 0;
        TSet<UFunction*> Visited;
        UFunction* Function = StartFunction;
        FString StopReason;

        for (int32 Depth = 0; Function && Depth < MaxRepairDepth; ++Depth)
        {
            if (Visited.Contains(Function))
            {
                StopReason = TEXT("cycle_detected");
                break;
            }
            Visited.Add(Function);

            UFunction* NextSuperFunction = nullptr;
            if (!TryRepairStockUFunctionNullSuperCall(
                    Function,
                    TriggerPackageName,
                    Depth,
                    NextSuperFunction,
                    StopReason))
            {
                break;
            }

            ++RepairCount;
            Function = NextSuperFunction;
        }

        if (RepairCount > 0)
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_FIX STOCK_UFUNCTION_NULL_SUPER_CHAIN_APPLIED | triggerPackage='%s' | startFunction='%s' | repairs=%d | stopReason='%s' | maxDepth=%d"),
                *TriggerPackageName,
                *StartFunction->GetPathName(),
                RepairCount,
                StopReason.IsEmpty() ? TEXT("max_depth_or_end") : *StopReason,
                MaxRepairDepth);
        }

        return RepairCount;
    }

    static int32 RepairStockUFunctionsForEndLoadedPackage(
        UPackage* Package)
    {
        if (!IsInGameThread() || !Package)
        {
            return 0;
        }

        const FPackageId PackageId =
            FPackageId::FromName(Package->GetFName());
        if (GSCMExternalPackageIds.Contains(PackageId))
        {
            return 0;
        }

        FLinkerLoad* Linker = Package->GetLinker();
        if (!Linker)
        {
            return 0;
        }

        const FString TriggerPackageName =
            FString::Printf(TEXT("EndLoad:%s"), *Package->GetName());
        int32 FailedExports = 0;
        int32 ExactLiveUFunctionCandidates = 0;
        int32 RepairCount = 0;
        TSet<UFunction*> AttemptedFunctions;

        for (int32 ExportIndex = 0;
             ExportIndex < Linker->ExportMap.Num();
             ++ExportIndex)
        {
            const FObjectExport& Export = Linker->ExportMap[ExportIndex];
            if (!Export.bExportLoadFailed)
            {
                continue;
            }
            ++FailedExports;

            FString ExportRelativePath;
            const uint64 ExportPublicHash =
                ComputeLinkerLoadExportHash(
                    Linker,
                    ExportIndex,
                    ExportRelativePath);
            if (ExportPublicHash == 0 || ExportRelativePath.IsEmpty())
            {
                continue;
            }

            int32 LiveMatches = 0;
            UFunction* Function =
                FindUniqueLiveUFunctionByExactPathHash(
                    Package,
                    ExportPublicHash,
                    ExportRelativePath,
                    LiveMatches);
            if (LiveMatches != 1 || !Function ||
                AttemptedFunctions.Contains(Function))
            {
                continue;
            }

            AttemptedFunctions.Add(Function);
            ++ExactLiveUFunctionCandidates;
            RepairCount +=
                RepairStockUFunctionNullSuperChain(
                    Function,
                    TriggerPackageName);
        }

        if (FailedExports > 0 && ExactLiveUFunctionCandidates > 0 &&
            (RepairCount > 0 || IsVerboseSCMDiagnosticsEnabled()))
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_FIX STOCK_UFUNCTION_NULL_SUPER_ENDLOAD_SCAN | package='%s' | id=0x%016llX | failedExports=%d | exactLiveUFunctionCandidates=%d | repairs=%d | endLoadDelegate=YES"),
                *Package->GetName(),
                static_cast<unsigned long long>(PackageId.Value()),
                FailedExports,
                ExactLiveUFunctionCandidates,
                RepairCount);
        }

        return RepairCount;
    }

    static FString MakeUFunctionBindingKey(
        FPackageId ParentPackageId,
        uint64 ParentPublicExportHash)
    {
        return FString::Printf(
            TEXT("%016llX_%016llX"),
            static_cast<unsigned long long>(ParentPackageId.Value()),
            static_cast<unsigned long long>(ParentPublicExportHash));
    }

    static bool RegisterLiveUFunctionScriptImport(
        UPackage* ParentPackage,
        UFunction* Function,
        uint64 ExpectedPublicExportHash,
        FPackageObjectIndex& OutScriptIndex,
        FString& OutScriptPath)
    {
        OutScriptIndex = FPackageObjectIndex();
        OutScriptPath.Reset();
        if (!IsInGameThread() || !ParentPackage || !Function ||
            ExpectedPublicExportHash == 0 ||
            Function->IsUnreachable() ||
            Function->GetOutermost() != ParentPackage)
        {
            return false;
        }

        const FString RelativePath = Function->GetPathName(ParentPackage);
        if (RelativePath.IsEmpty())
        {
            return false;
        }

        // AsyncLoading2 hashes script imports from a normalized object path.
        // Register the real regenerated/class-owned UFunction under the same
        // package-relative path, then point the external Zen header at that
        // ScriptImport. This avoids transient-package surrogate UFunctions.
        OutScriptPath = Function->GetPathName();
        OutScriptIndex = FPackageObjectIndex::FromScriptPath(
            FStringView(*OutScriptPath, OutScriptPath.Len()));

        const FString RegistrationPath = FString::Printf(
            TEXT("%s/%s"),
            *ParentPackage->GetName(),
            *RelativePath);
        const FPackageObjectIndex RegistrationIndex =
            FPackageObjectIndex::FromScriptPath(
                FStringView(*RegistrationPath, RegistrationPath.Len()));
        if (!OutScriptIndex.IsScriptImport() ||
            RegistrationIndex != OutScriptIndex)
        {
            UE_LOG(
                LogSquadCookedMount,
                Error,
                TEXT("SCM_FIX UFUNCTION_LIVE_SCRIPT_PATH_MISMATCH | function='%s' | relative='%s' | registration='%s' | objectIndex=0x%016llX | registrationIndex=0x%016llX | mutation=NO"),
                *OutScriptPath,
                *RelativePath,
                *RegistrationPath,
                static_cast<unsigned long long>(OutScriptIndex.Value()),
                static_cast<unsigned long long>(RegistrationIndex.Value()));
            OutScriptIndex = FPackageObjectIndex();
            OutScriptPath.Reset();
            return false;
        }

        FString VerifiedRelativePath;
        const uint64 VerifiedPublicHash =
            ComputeLiveObjectExportHash(
                Function,
                ParentPackage,
                VerifiedRelativePath);
        // ComputeLiveObjectExportHash returns the normalized Zen public-export
        // identity (lowercase, '/'-separated). Function->GetPathName(ParentPackage)
        // returns an Unreal object path (for example Class:Function). Comparing
        // those strings directly rejects valid Blueprint UFunctions. Verify the
        // same cooked PublicExportHash that selected this live function instead,
        // and do it before touching AsyncLoading2's ScriptObjects table.
        if (VerifiedPublicHash != ExpectedPublicExportHash)
        {
            UE_LOG(
                LogSquadCookedMount,
                Error,
                TEXT("SCM_FIX UFUNCTION_LIVE_PUBLIC_HASH_MISMATCH | function='%s' | relative='%s' | normalized='%s' | expectedHash=0x%016llX | verifiedHash=0x%016llX | mutation=NO"),
                *OutScriptPath,
                *RelativePath,
                *VerifiedRelativePath,
                static_cast<unsigned long long>(ExpectedPublicExportHash),
                static_cast<unsigned long long>(VerifiedPublicHash));
            return false;
        }

        NotifyRegistrationEvent(
            ParentPackage->GetFName(),
            FName(*RelativePath),
            ENotifyRegistrationType::NRT_NoExportObject,
            ENotifyRegistrationPhase::NRP_Finished,
            nullptr,
            true,
            Function);

        GSCMLiveUFunctionScriptPins.Add(
            OutScriptIndex,
            TStrongObjectPtr<UObject>(Function));
        FSCMLiveUFunctionScriptBindingDescriptor Descriptor;
        Descriptor.ParentPackageId =
            FPackageId::FromName(ParentPackage->GetFName());
        Descriptor.ParentPackageName = ParentPackage->GetFName();
        Descriptor.PublicExportHash = VerifiedPublicHash;
        GSCMLiveUFunctionScriptBindingDescriptors.Add(
            OutScriptIndex,
            MoveTemp(Descriptor));
        return true;
    }

    static bool ValidateZenDependencyBundleLayout(
        const FDiagnosticZenHeaderView& Header)
    {
        const int32 ExpectedHeaderCount =
            Header.ExportMap.Num() + Header.CellExportCount;
        bool bValid =
            Header.bHasDependencyBundles &&
            Header.DependencyBundleHeaders.Num() == ExpectedHeaderCount &&
            (!Header.DependencyBundleHeaders.IsEmpty() ||
             Header.DependencyBundleEntries.IsEmpty());

        uint64 ExpectedEntryIndex = 0;
        for (const FDependencyBundleHeader& DependencyHeader :
             Header.DependencyBundleHeaders)
        {
            uint64 TotalEntries = 0;
            for (uint32 CommandType = 0;
                 CommandType < FExportBundleEntry::ExportCommandType_Count;
                 ++CommandType)
            {
                for (uint32 DependencyType = 0;
                     DependencyType < FExportBundleEntry::ExportCommandType_Count;
                     ++DependencyType)
                {
                    TotalEntries +=
                        DependencyHeader.EntryCount[CommandType][DependencyType];
                }
            }

            if (DependencyHeader.FirstEntryIndex < 0)
            {
                if (TotalEntries != 0)
                {
                    bValid = false;
                    break;
                }
                continue;
            }

            const uint64 FirstEntry =
                static_cast<uint64>(DependencyHeader.FirstEntryIndex);
            if (FirstEntry != ExpectedEntryIndex ||
                FirstEntry + TotalEntries >
                    static_cast<uint64>(Header.DependencyBundleEntries.Num()))
            {
                bValid = false;
                break;
            }
            ExpectedEntryIndex += TotalEntries;
        }

        return bValid &&
            ExpectedEntryIndex ==
                static_cast<uint64>(Header.DependencyBundleEntries.Num());
    }

    static FString JoinDiagnosticLocalImportIndices(
        const TArray<int32, TInlineAllocator<8>>& Indices)
    {
        FString Result;
        for (int32 Index = 0; Index < Indices.Num(); ++Index)
        {
            if (Index > 0)
            {
                Result += TEXT(",");
            }
            Result += FString::FromInt(Indices[Index]);
        }
        return Result.IsEmpty() ? TEXT("<none>") : Result;
    }

    static void AuditZenDependencyBundleForPackageImport(
        const FDiagnosticZenHeaderView& Header,
        const FString& PackageName,
        const FString& ExportName,
        int32 ExportIndex,
        const TCHAR* FieldName,
        FPackageObjectIndex TargetIndex)
    {
        if (!TargetIndex.IsPackageImport())
        {
            return;
        }

        TArray<int32, TInlineAllocator<8>> MatchingLocalImports;
        for (int32 LocalImportIndex = 0;
             LocalImportIndex < Header.ImportMap.Num();
             ++LocalImportIndex)
        {
            if (Header.ImportMap[LocalImportIndex] == TargetIndex)
            {
                MatchingLocalImports.Add(LocalImportIndex);
            }
        }

        const bool bLayoutValid = ValidateZenDependencyBundleLayout(Header);
        int32 Counts[2][2] = {{0, 0}, {0, 0}};
        int32 TotalImportDependencies = 0;
        int32 MatchingDependencies = 0;
        int32 FirstEntryIndex = -1;

        if (bLayoutValid &&
            Header.DependencyBundleHeaders.IsValidIndex(ExportIndex))
        {
            const FDependencyBundleHeader& DependencyHeader =
                Header.DependencyBundleHeaders[ExportIndex];
            FirstEntryIndex = DependencyHeader.FirstEntryIndex;

            if (FirstEntryIndex >= 0)
            {
                int32 ReadIndex = FirstEntryIndex;
                for (int32 CommandType = 0;
                     CommandType < FExportBundleEntry::ExportCommandType_Count;
                     ++CommandType)
                {
                    for (int32 DependencyType = 0;
                         DependencyType < FExportBundleEntry::ExportCommandType_Count;
                         ++DependencyType)
                    {
                        const uint32 EntryCount =
                            DependencyHeader.EntryCount[CommandType][DependencyType];
                        for (uint32 EntryOffset = 0;
                             EntryOffset < EntryCount;
                             ++EntryOffset)
                        {
                            const FDependencyBundleEntry& Entry =
                                Header.DependencyBundleEntries[ReadIndex++];
                            if (!Entry.LocalImportOrExportIndex.IsImport())
                            {
                                continue;
                            }

                            ++TotalImportDependencies;
                            const int32 LocalImportIndex =
                                Entry.LocalImportOrExportIndex.ToImport();
                            if (MatchingLocalImports.Contains(LocalImportIndex))
                            {
                                ++Counts[CommandType][DependencyType];
                                ++MatchingDependencies;
                            }
                        }
                    }
                }
            }
        }

        const FString LocalImportText =
            JoinDiagnosticLocalImportIndices(MatchingLocalImports);
        const int32 CreatePhaseMatches = Counts[0][0] + Counts[0][1];
        const int32 SerializePhaseMatches = Counts[1][0] + Counts[1][1];

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_DIAG BP_DEP_BUNDLE | package='%s' | export='%s' | exportIndex=%d | field=%s | value=0x%016llX | layoutValid=%s | localImportSlots=%d[%s] | firstEntry=%d | importDeps=%d | matchingDeps=%d | createToCreate=%d | createToSerialize=%d | serializeToCreate=%d | serializeToSerialize=%d | createPhaseCoverage=%d | serializePhaseCoverage=%d | createBeforeFieldResolve=%s"),
            *PackageName,
            *ExportName,
            ExportIndex,
            FieldName,
            static_cast<unsigned long long>(TargetIndex.Value()),
            bLayoutValid ? TEXT("YES") : TEXT("NO"),
            MatchingLocalImports.Num(),
            *LocalImportText,
            FirstEntryIndex,
            TotalImportDependencies,
            MatchingDependencies,
            Counts[0][0],
            Counts[0][1],
            Counts[1][0],
            Counts[1][1],
            CreatePhaseMatches,
            SerializePhaseMatches,
            CreatePhaseMatches > 0 ? TEXT("YES") : TEXT("NO"));
    }

    static int32 PruneZenDependenciesForLocalImports(
        FDiagnosticZenHeaderView& Header,
        const TSet<int32>& LocalImportIndices)
    {
        if (LocalImportIndices.IsEmpty() ||
            !ValidateZenDependencyBundleLayout(Header))
        {
            return 0;
        }

        TArray<FDependencyBundleHeader> OriginalHeaders;
        OriginalHeaders.Append(
            Header.DependencyBundleHeaders.GetData(),
            Header.DependencyBundleHeaders.Num());
        TArray<FDependencyBundleEntry> OriginalEntries;
        OriginalEntries.Append(
            Header.DependencyBundleEntries.GetData(),
            Header.DependencyBundleEntries.Num());

        FDependencyBundleHeader* MutableHeaders =
            const_cast<FDependencyBundleHeader*>(
                Header.DependencyBundleHeaders.GetData());
        FDependencyBundleEntry* MutableEntries =
            const_cast<FDependencyBundleEntry*>(
                Header.DependencyBundleEntries.GetData());

        int32 WriteIndex = 0;
        int32 Pruned = 0;
        for (int32 HeaderIndex = 0;
             HeaderIndex < OriginalHeaders.Num();
             ++HeaderIndex)
        {
            const FDependencyBundleHeader& OriginalHeader =
                OriginalHeaders[HeaderIndex];
            FDependencyBundleHeader RebuiltHeader = OriginalHeader;
            FMemory::Memzero(
                RebuiltHeader.EntryCount,
                sizeof(RebuiltHeader.EntryCount));

            if (OriginalHeader.FirstEntryIndex < 0)
            {
                RebuiltHeader.FirstEntryIndex = -1;
                MutableHeaders[HeaderIndex] = RebuiltHeader;
                continue;
            }

            int32 ReadIndex = OriginalHeader.FirstEntryIndex;
            const int32 FirstWrittenEntry = WriteIndex;
            int32 KeptForHeader = 0;

            for (uint32 CommandType = 0;
                 CommandType < FExportBundleEntry::ExportCommandType_Count;
                 ++CommandType)
            {
                for (uint32 DependencyType = 0;
                     DependencyType < FExportBundleEntry::ExportCommandType_Count;
                     ++DependencyType)
                {
                    const uint32 OriginalCount =
                        OriginalHeader.EntryCount[CommandType][DependencyType];
                    uint32 KeptCount = 0;

                    for (uint32 EntryOffset = 0;
                         EntryOffset < OriginalCount;
                         ++EntryOffset)
                    {
                        const FDependencyBundleEntry& Entry =
                            OriginalEntries[ReadIndex++];
                        bool bPrune = false;
                        if (Entry.LocalImportOrExportIndex.IsImport())
                        {
                            const int32 LocalImportIndex =
                                Entry.LocalImportOrExportIndex.ToImport();
                            bPrune =
                                LocalImportIndices.Contains(LocalImportIndex);
                        }

                        if (bPrune)
                        {
                            ++Pruned;
                            continue;
                        }

                        MutableEntries[WriteIndex++] = Entry;
                        ++KeptCount;
                        ++KeptForHeader;
                    }

                    RebuiltHeader.EntryCount[CommandType][DependencyType] =
                        KeptCount;
                }
            }

            RebuiltHeader.FirstEntryIndex =
                KeptForHeader > 0 ? FirstWrittenEntry : -1;
            MutableHeaders[HeaderIndex] = RebuiltHeader;
        }

        for (int32 EntryIndex = WriteIndex;
             EntryIndex < Header.DependencyBundleEntries.Num();
             ++EntryIndex)
        {
            MutableEntries[EntryIndex] = FDependencyBundleEntry();
        }
        return Pruned;
    }

    static const TCHAR* DiagPackageStoreStatusToString(EPackageStoreEntryStatus Status)
    {
        switch (Status)
        {
        case EPackageStoreEntryStatus::None: return TEXT("None");
        case EPackageStoreEntryStatus::Missing: return TEXT("Missing");
        case EPackageStoreEntryStatus::NotInstalled: return TEXT("NotInstalled");
        case EPackageStoreEntryStatus::Pending: return TEXT("Pending");
        case EPackageStoreEntryStatus::Ok: return TEXT("Ok");
        default: return TEXT("Unknown");
        }
    }

    static const TCHAR* DiagPackageLoaderToString(EPackageLoader Loader)
    {
        switch (Loader)
        {
        case EPackageLoader::Unknown: return TEXT("Unknown");
        case EPackageLoader::LinkerLoad: return TEXT("LinkerLoad");
        case EPackageLoader::Zen: return TEXT("Zen");
        default: return TEXT("Mixed/Unknown");
        }
    }

    static const TCHAR* BoolText(bool bValue)
    {
        return bValue ? TEXT("YES") : TEXT("NO");
    }


    // ---------------------------------------------------------------------
    // Generic editor-only UFunction SuperStruct package-data overlay.
    // ---------------------------------------------------------------------
    // The backend owns only package-data chunks that were patched in memory.
    // All other requests fall through to the real IoStore backend. Chunks can
    // be added/replaced from the game thread before an external package load;
    // the dispatcher thread reads them under the same lock.
    class FSCMGenericBlueprintSuperIoOverlayBackend final : public IIoDispatcherBackend
    {
    public:
        virtual void Initialize(
            TSharedRef<const FIoDispatcherBackendContext> InContext) override
        {
            Context = InContext;
        }

        virtual void Shutdown() override
        {
            Context.Reset();
        }

        void AddOrReplaceChunk(const FIoChunkId& ChunkId, TArray<uint8>&& Bytes)
        {
            FScopeLock Lock(&ChunksCriticalSection);
            Chunks.Add(ChunkId, MoveTemp(Bytes));
        }

        int32 NumChunks() const
        {
            FScopeLock Lock(&ChunksCriticalSection);
            return Chunks.Num();
        }

        virtual void ResolveIoRequests(
            FIoRequestList Requests,
            FIoRequestList& OutUnresolved) override
        {
            bool bCompletedAny = false;

            while (FIoRequestImpl* Request = Requests.PopHead())
            {
                bool bOwned = false;
                uint64 Offset = 0;
                uint64 ReadSize = 0;

                {
                    FScopeLock Lock(&ChunksCriticalSection);
                    const TArray<uint8>* Bytes = Chunks.Find(Request->ChunkId);
                    if (!Bytes)
                    {
                        OutUnresolved.AddTail(Request);
                        continue;
                    }

                    bOwned = true;
                    if (!LoggedHits.Contains(Request->ChunkId))
                    {
                        LoggedHits.Add(Request->ChunkId);
                        FString ChunkText;
                        Request->ChunkId.ToString(ChunkText);
                        UE_LOG(
                            LogSquadCookedMount,
                            Verbose,
                            TEXT("SCM_FIX GENERIC_SUPER_OVERLAY_IO_HIT | chunk='%s' | totalBytes=%d"),
                            *ChunkText,
                            Bytes->Num());
                    }

                    Offset = Request->Options.GetOffset();
                    const uint64 TotalSize = static_cast<uint64>(Bytes->Num());
                    if (Offset > TotalSize)
                    {
                        Request->SetLastBackendError(EIoErrorCode::ReadError);
                    }
                    else
                    {
                        const uint64 Available = TotalSize - Offset;
                        const uint64 RequestedSize = Request->Options.GetSize();
                        ReadSize = RequestedSize == ~uint64(0)
                            ? Available
                            : FMath::Min(RequestedSize, Available);

                        Request->CreateBuffer(ReadSize);
                        if (ReadSize > 0)
                        {
                            FMemory::Memcpy(
                                Request->GetBuffer().Data(),
                                Bytes->GetData() + Offset,
                                static_cast<SIZE_T>(ReadSize));
                        }
                    }
                }

                if (bOwned)
                {
                    CompletedRequests.AddTail(Request);
                    bCompletedAny = true;
                }
            }

            if (bCompletedAny && Context.IsValid())
            {
                Context->WakeUpDispatcherThreadDelegate.ExecuteIfBound();
            }
        }

        virtual FIoRequestImpl* GetCompletedIoRequests() override
        {
            FIoRequestImpl* Head = nullptr;
            FIoRequestImpl* Tail = nullptr;

            while (FIoRequestImpl* Request = CompletedRequests.PopHead())
            {
                Request->NextRequest = nullptr;
                if (!Head)
                {
                    Head = Tail = Request;
                }
                else
                {
                    Tail->NextRequest = Request;
                    Tail = Request;
                }
            }
            return Head;
        }

        virtual void CancelIoRequest(FIoRequestImpl* /*Request*/) override {}
        virtual void UpdatePriorityForIoRequest(FIoRequestImpl* /*Request*/) override {}

        virtual bool DoesChunkExist(const FIoChunkId& ChunkId) const override
        {
            FScopeLock Lock(&ChunksCriticalSection);
            return Chunks.Contains(ChunkId);
        }

        virtual TIoStatusOr<uint64> GetSizeForChunk(
            const FIoChunkId& ChunkId) const override
        {
            FScopeLock Lock(&ChunksCriticalSection);
            if (const TArray<uint8>* Bytes = Chunks.Find(ChunkId))
            {
                return static_cast<uint64>(Bytes->Num());
            }
            return FIoStatus(EIoErrorCode::NotFound);
        }

        virtual TIoStatusOr<FIoMappedRegion> OpenMapped(
            const FIoChunkId& /*ChunkId*/,
            const FIoReadOptions& /*Options*/) override
        {
            return FIoStatus(EIoErrorCode::NotFound);
        }

        virtual const TCHAR* GetName() const override
        {
            return TEXT("SquadCookedMountGenericBlueprintSuperOverlay");
        }

    private:
        TSharedPtr<const FIoDispatcherBackendContext> Context;
        mutable FCriticalSection ChunksCriticalSection;
        TMap<FIoChunkId, TArray<uint8>> Chunks;
        TSet<FIoChunkId> LoggedHits;
        FIoRequestList CompletedRequests;
    };

    static TSharedPtr<FSCMGenericBlueprintSuperIoOverlayBackend>
        GSCMGenericBlueprintSuperOverlay;

    // ---------------------------------------------------------------------
    // v0.3.17v6.1: synthetic-export bridge ABI/link fix (no FObjectExport(UObject*) constructor dependency).
    // ---------------------------------------------------------------------
    class FSCMMaterialErrorCapture final : public FOutputDevice
    {
    public:
        struct FInvalidShaderMapRecord
        {
            FString ObjectPath;
            FString PackagePath;
            FString ClassPath;
            ELogVerbosity::Type Verbosity = ELogVerbosity::NoLogging;
        };

        virtual bool CanBeUsedOnAnyThread() const override { return true; }
        virtual bool CanBeUsedOnMultipleThreads() const override { return true; }

        virtual void Serialize(
            const TCHAR* V,
            ELogVerbosity::Type Verbosity,
            const FName& Category) override
        {
            if (!V ||
                Category != FName(TEXT("LogMaterial")) ||
                FCString::Stristr(V, TEXT("invalid ShaderMap")) == nullptr)
            {
                return;
            }

            static thread_local bool bInsideCapture = false;
            if (bInsideCapture)
            {
                return;
            }
            TGuardValue<bool> ReentryGuard(bInsideCapture, true);

            FUObjectSerializeContext* SerializeContext =
                FUObjectThreadContext::Get().GetSerializeContext();
            UObject* SerializedObject =
                SerializeContext ? SerializeContext->SerializedObject : nullptr;
            FLinkerLoad* SerializedLinker =
                SerializeContext ? SerializeContext->SerializedPackageLinker : nullptr;

            const FString ObjectPath =
                SerializedObject ? SerializedObject->GetPathName() : TEXT("<none>");
            const FString PackagePath =
                SerializedObject && SerializedObject->GetOutermost()
                    ? SerializedObject->GetOutermost()->GetName()
                    : (SerializedLinker && SerializedLinker->LinkerRoot
                        ? SerializedLinker->LinkerRoot->GetName()
                        : TEXT("<none>"));
            const FString ClassPath =
                SerializedObject ? SerializedObject->GetClass()->GetPathName() : TEXT("<none>");

            {
                FScopeLock Lock(&RecordsCriticalSection);
                FInvalidShaderMapRecord& Record = Records.AddDefaulted_GetRef();
                Record.ObjectPath = ObjectPath;
                Record.PackagePath = PackagePath;
                Record.ClassPath = ClassPath;
                Record.Verbosity = Verbosity;
            }

            // Capturing this context is functional cook-gate state, not
            // diagnostics. Keep the per-error line opt-in so normal cook logs
            // do not repeat every expected NullRHI ShaderMap diagnostic.
            if (IsVerboseSCMDiagnosticsEnabled())
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Display,
                    TEXT("SCM_DIAG MATERIAL_ERROR_CONTEXT | object='%s' | package='%s' | class='%s' | serializedExportIndex=%d | linker='%s' | original='%s'"),
                    *ObjectPath,
                    *PackagePath,
                    *ClassPath,
                    SerializeContext ? SerializeContext->SerializedExportIndex : INDEX_NONE,
                    SerializedLinker ? *SerializedLinker->GetDebugName() : TEXT("<none>"),
                    V);
            }
        }

        void SnapshotRecords(TArray<FInvalidShaderMapRecord>& OutRecords) const
        {
            FScopeLock Lock(&RecordsCriticalSection);
            OutRecords = Records;
        }

    private:
        mutable FCriticalSection RecordsCriticalSection;
        TArray<FInvalidShaderMapRecord> Records;
    };

    static TUniquePtr<FSCMMaterialErrorCapture> GSCMMaterialErrorCapture;
}

void FSquadCookedMountModule::StartTargetedDiagnostics()
{
#if WITH_EDITOR
    if (!DiagnosticSyncLoadPackageHandle.IsValid())
    {
        DiagnosticSyncLoadPackageHandle =
            FCoreDelegates::OnSyncLoadPackage.AddRaw(
                this,
                &FSquadCookedMountModule::OnDiagnosticSyncLoadPackage);
    }

    if (!DiagnosticAsyncLoadPackageHandle.IsValid())
    {
        DiagnosticAsyncLoadPackageHandle =
            FCoreDelegates::GetOnAsyncLoadPackage().AddRaw(
                this,
                &FSquadCookedMountModule::OnDiagnosticAsyncLoadPackage);
    }

    if (!DiagnosticEndLoadPackageHandle.IsValid())
    {
        DiagnosticEndLoadPackageHandle =
            FCoreUObjectDelegates::OnEndLoadPackage.AddRaw(
                this,
                &FSquadCookedMountModule::OnDiagnosticEndLoadPackage);
    }

    // Sync/async/end-load delegates above are behavior-critical: they prepare
    // the SuperStruct overlay and apply EndLoad fixups. The material capture is
    // also behavior-critical for -nullrhi cook: OnCookCommandletPostMain uses
    // its exact serialization context to remove only proven external cooked
    // Material invalid-ShaderMap errors. v6.8.5 accidentally made that capture
    // diagnostic-only, which disabled the gate in normal cook. Restore capture
    // for cook while keeping heavy per-error tracing strictly opt-in.
    const bool bNeedMaterialErrorCapture =
        bCookCommandletMode || SquadCookedMount::IsVerboseSCMDiagnosticsEnabled();
    if (bNeedMaterialErrorCapture && !SquadCookedMount::GSCMMaterialErrorCapture)
    {
        SquadCookedMount::GSCMMaterialErrorCapture =
            MakeUnique<SquadCookedMount::FSCMMaterialErrorCapture>();
        if (GLog)
        {
            GLog->AddOutputDevice(
                SquadCookedMount::GSCMMaterialErrorCapture.Get());
        }
    }

    if (SquadCookedMount::IsVerboseSCMDiagnosticsEnabled())
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_DIAG verbose tracing enabled by -SCMDiagnostics"));
    }
#endif
}

void FSquadCookedMountModule::StopTargetedDiagnostics()
{
#if WITH_EDITOR
    if (DiagnosticSyncLoadPackageHandle.IsValid())
    {
        FCoreDelegates::OnSyncLoadPackage.Remove(DiagnosticSyncLoadPackageHandle);
        DiagnosticSyncLoadPackageHandle.Reset();
    }

    if (DiagnosticAsyncLoadPackageHandle.IsValid())
    {
        FCoreDelegates::GetOnAsyncLoadPackage().Remove(
            DiagnosticAsyncLoadPackageHandle);
        DiagnosticAsyncLoadPackageHandle.Reset();
    }

    if (DiagnosticEndLoadPackageHandle.IsValid())
    {
        FCoreUObjectDelegates::OnEndLoadPackage.Remove(DiagnosticEndLoadPackageHandle);
        DiagnosticEndLoadPackageHandle.Reset();
    }

    if (SquadCookedMount::GSCMMaterialErrorCapture)
    {
        if (GLog)
        {
            GLog->RemoveOutputDevice(
                SquadCookedMount::GSCMMaterialErrorCapture.Get());
        }
        SquadCookedMount::GSCMMaterialErrorCapture.Reset();
    }

#endif
}


bool FSquadCookedMountModule::PrepareGenericBlueprintSuperOverlayForPackage(
    const FString& PackageName,
    bool bAllowKnownFailedStockUFunctionImports)
{
#if WITH_EDITOR
    if (bCookCommandletMode || !bCrossLoaderImportIndexReady ||
        PackageName.IsEmpty() ||
        !IsInGameThread() || !FIoDispatcher::IsInitialized() ||
        MountedPakPaths.IsEmpty())
    {
        return false;
    }

    bool bExternal = false;
    for (const FString& Root : MountedCookedLongRoots)
    {
        if (PackageName.StartsWith(Root, ESearchCase::IgnoreCase))
        {
            bExternal = true;
            break;
        }
    }
    if (!bExternal)
    {
        return false;
    }

    const FName PackageFName(*PackageName);
    FPackageId PackageId = FPackageId::FromName(PackageFName);
    if (const FPackageId* KnownId = ExternalPackageNameToId.Find(PackageFName))
    {
        PackageId = *KnownId;
    }
    if (!PackageId.IsValid())
    {
        return false;
    }

    if (SquadCookedMount::GSCMPreparingGenericSuperOverlayPackages.Contains(PackageId))
    {
        return false;
    }
    SquadCookedMount::GSCMPreparingGenericSuperOverlayPackages.Add(PackageId);
    ON_SCOPE_EXIT
    {
        SquadCookedMount::GSCMPreparingGenericSuperOverlayPackages.Remove(PackageId);
    };

    // The package-data chunk has to be replaced before Zen starts creating
    // exports. If the external package is already live, changing the backend
    // now would only affect a future reload and could make diagnostics lie.
    UPackage* ExistingExternalPackage = FindPackage(nullptr, *PackageName);
    if (ExistingExternalPackage &&
        (ExistingExternalPackage->bHasBeenFullyLoaded ||
         ExistingExternalPackage->HasAnyFlags(RF_WasLoaded | RF_LoadCompleted)))
    {
        return false;
    }

    TArray<uint8> PackageData;
    FString SourceUtoc;
    FString ReadError;
    if (!SquadCookedMount::ReadDiagnosticPackageData(
            MountedPakPaths,
            PackageId,
            PackageData,
            SourceUtoc,
            ReadError))
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_FIX GENERIC_SUPER_OVERLAY_READ_FAIL | package='%s' | id=0x%016llX | error='%s' | mutation=NO"),
            *PackageName,
            static_cast<unsigned long long>(PackageId.Value()),
            *ReadError);
        return false;
    }

    SquadCookedMount::FDiagnosticZenHeaderView Header;
    FString ParseError;
    if (!SquadCookedMount::ParseDiagnosticZenHeader(
            PackageData,
            Header,
            ParseError))
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_FIX GENERIC_SUPER_OVERLAY_PARSE_FAIL | package='%s' | source='%s' | error='%s'"),
            *PackageName,
            *SourceUtoc,
            *ParseError);
        return false;
    }

    TArray<FPackageId> ImportedPackageIds;
    bool bImportedIdsFromIndex = false;
    if (const TArray<FPackageId>* IndexedImportedIds =
            ExternalPackageImportedPackageIds.Find(PackageId))
    {
        ImportedPackageIds = *IndexedImportedIds;
        bImportedIdsFromIndex = !ImportedPackageIds.IsEmpty();
    }

    // Fallback for packages discovered after the initial immutable container scan.
    // Indexed startup targets should never need this path.
    if (ImportedPackageIds.IsEmpty())
    {
        FPackageStore& PackageStore = FPackageStore::Get();
        FPackageStoreReadScope ReadScope(PackageStore);
        FPackageStoreEntry Entry;
        const EPackageStoreEntryStatus Status =
            PackageStore.GetPackageStoreEntry(PackageId, PackageFName, Entry);
        if (Status == EPackageStoreEntryStatus::Ok)
        {
            ImportedPackageIds.Append(
                Entry.ImportedPackageIds.GetData(),
                Entry.ImportedPackageIds.Num());
        }
    }
    if (ImportedPackageIds.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_FIX GENERIC_SUPER_OVERLAY_IMPORT_IDS_MISSING | package='%s' | id=0x%016llX | indexedEntry=%s | mutation=NO"),
            *PackageName,
            static_cast<unsigned long long>(PackageId.Value()),
            ExternalPackageImportedPackageIds.Contains(PackageId) ? TEXT("YES_EMPTY") : TEXT("NO"));
        return false;
    }

    // Stock UFunction SuperStruct parents are first-loaded by the JIT preflight
    // before this function runs. Other stock dependencies remain PackageImports
    // and are handled by the LinkerLoad reindex bridge / AsyncLoading2.

    // Prepare only the external packages that are actual UFunction SuperIndex
    // parents of this package. This is metadata preparation only: it never
    // loads an external parent package and therefore leaves AsyncLoading2's
    // dependency scheduler in charge of external->external load order.
    for (const FExportMapEntry& Export : Header.ExportMap)
    {
        if (!Export.SuperIndex.IsPackageImport())
        {
            continue;
        }
        const FPackageImportReference ImportRef =
            Export.SuperIndex.ToPackageImportRef();
        const uint32 ImportedPackageIndex =
            ImportRef.GetImportedPackageIndex();
        if (ImportedPackageIndex >= static_cast<uint32>(ImportedPackageIds.Num()))
        {
            continue;
        }
        const FPackageId ParentPackageId =
            ImportedPackageIds[ImportedPackageIndex];
        if (!SquadCookedMount::GSCMExternalPackageIds.Contains(ParentPackageId) ||
            ParentPackageId == PackageId)
        {
            continue;
        }

        FName ParentPackageName = NAME_None;
        if (Header.ImportedPackageNames.IsValidIndex(
                static_cast<int32>(ImportedPackageIndex)))
        {
            ParentPackageName =
                Header.ImportedPackageNames[ImportedPackageIndex];
        }
        if (ParentPackageName.IsNone())
        {
            for (const TPair<FName, FPackageId>& Pair : ExternalPackageNameToId)
            {
                if (Pair.Value == ParentPackageId)
                {
                    ParentPackageName = Pair.Key;
                    break;
                }
            }
        }
        if (!ParentPackageName.IsNone())
        {
            PrepareGenericBlueprintSuperOverlayForPackage(
                ParentPackageName.ToString());
        }
    }

    // JIT bridge for stock Blueprint UFunctions. The external package is
    // patched only after its exact stock UFunction parents are live. Real
    // regenerated/class-owned UFunctions are registered in AsyncLoading2 as
    // ScriptImports; no transient-package surrogate object is created.
    const FString FunctionClassPath = UFunction::StaticClass()->GetPathName();
    const FPackageObjectIndex FunctionClassIndex =
        FPackageObjectIndex::FromScriptPath(
            FStringView(*FunctionClassPath, FunctionClassPath.Len()));

    TMap<FPackageId, TSet<uint64>> LocalUFunctionSuperHashesByParent;
    for (const FExportMapEntry& Export : Header.ExportMap)
    {
        if (Export.ClassIndex != FunctionClassIndex ||
            !Export.SuperIndex.IsPackageImport())
        {
            continue;
        }

        const FPackageImportReference SuperRef =
            Export.SuperIndex.ToPackageImportRef();
        const uint32 SuperPackageIndex = SuperRef.GetImportedPackageIndex();
        const uint32 SuperHashIndex =
            SuperRef.GetImportedPublicExportHashIndex();
        if (SuperPackageIndex >= static_cast<uint32>(ImportedPackageIds.Num()) ||
            SuperHashIndex >= static_cast<uint32>(Header.ImportedPublicExportHashes.Num()))
        {
            continue;
        }

        const FPackageId ParentPackageId = ImportedPackageIds[SuperPackageIndex];
        const uint64 ParentPublicExportHash =
            Header.ImportedPublicExportHashes[SuperHashIndex];
        if (ParentPackageId.IsValid() && ParentPublicExportHash != 0 &&
            !SquadCookedMount::GSCMExternalPackageIds.Contains(ParentPackageId))
        {
            LocalUFunctionSuperHashesByParent
                .FindOrAdd(ParentPackageId)
                .Add(ParentPublicExportHash);
        }
    }

    struct FLiveUFunctionBinding
    {
        UFunction* Function = nullptr;
        FPackageObjectIndex ScriptIndex;
        FString ScriptPath;
        FString RelativePath;
        bool bLinkerExportLoadFailed = false;
        bool bLiveFallback = false;
    };

    TMap<FString, FLiveUFunctionBinding> LiveUFunctionBindings;
    int32 LiveScriptImports = 0;
    int32 LiveScriptSuperIndices = 0;
    int32 LiveScriptPrunedDependencies = 0;
    int32 LiveScriptMissingTargets = 0;
    int32 LiveScriptAmbiguousTargets = 0;
    int32 LiveScriptRegistrationFailures = 0;

    auto ResolveParentName =
        [this, &Header](uint32 ImportedPackageIndex, FPackageId ParentPackageId)
        {
            FName ParentPackageName = NAME_None;
            if (Header.ImportedPackageNames.IsValidIndex(
                    static_cast<int32>(ImportedPackageIndex)))
            {
                ParentPackageName = Header.ImportedPackageNames[ImportedPackageIndex];
            }
            if (ParentPackageName.IsNone())
            {
                if (const FName* KnownName =
                        CrossLoaderParentPackageNames.Find(ParentPackageId))
                {
                    ParentPackageName = *KnownName;
                }
            }
#if WITH_PACKAGEID_NAME_MAP
            if (ParentPackageName.IsNone())
            {
                ParentPackageName = ParentPackageId.GetName();
            }
#endif
            return ParentPackageName;
        };

    auto ResolveLiveUFunctionBinding =
        [&LiveUFunctionBindings,
         &LiveScriptMissingTargets,
         &LiveScriptAmbiguousTargets,
         &LiveScriptRegistrationFailures](
            FPackageId ParentPackageId,
            FName ParentPackageName,
            uint64 ParentPublicExportHash,
            FLiveUFunctionBinding*& OutBinding)
        {
            OutBinding = nullptr;
            const FString BindingKey = SquadCookedMount::MakeUFunctionBindingKey(
                ParentPackageId,
                ParentPublicExportHash);
            if (FLiveUFunctionBinding* Existing =
                    LiveUFunctionBindings.Find(BindingKey))
            {
                OutBinding = Existing;
                return true;
            }

            if (ParentPackageName.IsNone())
            {
                ++LiveScriptMissingTargets;
                return false;
            }

            UPackage* ParentPackage =
                FindPackage(nullptr, *ParentPackageName.ToString());
            FLinkerLoad* ParentLinker =
                ParentPackage ? ParentPackage->GetLinker() : nullptr;
            if (!ParentPackage)
            {
                ++LiveScriptMissingTargets;
                return false;
            }

            int32 ParentMatches = 0;
            FString ParentRelativePath;
            bool bParentExportLoadFailed = false;
            bool bParentFromLiveFallback = false;
            UFunction* ParentFunction =
                SquadCookedMount::FindUniqueLiveUFunctionByExportHash(
                    ParentPackage,
                    ParentLinker,
                    ParentPublicExportHash,
                    ParentMatches,
                    ParentRelativePath,
                    bParentExportLoadFailed,
                    bParentFromLiveFallback);
            if (ParentMatches != 1 || !ParentFunction)
            {
                if (ParentMatches > 1)
                {
                    ++LiveScriptAmbiguousTargets;
                }
                else
                {
                    ++LiveScriptMissingTargets;
                }
                return false;
            }

            FLiveUFunctionBinding Binding;
            Binding.Function = ParentFunction;
            Binding.RelativePath = ParentRelativePath;
            Binding.bLinkerExportLoadFailed = bParentExportLoadFailed;
            Binding.bLiveFallback = bParentFromLiveFallback;
            if (!SquadCookedMount::RegisterLiveUFunctionScriptImport(
                    ParentPackage,
                    ParentFunction,
                    ParentPublicExportHash,
                    Binding.ScriptIndex,
                    Binding.ScriptPath))
            {
                ++LiveScriptRegistrationFailures;
                return false;
            }

            FLiveUFunctionBinding& Stored =
                LiveUFunctionBindings.Add(BindingKey, MoveTemp(Binding));
            OutBinding = &Stored;
            return true;
        };

    const bool bDependencyLayoutValid =
        SquadCookedMount::ValidateZenDependencyBundleLayout(Header);

    // If an exact UFunction SuperIndex is also present in ImportMap, serialized
    // bytecode can reference the same function through that local import slot.
    // Converting ImportMap to ScriptImport requires removing dependency-bundle
    // entries for that slot because UE5.7 ConditionalCreateImport/
    // ConditionalSerializeImport assert PackageImport. If the dependency layout
    // cannot be validated, refuse the whole overlay instead of creating a
    // partially working function with broken bytecode references.
    bool bSharedUFunctionSuperImport = false;
    for (const FPackageObjectIndex& LocalImport : Header.ImportMap)
    {
        if (!LocalImport.IsPackageImport())
        {
            continue;
        }
        const FPackageImportReference Ref = LocalImport.ToPackageImportRef();
        const uint32 PackageIndex = Ref.GetImportedPackageIndex();
        const uint32 HashIndex = Ref.GetImportedPublicExportHashIndex();
        if (PackageIndex >= static_cast<uint32>(ImportedPackageIds.Num()) ||
            HashIndex >= static_cast<uint32>(Header.ImportedPublicExportHashes.Num()))
        {
            continue;
        }
        const FPackageId ParentPackageId = ImportedPackageIds[PackageIndex];
        const uint64 ParentPublicExportHash =
            Header.ImportedPublicExportHashes[HashIndex];
        const TSet<uint64>* SuperHashes =
            LocalUFunctionSuperHashesByParent.Find(ParentPackageId);
        if (SuperHashes && SuperHashes->Contains(ParentPublicExportHash))
        {
            bSharedUFunctionSuperImport = true;
            break;
        }
    }
    if (bSharedUFunctionSuperImport && !bDependencyLayoutValid)
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("SCM_FIX UFUNCTION_LIVE_BRIDGE_DEP_LAYOUT_INVALID | package='%s' | sharedSuperImport=YES | mutation=NO"),
            *PackageName);
        return false;
    }

    TSet<int32> LiveScriptLocalImportIndices;

    // Convert only imports proven to refer to a UFunction: either the exact
    // import is a UFunction SuperIndex in this package, or the stock refresh
    // previously classified that exact public hash as a broken UFunction.
    if (bDependencyLayoutValid)
    {
        for (int32 ImportIndex = 0;
             ImportIndex < Header.ImportMap.Num();
             ++ImportIndex)
        {
            const FPackageObjectIndex OriginalIndex = Header.ImportMap[ImportIndex];
            if (!OriginalIndex.IsPackageImport())
            {
                continue;
            }

            const FPackageImportReference ImportRef =
                OriginalIndex.ToPackageImportRef();
            const uint32 ImportedPackageIndex =
                ImportRef.GetImportedPackageIndex();
            const uint32 PublicHashIndex =
                ImportRef.GetImportedPublicExportHashIndex();
            if (ImportedPackageIndex >= static_cast<uint32>(ImportedPackageIds.Num()) ||
                PublicHashIndex >= static_cast<uint32>(Header.ImportedPublicExportHashes.Num()))
            {
                continue;
            }

            const FPackageId ParentPackageId =
                ImportedPackageIds[ImportedPackageIndex];
            const uint64 ParentPublicExportHash =
                Header.ImportedPublicExportHashes[PublicHashIndex];
            if (!ParentPackageId.IsValid() || ParentPublicExportHash == 0 ||
                SquadCookedMount::GSCMExternalPackageIds.Contains(ParentPackageId))
            {
                continue;
            }

            const TSet<uint64>* LocalSuperHashes =
                LocalUFunctionSuperHashesByParent.Find(ParentPackageId);
            const bool bLocalUFunctionSuperUse =
                LocalSuperHashes &&
                LocalSuperHashes->Contains(ParentPublicExportHash);
            const TSet<uint64>* KnownFunctionHashes =
                EditorSuperOverlayParentHashes.Find(ParentPackageId);
            const bool bKnownFailedStockUFunctionImport =
                bAllowKnownFailedStockUFunctionImports &&
                KnownFunctionHashes &&
                KnownFunctionHashes->Contains(ParentPublicExportHash);
            if (!bLocalUFunctionSuperUse && !bKnownFailedStockUFunctionImport)
            {
                continue;
            }

            const FName ParentPackageName =
                ResolveParentName(ImportedPackageIndex, ParentPackageId);
            FLiveUFunctionBinding* Binding = nullptr;
            if (!ResolveLiveUFunctionBinding(
                    ParentPackageId,
                    ParentPackageName,
                    ParentPublicExportHash,
                    Binding) ||
                !Binding)
            {
                continue;
            }

            FPackageObjectIndex& MutableImport =
                const_cast<FPackageObjectIndex&>(Header.ImportMap[ImportIndex]);
            MutableImport = Binding->ScriptIndex;
            LiveScriptLocalImportIndices.Add(ImportIndex);
            EditorSuperOverlayParentHashes
                .FindOrAdd(ParentPackageId)
                .Add(ParentPublicExportHash);
            ++LiveScriptImports;

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_FIX UFUNCTION_LIVE_SCRIPT_IMPORT | package='%s' | importIndex=%d | original=0x%016llX | parent='%s' | parentId=0x%016llX | publicHash=0x%016llX | target='%s' | scriptIndex=0x%016llX | localSuper=%s | knownFailed=%s | parentLoadFailed=%s | liveFallback=%s"),
                *PackageName,
                ImportIndex,
                static_cast<unsigned long long>(OriginalIndex.Value()),
                *ParentPackageName.ToString(),
                static_cast<unsigned long long>(ParentPackageId.Value()),
                static_cast<unsigned long long>(ParentPublicExportHash),
                *Binding->ScriptPath,
                static_cast<unsigned long long>(Binding->ScriptIndex.Value()),
                bLocalUFunctionSuperUse ? TEXT("YES") : TEXT("NO"),
                bKnownFailedStockUFunctionImport ? TEXT("YES") : TEXT("NO"),
                Binding->bLinkerExportLoadFailed ? TEXT("YES") : TEXT("NO"),
                Binding->bLiveFallback ? TEXT("YES") : TEXT("NO"));
        }

        LiveScriptPrunedDependencies =
            SquadCookedMount::PruneZenDependenciesForLocalImports(
                Header,
                LiveScriptLocalImportIndices);
    }

    // A UFunction export may use a PackageImport SuperIndex without sharing
    // that exact index through ImportMap. Patch SuperIndex directly to the real
    // live ScriptImport so EventDrivenCreateExport receives a class-owned
    // UFunction and never a transient surrogate or null SuperStruct.
    for (int32 ExportIndex = 0; ExportIndex < Header.ExportMap.Num(); ++ExportIndex)
    {
        const FExportMapEntry& Export = Header.ExportMap[ExportIndex];
        if (Export.ClassIndex != FunctionClassIndex ||
            !Export.SuperIndex.IsPackageImport())
        {
            continue;
        }

        const FPackageImportReference ImportRef =
            Export.SuperIndex.ToPackageImportRef();
        const uint32 ImportedPackageIndex = ImportRef.GetImportedPackageIndex();
        const uint32 PublicHashIndex =
            ImportRef.GetImportedPublicExportHashIndex();
        if (ImportedPackageIndex >= static_cast<uint32>(ImportedPackageIds.Num()) ||
            PublicHashIndex >= static_cast<uint32>(Header.ImportedPublicExportHashes.Num()))
        {
            continue;
        }

        const FPackageId ParentPackageId =
            ImportedPackageIds[ImportedPackageIndex];
        const uint64 ParentPublicExportHash =
            Header.ImportedPublicExportHashes[PublicHashIndex];
        if (!ParentPackageId.IsValid() || ParentPublicExportHash == 0 ||
            SquadCookedMount::GSCMExternalPackageIds.Contains(ParentPackageId))
        {
            continue;
        }

        const FName ParentPackageName =
            ResolveParentName(ImportedPackageIndex, ParentPackageId);
        FLiveUFunctionBinding* Binding = nullptr;
        if (!ResolveLiveUFunctionBinding(
                ParentPackageId,
                ParentPackageName,
                ParentPublicExportHash,
                Binding) ||
            !Binding)
        {
            continue;
        }

        FExportMapEntry& MutableExport =
            const_cast<FExportMapEntry&>(Header.ExportMap[ExportIndex]);
        const uint64 OriginalSuperValue = MutableExport.SuperIndex.Value();
        MutableExport.SuperIndex = Binding->ScriptIndex;
        EditorSuperOverlayParentHashes
            .FindOrAdd(ParentPackageId)
            .Add(ParentPublicExportHash);
        ++LiveScriptSuperIndices;

        UE_LOG(
            LogSquadCookedMount,
            Verbose,
            TEXT("SCM_FIX UFUNCTION_LIVE_SUPER_IMPORT | package='%s' | export='%s' | exportIndex=%d | originalSuper=0x%016llX | parent='%s' | parentId=0x%016llX | parentHash=0x%016llX | target='%s' | scriptIndex=0x%016llX | parentLoadFailed=%s | liveFallback=%s"),
            *PackageName,
            *Header.NameMap.GetName(Export.ObjectName).ToString(),
            ExportIndex,
            static_cast<unsigned long long>(OriginalSuperValue),
            *ParentPackageName.ToString(),
            static_cast<unsigned long long>(ParentPackageId.Value()),
            static_cast<unsigned long long>(ParentPublicExportHash),
            *Binding->ScriptPath,
            static_cast<unsigned long long>(Binding->ScriptIndex.Value()),
            Binding->bLinkerExportLoadFailed ? TEXT("YES") : TEXT("NO"),
            Binding->bLiveFallback ? TEXT("YES") : TEXT("NO"));
    }

    if (LiveScriptSuperIndices == 0 && LiveScriptImports == 0)
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_FIX GENERIC_SUPER_OVERLAY_NO_BINDINGS | package='%s' | id=0x%016llX | importedIds=%d | importedIdSource=%s | localSuperParents=%d | missingTargets=%d | ambiguousTargets=%d | registrationFailures=%d | mutation=NO"),
            *PackageName,
            static_cast<unsigned long long>(PackageId.Value()),
            ImportedPackageIds.Num(),
            bImportedIdsFromIndex ? TEXT("INDEX") : TEXT("PACKAGE_STORE"),
            LocalUFunctionSuperHashesByParent.Num(),
            LiveScriptMissingTargets,
            LiveScriptAmbiguousTargets,
            LiveScriptRegistrationFailures);
        return false;
    }

    const FIoChunkId ChunkId = CreatePackageDataChunkId(PackageId);
    if (!SquadCookedMount::GSCMGenericBlueprintSuperOverlay.IsValid())
    {
        SquadCookedMount::GSCMGenericBlueprintSuperOverlay =
            MakeShared<SquadCookedMount::FSCMGenericBlueprintSuperIoOverlayBackend>();
        SquadCookedMount::GSCMGenericBlueprintSuperOverlay->AddOrReplaceChunk(
            ChunkId,
            MoveTemp(PackageData));
        FIoDispatcher::Get().Mount(
            SquadCookedMount::GSCMGenericBlueprintSuperOverlay.ToSharedRef(),
            1000);
        bGenericBlueprintSuperIoOverlayMounted = true;
    }
    else
    {
        SquadCookedMount::GSCMGenericBlueprintSuperOverlay->AddOrReplaceChunk(
            ChunkId,
            MoveTemp(PackageData));
        bGenericBlueprintSuperIoOverlayMounted = true;
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_FIX GENERIC_SUPER_OVERLAY_READY | package='%s' | id=0x%016llX | importedIdSource=%s | liveScriptSuperIndices=%d | liveScriptImports=%d | prunedDependencies=%d | missingTargets=%d | ambiguousTargets=%d | registrationFailures=%d | dependencyLayout=%s | overlayChunks=%d | surrogateUFunctions=NO | diskFilesModified=NO | hardcodedAssets=NO"),
        *PackageName,
        static_cast<unsigned long long>(PackageId.Value()),
        bImportedIdsFromIndex ? TEXT("INDEX") : TEXT("PACKAGE_STORE"),
        LiveScriptSuperIndices,
        LiveScriptImports,
        LiveScriptPrunedDependencies,
        LiveScriptMissingTargets,
        LiveScriptAmbiguousTargets,
        LiveScriptRegistrationFailures,
        bDependencyLayoutValid ? TEXT("VALID") : TEXT("INVALID_FAIL_CLOSED"),
        SquadCookedMount::GSCMGenericBlueprintSuperOverlay->NumChunks());

    return true;
#else
    return false;
#endif
}


void FSquadCookedMountModule::OnDiagnosticAsyncLoadPackage(
    FStringView PackageName)
{
#if WITH_EDITOR
    if (bCookCommandletMode || !IsInGameThread() || PackageName.IsEmpty())
    {
        return;
    }

    // UE5.7 broadcasts OnAsyncLoadPackage before creating/enqueuing the async
    // request. Use that pre-request barrier for the same JIT cross-loader
    // preparation as the sync path.
    const FString PackageNameText(PackageName.Len(), PackageName.GetData());
    PrepareCrossLoaderParentsForExternalPackage(
        PackageNameText,
        TEXT("ExternalAsyncLoad"));
#endif
}

void FSquadCookedMountModule::OnDiagnosticSyncLoadPackage(
    const FString& PackageName)
{
#if WITH_EDITOR
    // OnSyncLoadPackage is also before the request enters AsyncLoading2. Keep
    // both entry points on one preflight implementation so child Blueprint
    // loads behave identically for sync and async callers.
    PrepareCrossLoaderParentsForExternalPackage(
        PackageName,
        TEXT("ExternalSyncLoad"));

    if (SquadCookedMount::IsTargetedProblemPackage(PackageName))
    {
        DiagnoseProblemZenPackage(PackageName);
    }

    if (!SquadCookedMount::IsVerboseSCMDiagnosticsEnabled())
    {
        return;
    }

    bool bExternal = false;
    for (const FString& Root : MountedCookedLongRoots)
    {
        if (PackageName.StartsWith(Root, ESearchCase::IgnoreCase))
        {
            bExternal = true;
            break;
        }
    }

    if (!bExternal || DiagnosticLoggedMaterialPackages.Contains(PackageName))
    {
        return;
    }

    const FName PackageFName(*PackageName);
    const FPackageId PackageId = FPackageId::FromName(PackageFName);
    if (!PackageId.IsValid())
    {
        return;
    }

    FPackageStore& PackageStore = FPackageStore::Get();
    FPackageStoreReadScope ReadScope(PackageStore);
    FPackageStoreEntry Entry;
    const EPackageStoreEntryStatus Status =
        PackageStore.GetPackageStoreEntry(PackageId, PackageFName, Entry);

    // Material resources that depend on shared shader code carry shader-map
    // hashes in the package-store entry. Log only those packages so the
    // diagnostic remains focused even for large external mods.
    if (Status != EPackageStoreEntryStatus::Ok || Entry.ShaderMapHashes.IsEmpty())
    {
        return;
    }

    DiagnosticLoggedMaterialPackages.Add(PackageName);
    FString ShaderHashList;
    const int32 ShaderHashLogCount = FMath::Min(Entry.ShaderMapHashes.Num(), 8);
    for (int32 ShaderHashIndex = 0; ShaderHashIndex < ShaderHashLogCount; ++ShaderHashIndex)
    {
        if (!ShaderHashList.IsEmpty())
        {
            ShaderHashList += TEXT(",");
        }
        ShaderHashList += Entry.ShaderMapHashes[ShaderHashIndex].ToString();
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_DIAG MATERIAL_PRELOAD | package='%s' | id=0x%016llX | status=%s | loader=%s(%d) | imports=%d | shaderMaps=%d | hashes=[%s]"),
        *PackageName,
        static_cast<unsigned long long>(PackageId.Value()),
        SquadCookedMount::DiagPackageStoreStatusToString(Status),
        SquadCookedMount::DiagPackageLoaderToString(Entry.LoaderType),
        static_cast<int32>(Entry.LoaderType),
        Entry.ImportedPackageIds.Num(),
        Entry.ShaderMapHashes.Num(),
        *ShaderHashList);
#endif
}

void FSquadCookedMountModule::OnDiagnosticEndLoadPackage(
    const FEndLoadPackageContext& Context)
{
#if WITH_EDITOR
    // A1 memory-lifetime fix: AsyncLoading2's LinkerLoad path detaches the
    // completed async package from FLinkerLoad but does not flush the legacy
    // FAsyncArchive precache. In editor builds that cache can retain at least
    // one 1 MiB read block per linker and was measured at multiple GiB.
    //
    // Keep this deliberately narrower than ResetLoaders/DetachLoader:
    // FlushCache() only releases the underlying archive cache and preserves
    // the linker/import/export identity required by the live UFunction bridge.
    struct FAsyncLinkerCacheFlushContextStats
    {
        int32 Considered = 0;
        int32 Flushed = 0;
        int32 NoLinker = 0;
        int32 NotAsyncArchive = 0;
        int32 AsyncRootStillAttached = 0;
        int32 DestroyingLoader = 0;
        int32 PendingObjects = 0;
        int32 OwnerThreadMismatch = 0;
        double FlushSeconds = 0.0;
    } FlushStats;

    static uint64 TotalFlushContexts = 0;
    static uint64 TotalFlushedPackages = 0;
    static uint64 TotalOwnerThreadMismatches = 0;
    static double TotalFlushSeconds = 0.0;

    const bool bRunAsyncLinkerCacheCleanup =
        !bCookCommandletMode && !Context.bSynchronous;
    const uint32 CurrentThreadId = FPlatformTLS::GetCurrentThreadId();

    for (UPackage* LoadedPackage : Context.LoadedPackages)
    {
        if (!LoadedPackage)
        {
            continue;
        }

        const FString PackageName = LoadedPackage->GetName();

        // v6.8.10: repair proven failed stock UFunction null-super bytecode at
        // the natural completion point of the stock package itself. UE5.7
        // broadcasts OnEndLoadPackage after marking LoadedPackages end-loaded.
        // External packages are rejected inside the repair scanner.
        SquadCookedMount::RepairStockUFunctionsForEndLoadedPackage(LoadedPackage);

        if (SquadCookedMount::IsTargetedProblemPackage(PackageName))
        {
            DiagnoseLoadedProblemPackage(LoadedPackage);
        }

        if (SquadCookedMount::IsVerboseSCMDiagnosticsEnabled())
        {
            bool bExternal = false;
            for (const FString& Root : MountedCookedLongRoots)
            {
                if (PackageName.StartsWith(Root, ESearchCase::IgnoreCase))
                {
                    bExternal = true;
                    break;
                }
            }
            if (bExternal)
            {
                DiagnoseLoadedExternalMaterials(LoadedPackage);
            }
        }

        if (!bRunAsyncLinkerCacheCleanup)
        {
            continue;
        }

        ++FlushStats.Considered;
        FLinkerLoad* Linker = LoadedPackage->GetLinker();
        if (!Linker)
        {
            ++FlushStats.NoLinker;
            continue;
        }

        // GetAsyncLoader() is non-null only for the legacy FAsyncArchive whose
        // STAT_FAsyncArchiveMem footprint A1 targets. Do not touch text,
        // generic-file, or future LinkerLoad archive implementations here.
        if (!Linker->GetAsyncLoader())
        {
            ++FlushStats.NotAsyncArchive;
            continue;
        }

        if (Linker->AsyncRoot != nullptr)
        {
            ++FlushStats.AsyncRootStillAttached;
            continue;
        }
        if (Linker->IsDestroyingLoader())
        {
            ++FlushStats.DestroyingLoader;
            continue;
        }

        const bool bOwnerThreadMismatch =
            Linker->GetOwnerThreadId() != static_cast<int32>(CurrentThreadId);

        // AsyncLoading2 protects LinkerLoad serialization with this same mutex.
        // Recheck mutable conditions under the lock before flushing. The package
        // is already in OnEndLoadPackage, so pending exports are skipped rather
        // than forced to completion by this memory-lifetime fix.
        UE::TUniqueLock LinkerLock(Linker->Mutex);
        if (Linker->AsyncRoot != nullptr)
        {
            ++FlushStats.AsyncRootStillAttached;
            continue;
        }
        if (Linker->IsDestroyingLoader())
        {
            ++FlushStats.DestroyingLoader;
            continue;
        }
        if (!Linker->GetAsyncLoader())
        {
            ++FlushStats.NotAsyncArchive;
            continue;
        }
        if (Linker->HasAnyObjectsPendingLoad())
        {
            ++FlushStats.PendingObjects;
            continue;
        }

        if (bOwnerThreadMismatch)
        {
            ++FlushStats.OwnerThreadMismatch;
        }

        const double FlushStartSeconds = FPlatformTime::Seconds();
        Linker->FlushCache();
        FlushStats.FlushSeconds += FPlatformTime::Seconds() - FlushStartSeconds;
        ++FlushStats.Flushed;
    }

    if (bRunAsyncLinkerCacheCleanup && FlushStats.Considered > 0)
    {
        ++TotalFlushContexts;
        const uint64 PreviousFlushedPackages = TotalFlushedPackages;
        TotalFlushedPackages += static_cast<uint64>(FlushStats.Flushed);
        TotalOwnerThreadMismatches +=
            static_cast<uint64>(FlushStats.OwnerThreadMismatch);
        TotalFlushSeconds += FlushStats.FlushSeconds;

        const bool bCrossedReportBoundary =
            (PreviousFlushedPackages / 256) != (TotalFlushedPackages / 256);
        const bool bSlowContext = FlushStats.FlushSeconds >= 0.010;
        const bool bReportNormally =
            FlushStats.Flushed > 0 &&
            (TotalFlushedPackages <= 16 || bCrossedReportBoundary || bSlowContext);

        if (bReportNormally || SquadCookedMount::IsVerboseSCMDiagnosticsEnabled())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_FIX ASYNC_LINKER_CACHE_FLUSH | context=%llu | packages=%d | flushed=%d | noLinker=%d | notAsyncArchive=%d | asyncRootAttached=%d | destroying=%d | pendingObjects=%d | ownerThreadMismatch=%d | contextMs=%.3f | totalFlushed=%llu | totalOwnerThreadMismatch=%llu | totalMs=%.3f"),
                static_cast<unsigned long long>(TotalFlushContexts),
                FlushStats.Considered,
                FlushStats.Flushed,
                FlushStats.NoLinker,
                FlushStats.NotAsyncArchive,
                FlushStats.AsyncRootStillAttached,
                FlushStats.DestroyingLoader,
                FlushStats.PendingObjects,
                FlushStats.OwnerThreadMismatch,
                FlushStats.FlushSeconds * 1000.0,
                static_cast<unsigned long long>(TotalFlushedPackages),
                static_cast<unsigned long long>(TotalOwnerThreadMismatches),
                TotalFlushSeconds * 1000.0);
        }
    }
#endif
}

void FSquadCookedMountModule::DiagnoseProblemZenPackage(
    const FString& PackageName)
{
#if WITH_EDITOR
    if (DiagnosticDumpedProblemPackages.Contains(PackageName))
    {
        return;
    }

    bool bExternal = false;
    for (const FString& Root : MountedCookedLongRoots)
    {
        if (PackageName.StartsWith(Root, ESearchCase::IgnoreCase))
        {
            bExternal = true;
            break;
        }
    }
    if (!bExternal || MountedPakPaths.IsEmpty())
    {
        return;
    }

    const FName TargetName(*PackageName);
    const FPackageId TargetId = FPackageId::FromName(TargetName);

    TArray<uint8> PackageData;
    FString SourceUtoc;
    FString Error;
    if (!SquadCookedMount::ReadDiagnosticPackageData(
            MountedPakPaths,
            TargetId,
            PackageData,
            SourceUtoc,
            Error))
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_DIAG BP_HEADER_READ_FAIL | package='%s' | id=0x%016llX | error='%s'"),
            *PackageName,
            static_cast<unsigned long long>(TargetId.Value()),
            *Error);
        return;
    }

    SquadCookedMount::FDiagnosticZenHeaderView Header;
    if (!SquadCookedMount::ParseDiagnosticZenHeader(
            PackageData,
            Header,
            Error))
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_DIAG BP_HEADER_PARSE_FAIL | package='%s' | source='%s' | error='%s'"),
            *PackageName,
            *SourceUtoc,
            *Error);
        return;
    }

    FPackageStore& PackageStore = FPackageStore::Get();
    FPackageStoreReadScope ReadScope(PackageStore);
    FPackageStoreEntry TargetEntry;
    const EPackageStoreEntryStatus TargetStatus =
        PackageStore.GetPackageStoreEntry(TargetId, TargetName, TargetEntry);

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_DIAG BP_HEADER | package='%s' | source='%s' | bytes=%d | status=%s | loader=%s(%d) | packageImports=%d | importedNames=%d | importMap=%d | publicHashes=%d | exports=%d"),
        *PackageName,
        *SourceUtoc,
        PackageData.Num(),
        SquadCookedMount::DiagPackageStoreStatusToString(TargetStatus),
        SquadCookedMount::DiagPackageLoaderToString(TargetEntry.LoaderType),
        static_cast<int32>(TargetEntry.LoaderType),
        TargetEntry.ImportedPackageIds.Num(),
        Header.ImportedPackageNames.Num(),
        Header.ImportMap.Num(),
        Header.ImportedPublicExportHashes.Num(),
        Header.ExportMap.Num());

    static const TCHAR* BrokenExportNames[] =
    {
        TEXT("bCan Place Marker"),
        TEXT("bCanRemoveMapMarkerNew"),
        TEXT("OnAltFireWeaponOverride"),
        TEXT("OnFireWeaponOverride"),
        TEXT("ReceiveBeginPlay"),
        TEXT("ReceiveTick"),
        TEXT("UserConstructionScript"),
        TEXT("BlueprintOnFire"),
        TEXT("BlueprintOnZoom"),
        TEXT("OnImpact"),
        TEXT("Server Die"),
        TEXT("Control Drone UI"),
        TEXT("OnServerValidatedItemPlacement"),
        TEXT("DrivetrainComponentDestroyed"),
        TEXT("DrivetrainComponentRepaired"),
        TEXT("Attach CROWS"),
        TEXT("Attach m240"),
        TEXT("NavmeshComponent"),
        TEXT("VehicleArmorTarget"),
        TEXT("VehicleComponentTarget"),
        TEXT("EmergencyRecoveryComponent")
    };

    int32 MatchedBrokenExports = 0;
    for (int32 ExportIndex = 0; ExportIndex < Header.ExportMap.Num(); ++ExportIndex)
    {
        const FExportMapEntry& Export = Header.ExportMap[ExportIndex];
        const FName ExportName = Header.NameMap.GetName(Export.ObjectName);
        const FString ExportNameText = ExportName.ToString();

        bool bInteresting = false;
        for (const TCHAR* BrokenName : BrokenExportNames)
        {
            if (ExportNameText.Equals(BrokenName, ESearchCase::IgnoreCase))
            {
                bInteresting = true;
                break;
            }
        }
        if (!bInteresting)
        {
            continue;
        }

        ++MatchedBrokenExports;
        const FPackageObjectIndex SuperIndex = Export.SuperIndex;
        SquadCookedMount::AuditZenDependencyBundleForPackageImport(
            Header,
            PackageName,
            ExportNameText,
            ExportIndex,
            TEXT("SuperIndex"),
            SuperIndex);
        SquadCookedMount::AuditZenDependencyBundleForPackageImport(
            Header,
            PackageName,
            ExportNameText,
            ExportIndex,
            TEXT("TemplateIndex"),
            Export.TemplateIndex);
        if (!SuperIndex.IsPackageImport())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_DIAG BP_SUPER_IMPORT | package='%s' | export='%s' | exportIndex=%d | superKind=%s | superValue=0x%llX"),
                *PackageName,
                *ExportNameText,
                ExportIndex,
                SuperIndex.IsNull() ? TEXT("Null") :
                    (SuperIndex.IsExport() ? TEXT("Export") :
                    (SuperIndex.IsScriptImport() ? TEXT("ScriptImport") : TEXT("Other"))),
                static_cast<unsigned long long>(SuperIndex.Value()));
            continue;
        }

        const FPackageImportReference ImportRef = SuperIndex.ToPackageImportRef();
        const uint32 ImportedPackageIndex = ImportRef.GetImportedPackageIndex();
        const uint32 PublicHashIndex = ImportRef.GetImportedPublicExportHashIndex();

        const bool bPackageIndexValid =
            ImportedPackageIndex < static_cast<uint32>(TargetEntry.ImportedPackageIds.Num());
        const bool bHashIndexValid =
            PublicHashIndex < static_cast<uint32>(Header.ImportedPublicExportHashes.Num());

        const FPackageId ImportedPackageId = bPackageIndexValid
            ? TargetEntry.ImportedPackageIds[ImportedPackageIndex]
            : FPackageId();
        const uint64 PublicExportHash = bHashIndexValid
            ? Header.ImportedPublicExportHashes[PublicHashIndex]
            : 0;
        FName ImportedPackageName =
            Header.ImportedPackageNames.IsValidIndex(ImportedPackageIndex)
                ? Header.ImportedPackageNames[ImportedPackageIndex]
                : NAME_None;
#if WITH_PACKAGEID_NAME_MAP
        if (ImportedPackageName.IsNone() && ImportedPackageId.IsValid())
        {
            ImportedPackageName = ImportedPackageId.GetName();
        }
#endif

        FPackageStoreEntry ImportedStoreEntry;
        EPackageStoreEntryStatus ImportedStatus = EPackageStoreEntryStatus::Missing;
        if (bPackageIndexValid)
        {
            ImportedStatus = PackageStore.GetPackageStoreEntry(
                ImportedPackageId,
                ImportedPackageName,
                ImportedStoreEntry);
        }

        UPackage* ImportedPackage = nullptr;
        FLinkerLoad* ImportedLinker = nullptr;
        if (!ImportedPackageName.IsNone())
        {
            ImportedPackage = FindPackage(
                nullptr,
                *ImportedPackageName.ToString());
            if (ImportedPackage)
            {
                ImportedLinker = ImportedPackage->GetLinker();
            }
        }

        int32 LinkerHashMatches = 0;
        FString FirstMatchPath;
        UObject* FirstMatchObject = nullptr;
        bool bFirstMatchLoadFailed = false;
        bool bFirstMatchFiltered = false;
        if (ImportedLinker && PublicExportHash != 0)
        {
            for (int32 LinkerExportIndex = 0;
                 LinkerExportIndex < ImportedLinker->ExportMap.Num();
                 ++LinkerExportIndex)
            {
                FString RelativePath;
                const uint64 CandidateHash =
                    SquadCookedMount::ComputeLinkerLoadExportHash(
                        ImportedLinker,
                        LinkerExportIndex,
                        RelativePath);
                if (CandidateHash != PublicExportHash)
                {
                    continue;
                }

                ++LinkerHashMatches;
                if (FirstMatchPath.IsEmpty())
                {
                    const FObjectExport& LinkerExport =
                        ImportedLinker->ExportMap[LinkerExportIndex];
                    FirstMatchPath = RelativePath;
                    FirstMatchObject = LinkerExport.Object;
                    bFirstMatchLoadFailed = LinkerExport.bExportLoadFailed;
                    bFirstMatchFiltered = LinkerExport.bWasFiltered;
                }
            }
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_DIAG BP_SUPER_IMPORT | package='%s' | export='%s' | exportIndex=%d | superValue=0x%llX | importedPackageIndex=%u/%d | publicHashIndex=%u/%d | importedId=0x%016llX | importedName='%s' | publicHash=0x%016llX | store=%s/%s(%d) | packageLoaded=%s | linker=%s | preloadedBeforeZen=%s | linkerExports=%d | hashMatches=%d | firstMatch='%s' | firstObject='%s' | firstObjectReady=%s | loadFailed=%s | filtered=%s"),
            *PackageName,
            *ExportNameText,
            ExportIndex,
            static_cast<unsigned long long>(SuperIndex.Value()),
            ImportedPackageIndex,
            TargetEntry.ImportedPackageIds.Num(),
            PublicHashIndex,
            Header.ImportedPublicExportHashes.Num(),
            static_cast<unsigned long long>(ImportedPackageId.Value()),
            ImportedPackageName.IsNone() ? TEXT("<none>") : *ImportedPackageName.ToString(),
            static_cast<unsigned long long>(PublicExportHash),
            SquadCookedMount::DiagPackageStoreStatusToString(ImportedStatus),
            SquadCookedMount::DiagPackageLoaderToString(ImportedStoreEntry.LoaderType),
            static_cast<int32>(ImportedStoreEntry.LoaderType),
            SquadCookedMount::BoolText(ImportedPackage != nullptr),
            SquadCookedMount::BoolText(ImportedLinker != nullptr),
            SquadCookedMount::BoolText(CookPreloadedLinkerPackageIds.Contains(ImportedPackageId)),
            ImportedLinker ? ImportedLinker->ExportMap.Num() : 0,
            LinkerHashMatches,
            FirstMatchPath.IsEmpty() ? TEXT("<none>") : *FirstMatchPath,
            FirstMatchObject ? *FirstMatchObject->GetPathName() : TEXT("<null>"),
            SquadCookedMount::BoolText(
                FirstMatchObject &&
                FirstMatchObject->HasAllFlags(RF_WasLoaded | RF_LoadCompleted)),
            SquadCookedMount::BoolText(bFirstMatchLoadFailed),
            SquadCookedMount::BoolText(bFirstMatchFiltered));
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_DIAG BP_HEADER_DONE | package='%s' | matchedKnownBrokenExports=%d"),
        *PackageName,
        MatchedBrokenExports);

    DiagnosticDumpedProblemPackages.Add(PackageName);
#endif
}

void FSquadCookedMountModule::DiagnoseLoadedProblemPackage(UPackage* Package)
{
#if WITH_EDITOR
    if (!Package)
    {
        return;
    }

    const FString PackageName = Package->GetName();
    if (DiagnosticDumpedLoadedProblemPackages.Contains(PackageName))
    {
        return;
    }
    DiagnosticDumpedLoadedProblemPackages.Add(PackageName);

    TArray<UObject*> Objects;
    GetObjectsWithPackage(Package, Objects, true);

    static const TCHAR* Members[] =
    {
        TEXT("bCan Place Marker"),
        TEXT("bCanRemoveMapMarkerNew"),
        TEXT("OnAltFireWeaponOverride"),
        TEXT("OnFireWeaponOverride"),
        TEXT("ReceiveBeginPlay"),
        TEXT("BlueprintOnFire")
    };

    int32 ClassCount = 0;
    for (UObject* Object : Objects)
    {
        UClass* Class = Cast<UClass>(Object);
        if (!Class)
        {
            continue;
        }

        ++ClassCount;
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_DIAG BP_CLASS | package='%s' | class='%s' | super='%s' | linkerIndex=%d | flags=0x%08X"),
            *PackageName,
            *Class->GetPathName(),
            Class->GetSuperClass() ? *Class->GetSuperClass()->GetPathName() : TEXT("<null>"),
            Class->GetLinkerIndex(),
            static_cast<uint32>(Class->GetFlags()));

        for (const TCHAR* MemberName : Members)
        {
            const FName MemberFName(MemberName);
            UFunction* Function = Class->FindFunctionByName(MemberFName);
            FProperty* Property = FindFProperty<FProperty>(Class, MemberFName);

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_DIAG BP_MEMBER | class='%s' | member='%s' | state=%s | function='%s' | functionOwner='%s' | property='%s' | propertyOwner='%s'"),
                *Class->GetPathName(),
                MemberName,
                (Function || Property) ? TEXT("FOUND") : TEXT("MISSING"),
                Function ? *Function->GetPathName() : TEXT("<none>"),
                Function && Function->GetOuter() ? *Function->GetOuter()->GetPathName() : TEXT("<none>"),
                Property ? *Property->GetName() : TEXT("<none>"),
                Property && Property->GetOwnerStruct() ? *Property->GetOwnerStruct()->GetPathName() : TEXT("<none>"));
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_DIAG BP_CLASS_DONE | package='%s' | objects=%d | classes=%d"),
        *PackageName,
        Objects.Num(),
        ClassCount);

    // Repeat the raw Zen-import decode after the package has completed. At
    // this point any LinkerLoad base package pulled in by the Zen dependency
    // should exist, so hash matching can distinguish "package not loaded"
    // from "public export hash absent/mismatched".
    DiagnosticDumpedProblemPackages.Remove(PackageName);
    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_DIAG BP_POSTLOAD_RECHECK | package='%s'"),
        *PackageName);
    DiagnoseProblemZenPackage(PackageName);
#endif
}

void FSquadCookedMountModule::DiagnoseLoadedExternalMaterials(UPackage* Package)
{
#if WITH_EDITOR
    if (!Package)
    {
        return;
    }

    const FString PackageName = Package->GetName();
    if (DiagnosticDumpedLoadedMaterialPackages.Contains(PackageName))
    {
        return;
    }

    TArray<UObject*> Objects;
    GetObjectsWithPackage(Package, Objects, true);

    int32 Materials = 0;
    int32 Logged = 0;
    for (UObject* Object : Objects)
    {
        UMaterialInterface* Material = Cast<UMaterialInterface>(Object);
        if (!Material)
        {
            continue;
        }

        ++Materials;
        if (Logged < 8)
        {
            ++Logged;
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_DIAG MATERIAL_LOADED | package='%s' | object='%s' | class='%s' | linkerIndex=%d | flags=0x%08X"),
                *PackageName,
                *Material->GetPathName(),
                *Material->GetClass()->GetPathName(),
                Material->GetLinkerIndex(),
                static_cast<uint32>(Material->GetFlags()));
        }
    }

    if (Materials <= 0)
    {
        return;
    }

    DiagnosticDumpedLoadedMaterialPackages.Add(PackageName);

    const FName PackageFName(*PackageName);
    const FPackageId PackageId = FPackageId::FromName(PackageFName);
    FPackageStoreEntry Entry;
    EPackageStoreEntryStatus StoreStatus = EPackageStoreEntryStatus::Missing;
    if (PackageId.IsValid())
    {
        FPackageStore& PackageStore = FPackageStore::Get();
        FPackageStoreReadScope ReadScope(PackageStore);
        StoreStatus = PackageStore.GetPackageStoreEntry(PackageId, PackageFName, Entry);
    }

    FString ShaderHashList;
    const int32 ShaderHashLogCount = FMath::Min(Entry.ShaderMapHashes.Num(), 8);
    for (int32 ShaderHashIndex = 0; ShaderHashIndex < ShaderHashLogCount; ++ShaderHashIndex)
    {
        if (!ShaderHashList.IsEmpty())
        {
            ShaderHashList += TEXT(",");
        }
        ShaderHashList += Entry.ShaderMapHashes[ShaderHashIndex].ToString();
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_DIAG MATERIAL_LOADED_DONE | package='%s' | id=0x%016llX | materialInterfaces=%d | packageLinker=%s | store=%s/%s(%d) | imports=%d | shaderMaps=%d | hashes=[%s]"),
        *PackageName,
        static_cast<unsigned long long>(PackageId.Value()),
        Materials,
        SquadCookedMount::BoolText(Package->GetLinker() != nullptr),
        SquadCookedMount::DiagPackageStoreStatusToString(StoreStatus),
        SquadCookedMount::DiagPackageLoaderToString(Entry.LoaderType),
        static_cast<int32>(Entry.LoaderType),
        Entry.ImportedPackageIds.Num(),
        Entry.ShaderMapHashes.Num(),
        *ShaderHashList);
#endif
}

void FSquadCookedMountModule::StartBlueprintActionAutoRefresh()
{
#if WITH_EDITOR
    if (!bAutoRefreshBlueprintActions ||
        BlueprintActionAutoRefreshTickerHandle.IsValid())
    {
        return;
    }

    // From this point onward ShutdownModule may safely tear down the transient
    // action objects created by the editor-only refresh path. Cook commandlets
    // never enter this function, so they never touch the Blueprint action DB.
    bBlueprintActionSubsystemStarted = true;

    // Register classes that may already have loaded while the cooked containers
    // and AssetRegistry were being mounted.
    SquadCookedMount::RefreshChangedCookedBlueprintActions(false);

    BlueprintActionAutoRefreshTickerHandle =
        FTSTicker::GetCoreTicker().AddTicker(
            FTickerDelegate::CreateRaw(
                this,
                &FSquadCookedMountModule::TickBlueprintActionAutoRefresh),
            BlueprintActionAutoRefreshInterval);

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Blueprint action auto-refresh ENABLED | interval=%.2fs"),
        BlueprintActionAutoRefreshInterval);
#endif
}

void FSquadCookedMountModule::StopBlueprintActionAutoRefresh()
{
#if WITH_EDITOR
    if (BlueprintActionAutoRefreshTickerHandle.IsValid())
    {
        FTSTicker::GetCoreTicker().RemoveTicker(
            BlueprintActionAutoRefreshTickerHandle);
        BlueprintActionAutoRefreshTickerHandle.Reset();
    }
#endif
}

bool FSquadCookedMountModule::TickBlueprintActionAutoRefresh(float /*DeltaTime*/)
{
#if WITH_EDITOR
    SquadCookedMount::RefreshChangedCookedBlueprintActions(false);
#endif
    return true;
}


void FSquadCookedMountModule::StartupModule()
{
#if WITH_EDITOR
    PluginVersionName = TEXT("<descriptor-unavailable>");
    const TSharedPtr<IPlugin> SelfPlugin =
        IPluginManager::Get().FindPlugin(TEXT("SquadCookedMount"));
    if (SelfPlugin.IsValid())
    {
        const FString& DescriptorVersionName = SelfPlugin->GetDescriptor().VersionName;
        if (!DescriptorVersionName.IsEmpty())
        {
            PluginVersionName = DescriptorVersionName;
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SquadCookedMount %s starting (plugin-only external Zen + generic editor UFunction SuperIndex memory overlay + exact-hash template/component registration bridge + targeted editor reindex + one-shot lifecycle guard + fail-closed NullRHI external-material error gate)."),
        *PluginVersionName);

    if (FParse::Param(FCommandLine::Get(), TEXT("UsePaks")))
    {
        UE_LOG(LogSquadCookedMount, Error, TEXT("-UsePaks is present. Remove it."));
        return;
    }

    FString RunCommandletName;
    FParse::Value(FCommandLine::Get(), TEXT("run="), RunCommandletName);
    bCookCommandletMode =
        IsRunningCommandlet() &&
        RunCommandletName.Equals(TEXT("Cook"), ESearchCase::IgnoreCase);

    // Blueprint action proxies/spawners are rooted UObjects. Module shutdown can
    // happen after CoreUObject has already torn down GUObjectArray, which makes
    // even constructing FObjectKey(UClass*) unsafe. Clean those editor-only
    // objects at OnEnginePreExit while CoreUObject is still alive.
    EnginePreExitHandle =
        FCoreDelegates::OnEnginePreExit.AddRaw(
            this,
            &FSquadCookedMountModule::HandleEnginePreExit);

    StartTargetedDiagnostics();

    FString ConfigFilter;
    if (GConfig &&
        GConfig->GetString(
            TEXT("SquadCookedMount"),
            TEXT("PakNameFilter"),
            ConfigFilter,
            GEngineIni))
    {
        PakNameFilter = ConfigFilter;
    }

    if (GConfig)
    {
        GConfig->GetBool(
            TEXT("SquadCookedMount"),
            TEXT("AutoRefreshBlueprintActions"),
            bAutoRefreshBlueprintActions,
            GGameIni);

        GConfig->GetFloat(
            TEXT("SquadCookedMount"),
            TEXT("BlueprintActionRefreshInterval"),
            BlueprintActionAutoRefreshInterval,
            GGameIni);
    }

    BlueprintActionAutoRefreshInterval =
        FMath::Max(0.10f, BlueprintActionAutoRefreshInterval);

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("PakNameFilter='%s' (empty = mount all PAKs)"),
        *PakNameFilter
    );

    IFileManager::Get().MakeDirectory(
        *FPaths::Combine(FPaths::ProjectDir(), SquadCookedMount::CookedModsFolderName),
        true);

    LooseShaderDir =
        SquadCookedMount::NormalizeDirectory(
            FPaths::Combine(
                FPaths::ProjectSavedDir(),
                TEXT("SquadCookedMount/ShaderCache")));

    FString ConfiguredLooseShaderDir;
    if (GConfig && GConfig->GetString(
            TEXT("SquadCookedMount"),
            TEXT("LooseShaderDir"),
            ConfiguredLooseShaderDir,
            GGameIni) &&
        !ConfiguredLooseShaderDir.IsEmpty())
    {
        LooseShaderDir =
            SquadCookedMount::NormalizeDirectory(
                FPaths::ConvertRelativePathToFull(ConfiguredLooseShaderDir));
    }

    FString ConfiguredBaseGamePaksDir;
    if (GConfig && GConfig->GetString(
            TEXT("SquadCookedMount"),
            TEXT("BaseGamePaksDir"),
            ConfiguredBaseGamePaksDir,
            GGameIni) &&
        !ConfiguredBaseGamePaksDir.IsEmpty())
    {
        BaseGamePaksDir =
            SquadCookedMount::NormalizeDirectory(
                FPaths::ConvertRelativePathToFull(
                    ConfiguredBaseGamePaksDir));
    }

    IFileManager::Get().MakeDirectory(*LooseShaderDir, true);

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("ShaderCacheDir='%s' | Configured BaseGamePaksDir='%s'"),
        *LooseShaderDir,
        *BaseGamePaksDir
    );


    if (bCookCommandletMode)
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK commandlet mode: passive metadata only before AssetManager; external Zen plus the generic LinkerLoad public-export reindex bridge activate behind the AssetManager barrier on the first subsequent synchronous package load."));

        // v0.3.17m/n and the s-experimental three-package probe both proved
        // that exposing any retail-Zen ownership before SquadAssetManager
        // completion is unsafe.  v0.3.17u keeps retail /Game entirely
        // on the stock LinkerLoad path and defers all external-Zen mutation behind
        // the public UAssetManager completed-initial-scan barrier.
        FAssetRegistryModule& AssetRegistryModule =
            FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));
        IAssetRegistry& Registry = AssetRegistryModule.Get();

        if (Registry.IsLoadingAssets())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK base bridge: AssetRegistry still loading; preparing passive registry/IoStore metadata only. No retail Zen is exposed before AssetManager completion."));
        }
        else
        {
            bCookInitialAssetRegistryCallbackReached = true;
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK base bridge: AssetRegistry is already complete during PostEngineInit; preparing passive metadata only before the AssetManager completion barrier."));
        }

        const ECookRegistryPhaseResult StartupRegistryPhaseResult =
            PrepareCookCommandletRegistryPhase();
        if (StartupRegistryPhaseResult == ECookRegistryPhaseResult::Pending)
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK base bridge: passive registry preparation is pending during PostEngineInit; retrying after the live AssetRegistry advances."));
        }
        else if (StartupRegistryPhaseResult == ECookRegistryPhaseResult::Failed)
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("COOK base bridge: passive registry preparation failed during PostEngineInit; OnCommandletPreMain will retry before the AssetManager barrier."));
        }

        CookCommandletPreMainHandle =
            FCoreDelegates::OnCommandletPreMain.AddRaw(
                this,
                &FSquadCookedMountModule::OnCookCommandletPreMain);

        CookCommandletPostMainHandle =
            FCoreDelegates::OnCommandletPostMain.AddRaw(
                this,
                &FSquadCookedMountModule::OnCookCommandletPostMain);

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge: registered OnCommandletPreMain AssetManager barrier + OnCommandletPostMain fail-closed NullRHI material gate."));

        // Keep the AssetRegistry completion callback as diagnostics only. It
        // never mutates IoStore/FPackageStore and never arms activation; the
        // stronger AssetManager initial-scan barrier owns that transition.
        if (Registry.IsLoadingAssets())
        {
            AssetRegistryFilesLoadedHandle =
                Registry.OnFilesLoaded().AddRaw(
                    this,
                    &FSquadCookedMountModule::OnInitialAssetRegistryFilesLoaded);
        }

        return;
    }

    if (!PreBeginPIEHandle.IsValid())
    {
        PreBeginPIEHandle =
            FEditorDelegates::PreBeginPIE.AddRaw(
                this,
                &FSquadCookedMountModule::OnPreBeginPIE);
    }

    // v0.3.15a proved that exposing cooked packages before their shader
    // libraries are open is unsafe: startup loading can deserialize cooked
    // materials immediately, permanently leaving invalid ShaderMaps until a
    // package reload. Therefore the EARLY mount is allowed only after the
    // runtime ShaderCodeLibrary is already enabled and the shared SquadGame
    // loose library has been opened.
    bool bCanEarlyMountCookedPackages = false;

    if (FShaderCodeLibrary::IsEnabled())
    {
        // Normally these archives are cache hits. Rebuild from retail Squad
        // only when needed, then open the shared project library BEFORE any
        // cooked mod package becomes visible through FPackageStore.
        EnsureBaseShaderArchives();
        OpenLooseShaderLibrariesForRoot(TEXT("SquadGame"));

        bCanEarlyMountCookedPackages =
            OpenedShaderLibraries.Contains(TEXT("SquadGame"));

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("EARLY shader gate | ShaderCodeLibrary=ENABLED | SquadGame=%s | totalShaders=%u"),
            bCanEarlyMountCookedPackages ? TEXT("OPEN") : TEXT("MISSING"),
            FShaderCodeLibrary::GetShaderCount());
    }
    else
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("EARLY shader gate: ShaderCodeLibrary is not enabled yet; cooked packages will NOT be exposed early."));
    }

    if (bCanEarlyMountCookedPackages && PreparePakPlatformFileEarly())
    {
        MountAllCookedMods(/*bPostProcess=*/false);

        // Build the generic import index while container metadata is already
        // available, but do NOT mutate any vanilla LinkerLoad package here.
        // SquadAssetManager/initial AssetRegistry startup is sensitive to even
        // narrow changes in package-loader state. The first actual reindex is
        // deliberately delayed until the normal post-scan barrier below.
        BuildCrossLoaderImportIndex();
    }
    else
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("EARLY cooked package mount disabled for this run; using the stable delayed mount path. Startup hard references may remain unresolved, but cooked materials will not deserialize before shader libraries are ready."));
    }

    BeginDelayedMount();
#endif
}

void FSquadCookedMountModule::HandleEnginePreExit()
{
#if WITH_EDITOR
    if (bEnginePreExitCleanupDone)
    {
        return;
    }

    bEnginePreExitCleanupDone = true;

    if (PreBeginPIEHandle.IsValid())
    {
        FEditorDelegates::PreBeginPIE.Remove(PreBeginPIEHandle);
        PreBeginPIEHandle.Reset();
    }

    if (GEditor && BlueprintCompiledHandle.IsValid())
    {
        GEditor->OnBlueprintCompiled().Remove(BlueprintCompiledHandle);
        BlueprintCompiledHandle.Reset();
    }

    StopTargetedDiagnostics();

    if (bBlueprintActionSubsystemStarted)
    {
        StopBlueprintActionAutoRefresh();
        SquadCookedMount::CleanupCookedActionProxies();
        bBlueprintActionSubsystemStarted = false;

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Pre-exit Blueprint cleanup complete while CoreUObject is still alive."));
    }
#endif
}

void FSquadCookedMountModule::ShutdownModule()
{
#if WITH_EDITOR
    StopTargetedDiagnostics();

    if (PreBeginPIEHandle.IsValid())
    {
        FEditorDelegates::PreBeginPIE.Remove(PreBeginPIEHandle);
        PreBeginPIEHandle.Reset();
    }

    if (EnginePreExitHandle.IsValid())
    {
        FCoreDelegates::OnEnginePreExit.Remove(EnginePreExitHandle);
        EnginePreExitHandle.Reset();
    }

    // Dynamic plugin unload can happen without an engine pre-exit broadcast. In
    // that case CoreUObject is still live and it is correct to clean the rooted
    // action objects here. During process shutdown HandleEnginePreExit() has
    // already done this work, so ShutdownModule never touches those UObjects.
    if (!bEnginePreExitCleanupDone && bBlueprintActionSubsystemStarted)
    {
        StopBlueprintActionAutoRefresh();
        SquadCookedMount::CleanupCookedActionProxies();
        bBlueprintActionSubsystemStarted = false;
    }

    if (CookCommandletPreMainHandle.IsValid())
    {
        FCoreDelegates::OnCommandletPreMain.Remove(CookCommandletPreMainHandle);
        CookCommandletPreMainHandle.Reset();
    }

    if (CookCommandletPostMainHandle.IsValid())
    {
        FCoreDelegates::OnCommandletPostMain.Remove(CookCommandletPostMainHandle);
        CookCommandletPostMainHandle.Reset();
    }

    if (CookSyncLoadPackageHandle.IsValid())
    {
        FCoreDelegates::OnSyncLoadPackage.Remove(CookSyncLoadPackageHandle);
        CookSyncLoadPackageHandle.Reset();
    }

    if (FModuleManager::Get().IsModuleLoaded(TEXT("AssetRegistry")) &&
        AssetRegistryFilesLoadedHandle.IsValid())
    {
        FAssetRegistryModule& AssetRegistryModule =
            FModuleManager::GetModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));

        AssetRegistryModule.Get().OnFilesLoaded().Remove(AssetRegistryFilesLoadedHandle);
        AssetRegistryFilesLoadedHandle.Reset();
    }

    for (const FString& LibraryName : OpenedShaderLibraries)
    {
        FShaderCodeLibrary::CloseLibrary(LibraryName);
    }
    OpenedShaderLibraries.Reset();

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SquadCookedMount %s shutdown complete."),
        *PluginVersionName
    );

    // Do not delete PakPlatformFile and do not manually remove it from the
    // wrapper chain. It was created through FPlatformFileManager::GetPlatformFile.
    PakPlatformFile = nullptr;
    PreviousTopmostPlatformFile = nullptr;
#endif
}

void FSquadCookedMountModule::BeginDelayedMount()
{
    FAssetRegistryModule& AssetRegistryModule =
        FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));

    IAssetRegistry& Registry = AssetRegistryModule.Get();

    if (!Registry.IsLoadingAssets())
    {
        OnInitialAssetRegistryFilesLoaded();
        return;
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Waiting for initial AssetRegistry scan to finish before modifying the platform-file chain.")
    );

    AssetRegistryFilesLoadedHandle =
        Registry.OnFilesLoaded().AddRaw(
            this,
            &FSquadCookedMountModule::OnInitialAssetRegistryFilesLoaded);
}

void FSquadCookedMountModule::OnInitialAssetRegistryFilesLoaded()
{
    if (bCookCommandletMode)
    {
        TGuardValue<bool> AssetRegistryCallbackGuard(
            bCookInsideAssetRegistryFilesLoadedCallback,
            true);

        if (FModuleManager::Get().IsModuleLoaded(TEXT("AssetRegistry")) &&
            AssetRegistryFilesLoadedHandle.IsValid())
        {
            FAssetRegistryModule& AssetRegistryModule =
                FModuleManager::GetModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));
            AssetRegistryModule.Get().OnFilesLoaded().Remove(AssetRegistryFilesLoadedHandle);
            AssetRegistryFilesLoadedHandle.Reset();
        }

        bCookInitialAssetRegistryCallbackReached = true;

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge: initial AssetRegistry callback reached; no IoStore/PackageStore mutation inside this callback."));

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge: AssetRegistry callback finished plugin work untouched; waiting for AssetManager completed-initial-scan barrier before arming Zen activation."));
        return;
    }

    if (bMountStarted)
    {
        return;
    }

    bMountStarted = true;

    if (FModuleManager::Get().IsModuleLoaded(TEXT("AssetRegistry")) &&
        AssetRegistryFilesLoadedHandle.IsValid())
    {
        FAssetRegistryModule& AssetRegistryModule =
            FModuleManager::GetModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));

        AssetRegistryModule.Get().OnFilesLoaded().Remove(AssetRegistryFilesLoadedHandle);
        AssetRegistryFilesLoadedHandle.Reset();
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Initial AssetRegistry scan finished. Promoting the already-prepared PakPlatformFile and running cooked post-processing.")
    );

    if (!PromotePakPlatformFile())
    {
        return;
    }

    // Containers should already be mounted from StartupModule. This second
    // pass deliberately skips re-mounting and performs the work that must wait
    // until the initial AssetRegistry scan is complete: cooked registry merge,
    // shader archive handling, primary assets, diagnostics, etc.
    MountAllCookedMods(/*bPostProcess=*/true);
    if (BuildCrossLoaderImportIndex())
    {
        // Build only the stock LinkerLoad public-export bridge that is safe to
        // establish after the initial AssetRegistry scan. External package-data
        // is not mutated here; UFunction ScriptImports are created JIT when an
        // external package is actually requested.
        RefreshLoadedLinkerPackagesForZenImports(
            nullptr,
            TEXT("EditorPostAssetRegistry"),
            /*bForceSyncRefresh=*/true);

        const int32 PreArmedUFunctionOverlays =
            PreArmExternalUFunctionSuperOverlays();

        if (GEditor && !BlueprintCompiledHandle.IsValid())
        {
            BlueprintCompiledHandle =
                GEditor->OnBlueprintCompiled().AddRaw(
                    this,
                    &FSquadCookedMountModule::RefreshLiveUFunctionScriptBindingsAfterBlueprintCompile);
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_FIX JIT_UFUNCTION_BRIDGE_READY | startupExternalPackageMutation=EXACT_UFUNCTION_PREARM | prearmedOverlays=%d | startupSurrogateUFunctions=NO | asyncAndSyncPreflight=ARMED | dependencyLoadsCovered=YES"),
            PreArmedUFunctionOverlays);

        bCrossLoaderInitialEditorRefreshDone = true;
    }
    StartBlueprintActionAutoRefresh();
}


FSquadCookedMountModule::ECookRegistryPhaseResult
FSquadCookedMountModule::PrepareCookCommandletRegistryPhase()
{
    if (bCookRegistryPhaseReady)
    {
        return ECookRegistryPhaseResult::Ready;
    }

    FAssetRegistryState ExternalState;
    if (!CollectCookedModAssetRegistriesPassive(ExternalState))
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK passive registry phase: no cooked external AssetRegistry could be read directly from CookedMods PAKs."));
        return ECookRegistryPhaseResult::Failed;
    }

    FString BasedOnReleaseVersion;
    FParse::Value(FCommandLine::Get(), TEXT("BasedOnReleaseVersion="), BasedOnReleaseVersion);
    if (!BasedOnReleaseVersion.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK passive registry phase: BasedOnReleaseVersion='%s' | externalPackages=%d"),
            *BasedOnReleaseVersion,
            ExternalState.GetNumPackages());
    }

    FString DlcName;
    if (!FParse::Value(FCommandLine::Get(), TEXT("DLCName="), DlcName) || DlcName.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK passive registry phase: -DLCName is missing; cannot build the targeted dependency gate."));
        return ECookRegistryPhaseResult::Failed;
    }

    DlcName.TrimStartAndEndInline();
    CookDlcLongRoot = FString::Printf(TEXT("/%s/"), *DlcName);

    const ECookTargetSeedResult SeedResult =
        PrepareCookTargetedDependencySeeds(ExternalState);

    if (SeedResult == ECookTargetSeedResult::Pending)
    {
        return ECookRegistryPhaseResult::Pending;
    }

    if (SeedResult == ECookTargetSeedResult::Failed)
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK passive registry phase: failed to derive targeted external seeds/dependency trigger graph."));
        return ECookRegistryPhaseResult::Failed;
    }

    if (SeedResult == ECookTargetSeedResult::NoExternalDependencies)
    {
        // A DLC is allowed to have no dependency on any cooked external mod.
        // In that case there is nothing for the PackageStore bridge to expose,
        // so do not create a synthetic based-on-release registry and do not arm
        // the first-sync-load activation gate. Normal cooker behavior remains
        // completely untouched for this DLC.
        bCookExternalBridgeRequired = false;
        CookExternalLongRoots.Reset();
        bCookRegistryPhaseReady = true;

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK passive registry phase READY | dlcRoot='%s' | externalBridge=NOT_REQUIRED | reason=NO_EXTERNAL_DEPENDENCIES | retailZen=NO"),
            *CookDlcLongRoot);
        return ECookRegistryPhaseResult::Ready;
    }

    bCookExternalBridgeRequired = true;

    // Only after a real current-DLC -> external cooked dependency has been
    // proven do we create the temporary based-on-release registry. This keeps
    // unrelated DLC cooks side-effect free with respect to external content.
    if (!bSyntheticBasedOnReleaseReady && !PrepareSyntheticBasedOnRelease(ExternalState))
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK passive registry phase: failed to prepare synthetic based-on-release registry before cooker session setup."));
        return ECookRegistryPhaseResult::Failed;
    }

    bCookRegistryPhaseReady = true;

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK passive registry phase READY | dlcRoot='%s' | externalBridge=REQUIRED | retailZen=NO | external activation still deferred"),
        *CookDlcLongRoot);
    return ECookRegistryPhaseResult::Ready;
}


FSquadCookedMountModule::ECookTargetSeedResult
FSquadCookedMountModule::PrepareCookTargetedDependencySeeds(
    const FAssetRegistryState& ExternalState)
{
    CookExternalLongRoots.Reset();
    CookTargetExternalSeedPackageIds.Reset();
    CookEarlyTriggerPackageNames.Reset();

    if (CookDlcLongRoot.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK targeted seeds: DLC root is empty."));
        return ECookTargetSeedResult::Failed;
    }

    TSet<FName> ExternalPackageNames;
    ExternalState.EnumerateAllAssets(
        [this, &ExternalPackageNames](const FAssetData& AssetData)
        {
            if (AssetData.PackageName.IsNone())
            {
                return;
            }

            ExternalPackageNames.Add(AssetData.PackageName);

            const FString PackageName = AssetData.PackageName.ToString();
            if (!PackageName.StartsWith(TEXT("/")))
            {
                return;
            }

            const int32 SecondSlash = PackageName.Find(
                TEXT("/"),
                ESearchCase::CaseSensitive,
                ESearchDir::FromStart,
                1);
            if (SecondSlash == INDEX_NONE)
            {
                return;
            }

            const FString Root = PackageName.Left(SecondSlash + 1);
            if (Root.Equals(TEXT("/Game/"), ESearchCase::IgnoreCase) ||
                Root.Equals(TEXT("/Engine/"), ESearchCase::IgnoreCase) ||
                Root.Equals(TEXT("/Script/"), ESearchCase::IgnoreCase) ||
                Root.Equals(CookDlcLongRoot, ESearchCase::IgnoreCase))
            {
                return;
            }

            CookExternalLongRoots.Add(Root);
        });

    if (ExternalPackageNames.IsEmpty() || CookExternalLongRoots.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK targeted seeds: external registry has no discoverable cooked package root."));
        return ECookTargetSeedResult::Failed;
    }

    FAssetRegistryModule& AssetRegistryModule =
        FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));
    IAssetRegistry& Registry = AssetRegistryModule.Get();

    FARFilter DlcFilter;
    FString DlcPath = CookDlcLongRoot;
    DlcPath.RemoveFromEnd(TEXT("/"));
    DlcFilter.PackagePaths.Add(FName(*DlcPath));
    DlcFilter.bRecursivePaths = true;

    TArray<FName> DlcPackages;
    TSet<FName> SeenDlcPackages;
    Registry.EnumerateAssets(
        DlcFilter,
        [&DlcPackages, &SeenDlcPackages](const FAssetData& AssetData)
        {
            if (!AssetData.PackageName.IsNone() && !SeenDlcPackages.Contains(AssetData.PackageName))
            {
                SeenDlcPackages.Add(AssetData.PackageName);
                DlcPackages.Add(AssetData.PackageName);
            }
            return true;
        });

    if (DlcPackages.IsEmpty())
    {
        // During PostEngineInit / early commandlet startup the live registry can
        // still be scanning the DLC. Do not conclude that the DLC has no
        // external references until that scan is complete.
        if (Registry.IsLoadingAssets())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK targeted seeds PENDING | live AssetRegistry still loading; DLC root '%s' has no packages yet."),
                *CookDlcLongRoot);
            return ECookTargetSeedResult::Pending;
        }

        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK targeted seeds: live AssetRegistry has no packages under DLC root '%s'."),
            *CookDlcLongRoot);
        return ECookTargetSeedResult::Failed;
    }

    TArray<FName> DlcWorkList = DlcPackages;
    TSet<FName> VisitedDlc;

    for (int32 WorkIndex = 0; WorkIndex < DlcWorkList.Num(); ++WorkIndex)
    {
        const FName PackageName = DlcWorkList[WorkIndex];
        if (PackageName.IsNone() || VisitedDlc.Contains(PackageName))
        {
            continue;
        }
        VisitedDlc.Add(PackageName);

        TArray<FName> Dependencies;
        Registry.GetDependencies(
            PackageName,
            Dependencies,
            UE::AssetRegistry::EDependencyCategory::Package);

        for (const FName Dependency : Dependencies)
        {
            if (Dependency.IsNone())
            {
                continue;
            }

            const FString DependencyText = Dependency.ToString();
            if (DependencyText.StartsWith(CookDlcLongRoot, ESearchCase::IgnoreCase))
            {
                if (!VisitedDlc.Contains(Dependency))
                {
                    DlcWorkList.Add(Dependency);
                }
                continue;
            }

            if (ExternalPackageNames.Contains(Dependency))
            {
                const FPackageId PackageId = FPackageId::FromName(Dependency);
                if (PackageId.IsValid() && !CookTargetExternalSeedPackageIds.Contains(PackageId))
                {
                    CookTargetExternalSeedPackageIds.Add(PackageId);
                }
            }
        }
    }

    if (CookTargetExternalSeedPackageIds.IsEmpty())
    {
        // Zero external seeds is a normal DLC configuration. While the registry
        // is still loading it is only provisional, so retry behind the existing
        // AssetManager completion barrier. Once loading is complete, this is a
        // definitive no-op: this DLC has no dependency into the discovered
        // external cooked package set and the bridge must stay completely off.
        if (Registry.IsLoadingAssets())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK targeted seeds PENDING | DLC '%s' currently has no external dependency while AssetRegistry is still loading."),
                *CookDlcLongRoot);
            return ECookTargetSeedResult::Pending;
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK targeted seeds NONE | DLC '%s' has no AssetRegistry package dependency into discovered external cooked roots; bridge is not required."),
            *CookDlcLongRoot);
        return ECookTargetSeedResult::NoExternalDependencies;
    }

    // AssetRegistry.bin from a runtime/cooked mod is not guaranteed to carry
    // package dependency edges. Once the current DLC has identified direct
    // external seed packages, build their transitive activation closure from
    // IoStore ContainerHeader ImportedPackages instead; those are the exact
    // package IDs consumed by the Zen loader.
    if (!BuildCookEarlyTriggerFromIoStoreMetadata(ExternalState))
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK targeted seeds: failed to build IoStore metadata trigger closure."));
        return ECookTargetSeedResult::Failed;
    }

    FString RootList;
    for (const FString& Root : CookExternalLongRoots)
    {
        if (!RootList.IsEmpty())
        {
            RootList += TEXT(",");
        }
        RootList += Root;
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK targeted seeds READY | dlcPackages=%d | externalRoots=[%s] | externalSeeds=%d | earlyTriggerPackages=%d"),
        DlcPackages.Num(),
        *RootList,
        CookTargetExternalSeedPackageIds.Num(),
        CookEarlyTriggerPackageNames.Num());

    return ECookTargetSeedResult::HasExternalDependencies;
}


void FSquadCookedMountModule::OnCookCommandletPreMain()
{
    if (!bCookCommandletMode || bCookBridgeReady)
    {
        return;
    }

    bool bAssetRegistryStillLoading = false;
    if (FModuleManager::Get().IsModuleLoaded(TEXT("AssetRegistry")))
    {
        FAssetRegistryModule& AssetRegistryModule =
            FModuleManager::GetModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));
        bAssetRegistryStillLoading = AssetRegistryModule.Get().IsLoadingAssets();
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK base bridge: OnCommandletPreMain reached | AssetRegistryLoading=%s | evaluating targeted external dependency gate."),
        bAssetRegistryStillLoading ? TEXT("YES") : TEXT("NO"));

    const ECookRegistryPhaseResult RegistryPhaseResult =
        PrepareCookCommandletRegistryPhase();

    if (RegistryPhaseResult == ECookRegistryPhaseResult::Pending)
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge: OnCommandletPreMain passive metadata is still pending; AssetManager completion will make the final dependency decision."));
    }
    else if (RegistryPhaseResult == ECookRegistryPhaseResult::Failed)
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: OnCommandletPreMain passive metadata retry failed; AssetManager barrier will retry metadata at completion."));
    }
    else if (!bCookExternalBridgeRequired)
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge NOT_REQUIRED | current DLC has no external cooked dependencies; AssetManager activation barrier and selective Zen gate are skipped."));
        return;
    }

    if (!bCookAssetManagerCompletionHookRegistered)
    {
        bCookAssetManagerCompletionHookRegistered = true;
        UAssetManager::CallOrRegister_OnCompletedInitialScan(
            FSimpleMulticastDelegate::FDelegate::CreateRaw(
                this,
                &FSquadCookedMountModule::OnCookAssetManagerInitialScanCompleted));

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge: AssetManager completed-initial-scan barrier registered."));
    }
}

void FSquadCookedMountModule::OnCookCommandletPostMain()
{
#if WITH_EDITOR
    if (!bCookCommandletMode ||
        !FParse::Param(FCommandLine::Get(), TEXT("nullrhi")) ||
        FApp::CanEverRender() ||
        !GWarn)
    {
        return;
    }

    // UE 5.7 intentionally disables FShaderCodeLibrary when
    // FApp::CanEverRender()==false (the normal -nullrhi cook path). Loading an
    // already-cooked external UMaterial in that process can therefore emit
    // "invalid ShaderMap" even though the package's shader library is valid in
    // the real rendering editor/game. The source DLC is not being asked to
    // recook that external shader map; the object is loaded only as a cooked
    // dependency. Do not let those NullRHI-only diagnostics turn a successful
    // cook into ExitCode=1.
    //
    // This is deliberately fail-closed. We remove history entries only when:
    //   * the command line explicitly contains -nullrhi;
    //   * every invalid-ShaderMap Error captured in this commandlet has an
    //     exact UObject serialization context;
    //   * every such object is a /Script/Engine.Material or
    //     /Script/Engine.MaterialInstanceConstant under one of the external
    //     cooked roots discovered by this plugin; and
    //   * the number of matching GWarn error-history entries is exactly the
    //     number captured. Any ambiguity leaves GWarn untouched.
    if (!SquadCookedMount::GSCMMaterialErrorCapture)
    {
        return;
    }

    TArray<SquadCookedMount::FSCMMaterialErrorCapture::FInvalidShaderMapRecord> Records;
    SquadCookedMount::GSCMMaterialErrorCapture->SnapshotRecords(Records);

    // ShaderMap diagnostics can be emitted while serializing either an actual
    // UMaterial or a cooked UMaterialInstanceConstant. Keep the eligible class
    // list exact: this gate must never become a generic material-error bypass.
    auto IsExactCookedMaterialClass = [](const FString& ClassPath)
    {
        return ClassPath.Equals(TEXT("/Script/Engine.Material"), ESearchCase::CaseSensitive) ||
            ClassPath.Equals(TEXT("/Script/Engine.MaterialInstanceConstant"), ESearchCase::CaseSensitive);
    };

    int32 CapturedErrorCount = 0;
    int32 ExternalMaterialErrorCount = 0;
    TSet<FString> ExternalMaterialPackages;

    for (const SquadCookedMount::FSCMMaterialErrorCapture::FInvalidShaderMapRecord& Record : Records)
    {
        if (Record.Verbosity != ELogVerbosity::Error)
        {
            continue;
        }

        ++CapturedErrorCount;

        bool bExternalRoot = false;
        for (const FString& Root : CookExternalLongRoots)
        {
            if (!Root.IsEmpty() &&
                Record.PackagePath.StartsWith(Root, ESearchCase::IgnoreCase))
            {
                bExternalRoot = true;
                break;
            }
        }

        const bool bExactMaterialClass = IsExactCookedMaterialClass(Record.ClassPath);

        if (bExternalRoot && bExactMaterialClass &&
            !Record.ObjectPath.Equals(TEXT("<none>"), ESearchCase::CaseSensitive))
        {
            ++ExternalMaterialErrorCount;
            ExternalMaterialPackages.Add(Record.PackagePath);
        }
    }

    if (CapturedErrorCount == 0)
    {
        if (SquadCookedMount::IsVerboseSCMDiagnosticsEnabled())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_FIX MATERIAL_NULLRHI_GATE | no invalid-ShaderMap Error records captured; GWarn unchanged."));
        }
        return;
    }

    if (CookExternalLongRoots.IsEmpty() ||
        ExternalMaterialErrorCount != CapturedErrorCount)
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_FIX MATERIAL_NULLRHI_GATE FAIL_CLOSED | captured=%d | exactExternalMaterials=%d | externalRoots=%d | GWarn unchanged."),
            CapturedErrorCount,
            ExternalMaterialErrorCount,
            CookExternalLongRoots.Num());
        int32 ReportedUnmatched = 0;
        for (const auto& Record : Records)
        {
            if (Record.Verbosity != ELogVerbosity::Error)
            {
                continue;
            }
            bool bInExternalRoot = false;
            for (const FString& Root : CookExternalLongRoots)
            {
                bInExternalRoot |= !Root.IsEmpty() &&
                    Record.PackagePath.StartsWith(Root, ESearchCase::IgnoreCase);
            }
            if (bInExternalRoot &&
                IsExactCookedMaterialClass(Record.ClassPath) &&
                Record.ObjectPath != TEXT("<none>"))
            {
                continue;
            }
            if (ReportedUnmatched++ < 16)
            {
                UE_LOG(LogSquadCookedMount, Warning,
                    TEXT("SCM_FIX MATERIAL_UNMATCHED | object='%s' | package='%s' | class='%s' | verbosity=%d | mutation=NO"),
                    *Record.ObjectPath, *Record.PackagePath, *Record.ClassPath,
                    static_cast<int32>(Record.Verbosity));
            }
        }
        return;
    }

    TArray<FString> Errors;
    TArray<FString> Warnings;
    GWarn->GetErrors(Errors);
    GWarn->GetWarnings(Warnings);

    auto IsInvalidShaderMapHistoryLine = [](const FString& Line)
    {
        return Line.Contains(TEXT("invalid ShaderMap"), ESearchCase::IgnoreCase) &&
               Line.Contains(TEXT("LogMaterial"), ESearchCase::IgnoreCase);
    };

    int32 MatchingHistoryErrors = 0;
    for (const FString& Error : Errors)
    {
        if (IsInvalidShaderMapHistoryLine(Error))
        {
            ++MatchingHistoryErrors;
        }
    }

    if (MatchingHistoryErrors != CapturedErrorCount)
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_FIX MATERIAL_NULLRHI_GATE FAIL_CLOSED | captured=%d | GWarnInvalidShaderMapErrors=%d | totalErrors=%d | GWarn unchanged."),
            CapturedErrorCount,
            MatchingHistoryErrors,
            Errors.Num());
        return;
    }

    // Rebuild FFeedbackContext history with all original warnings and every
    // non-target error. FEngineLoop checks GWarn->GetNumErrors() only after
    // OnCommandletPostMain, so this removes exactly the NullRHI-only external
    // material diagnostics from the exit-code decision while preserving every
    // unrelated error as an Error.
    const bool bOldTreatWarningsAsErrors = GWarn->TreatWarningsAsErrors;
    const bool bOldTreatErrorsAsWarnings = GWarn->TreatErrorsAsWarnings;
    GWarn->TreatWarningsAsErrors = false;
    GWarn->TreatErrorsAsWarnings = false;

    GWarn->ClearWarningsAndErrors();

    for (const FString& Warning : Warnings)
    {
        GWarn->Serialize(*Warning, ELogVerbosity::Warning, NAME_None);
    }

    int32 RemovedErrors = 0;
    for (const FString& Error : Errors)
    {
        if (IsInvalidShaderMapHistoryLine(Error))
        {
            ++RemovedErrors;
            continue;
        }

        GWarn->Serialize(*Error, ELogVerbosity::Error, NAME_None);
    }

    GWarn->TreatWarningsAsErrors = bOldTreatWarningsAsErrors;
    GWarn->TreatErrorsAsWarnings = bOldTreatErrorsAsWarnings;

    FString PackageList;
    for (const FString& Package : ExternalMaterialPackages)
    {
        if (!PackageList.IsEmpty())
        {
            PackageList += TEXT(",");
        }
        PackageList += Package;
    }

    if (SquadCookedMount::IsVerboseSCMDiagnosticsEnabled())
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_FIX MATERIAL_NULLRHI_GATE APPLIED | removedErrors=%d | externalMaterialPackages=%d | remainingErrors=%d | warningsPreserved=%d | packages=[%s]"),
            RemovedErrors,
            ExternalMaterialPackages.Num(),
            GWarn->GetNumErrors(),
            GWarn->GetNumWarnings(),
            *PackageList);
    }
    else
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_FIX MATERIAL_NULLRHI_GATE APPLIED | removedErrors=%d | externalMaterialPackages=%d | remainingErrors=%d"),
            RemovedErrors,
            ExternalMaterialPackages.Num(),
            GWarn->GetNumErrors());
    }
#endif
}

void FSquadCookedMountModule::OnCookAssetManagerInitialScanCompleted()
{
    if (!bCookCommandletMode || bCookBridgeReady)
    {
        return;
    }

    bCookAssetManagerInitialScanCompleted = true;

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK base bridge: AssetManager initial scan COMPLETE | arCallback=%s | bridgeReady=%s | evaluating whether selective Zen activation is required."),
        bCookInitialAssetRegistryCallbackReached ? TEXT("YES") : TEXT("NO"),
        bCookBridgeReady ? TEXT("YES") : TEXT("NO"));

    const ECookRegistryPhaseResult RegistryPhaseResult =
        PrepareCookCommandletRegistryPhase();

    if (RegistryPhaseResult == ECookRegistryPhaseResult::Pending)
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: dependency decision is still pending after AssetManager initial scan completion; first-load gate not armed."));
        return;
    }

    if (RegistryPhaseResult == ECookRegistryPhaseResult::Failed)
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: passive registry/IoStore metadata unavailable at AssetManager completion; first-load gate not armed."));
        return;
    }

    if (!bCookExternalBridgeRequired)
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge NOT_REQUIRED | AssetManager initial scan complete and current DLC has no external cooked dependencies; no PackageStore/IoStore mutation will be performed."));
        return;
    }

    ArmCookBridgeOnPostAssetManagerSyncLoad();
}

void FSquadCookedMountModule::ArmCookBridgeOnPostAssetManagerSyncLoad()
{
    if (!bCookCommandletMode || !bCookRegistryPhaseReady || !bCookExternalBridgeRequired ||
        bCookBridgeReady || !bCookAssetManagerInitialScanCompleted ||
        bCookBridgeFailedTerminal || CookSyncLoadPackageHandle.IsValid())
    {
        return;
    }

    CookSyncLoadPackageHandle =
        FCoreDelegates::OnSyncLoadPackage.AddRaw(
            this,
            &FSquadCookedMountModule::OnCookSyncLoadPackage);

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK base bridge: armed one-shot FIRST sync-load gate after AssetManager initial-scan completion; next non-script LoadPackage will activate selective Zen before loader selection."));
}

void FSquadCookedMountModule::OnCookSyncLoadPackage(const FString& PackageName)
{
    if (!bCookCommandletMode || !bCookExternalBridgeRequired || bCookBridgeReady ||
        bCookBridgeFailedTerminal || bCookBridgeActivationInProgress ||
        !bCookAssetManagerInitialScanCompleted ||
        CookDlcLongRoot.IsEmpty())
    {
        return;
    }

    FString LongPackageName = PackageName;
    if (!LongPackageName.StartsWith(TEXT("/")))
    {
        FString ConvertedLongName;
        if (FPackageName::TryConvertFilenameToLongPackageName(PackageName, ConvertedLongName))
        {
            LongPackageName = MoveTemp(ConvertedLongName);
        }
    }

    // Script package traffic does not represent a cooker content load and does
    // not benefit from the PackageStore bridge. The first real content package
    // after the AssetManager barrier is the activation point, regardless of
    // whether it belongs to the external closure. This avoids v0.3.17l waiting
    // until the first DLC package after the cooker has already loaded base data.
    if (LongPackageName.StartsWith(TEXT("/Script/"), ESearchCase::IgnoreCase))
    {
        return;
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK base bridge: FIRST post-AssetManager sync-load gate fired for '%s'; activating selective Zen BEFORE this LoadPackage continues."),
        *LongPackageName);

    bCookBridgeActivationInProgress = true;
    const bool bActivated = SetupCookCommandletBridge();
    bCookBridgeActivationInProgress = false;

    if (bActivated)
    {
        if (CookSyncLoadPackageHandle.IsValid())
        {
            FCoreDelegates::OnSyncLoadPackage.Remove(CookSyncLoadPackageHandle);
            CookSyncLoadPackageHandle.Reset();
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge: POST-ASSETMANAGER activation READY; selective Zen is active before '%s' loader selection."),
            *LongPackageName);
    }
    else
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: activation FAILED_TERMINAL at '%s'; no retry will be attempted."),
            *LongPackageName);
        bCookBridgeFailedTerminal = true;
        if (CookSyncLoadPackageHandle.IsValid())
        {
            FCoreDelegates::OnSyncLoadPackage.Remove(CookSyncLoadPackageHandle);
            CookSyncLoadPackageHandle.Reset();
        }
    }
}

namespace
{
    struct FCookZenOwnedEntry
    {
        TArray<FPackageId> ImportedPackageIds;
        TArray<FSHAHash> ShaderMapHashes;
#if WITH_EDITOR
        TArray<FPackageId> OptionalSegmentImportedPackageIds;
        bool bHasOptionalSegment = false;
#endif
    };

    struct FCookZenRedirect
    {
        FName SourcePackageName;
        FPackageId TargetPackageId;
    };

    /**
     * Immutable, cook-only PackageStore overlay.
     *
     * It intentionally returns Missing for every package outside the selected
     * cooked dependency closure. This lets the stock UE5.7 editor LinkerLoad
     * backend continue to serve the current source DLC and unrelated SDK assets,
     * while the external cooked graph is forced through the already-mounted
     * IoDispatcher containers as Zen packages.
     */
    class FCookSelectiveZenPackageStoreBackend final : public IPackageStoreBackend
    {
    public:
        FCookSelectiveZenPackageStoreBackend(
            TMap<FPackageId, FCookZenOwnedEntry>&& InEntries,
            TMap<FPackageId, FCookZenRedirect>&& InRedirects)
            : Entries(MoveTemp(InEntries))
            , Redirects(MoveTemp(InRedirects))
        {
        }

        virtual EPackageLoader GetSupportedLoaders() override
        {
            return EPackageLoader::Zen;
        }

        virtual void OnMounted(TSharedRef<const FPackageStoreBackendContext>) override
        {
        }

        virtual void BeginRead() override
        {
        }

        virtual void EndRead() override
        {
        }

        virtual EPackageStoreEntryStatus GetPackageStoreEntry(
            FPackageId PackageId,
            FName PackageName,
            FPackageStoreEntry& OutPackageStoreEntry) override
        {
            const FCookZenOwnedEntry* Entry = Entries.Find(PackageId);
            if (!Entry)
            {
                return EPackageStoreEntryStatus::Missing;
            }

            OutPackageStoreEntry = {};
            OutPackageStoreEntry.LoaderType = EPackageLoader::Zen;
            OutPackageStoreEntry.ImportedPackageIds = MakeArrayView(Entry->ImportedPackageIds);
            OutPackageStoreEntry.ShaderMapHashes = MakeArrayView(Entry->ShaderMapHashes);
#if WITH_EDITOR
            OutPackageStoreEntry.OptionalSegmentImportedPackageIds =
                MakeArrayView(Entry->OptionalSegmentImportedPackageIds);
            OutPackageStoreEntry.bHasOptionalSegment = Entry->bHasOptionalSegment;
            OutPackageStoreEntry.bReplaceChunkWithOptional = false;
#endif
            return EPackageStoreEntryStatus::Ok;
        }

        virtual bool GetPackageRedirectInfo(
            FPackageId PackageId,
            FName& OutSourcePackageName,
            FPackageId& OutRedirectedToPackageId) override
        {
            const FCookZenRedirect* Redirect = Redirects.Find(PackageId);
            if (!Redirect)
            {
                return false;
            }

            OutSourcePackageName = Redirect->SourcePackageName;
            OutRedirectedToPackageId = Redirect->TargetPackageId;
            return true;
        }

        int32 NumEntries() const
        {
            return Entries.Num();
        }

        int32 NumRedirects() const
        {
            return Redirects.Num();
        }

    private:
        // Immutable after FPackageStore::Mount. Concurrent reads are safe and
        // every ArrayView returned above remains valid for the backend lifetime.
        TMap<FPackageId, FCookZenOwnedEntry> Entries;
        TMap<FPackageId, FCookZenRedirect> Redirects;
    };

    struct FCookZenContainerSource
    {
        FString UtocPath;
        int32 Order = 0;
        uint32 Sequence = 0;
    };

    struct FCookZenSnapshotEntry
    {
        FCookZenOwnedEntry Data;
        FString SourceUtoc;
        int32 Order = 0;
        uint32 Sequence = 0;
    };

    static FString PakPathToContainerBase(const FString& PakPath)
    {
        FString BasePath = FPaths::ChangeExtension(PakPath, TEXT(""));
        if (BasePath.EndsWith(TEXT(".")))
        {
            BasePath.LeftChopInline(1);
        }
        return BasePath;
    }

    static int32 GetCookContainerOrderForPak(const FString& PakPath, int32 RequestedOrder)
    {
        int32 Result = RequestedOrder;
        FString Stem = FPaths::GetBaseFilename(PakPath);

        // FPakPlatformFile raises patch paks above their base container. Mirror
        // the conventional _<N>_P naming here so the metadata overlay chooses
        // the same representation as IoDispatcher. _P without an explicit
        // number is treated as the first patch level.
        if (Stem.EndsWith(TEXT("_P"), ESearchCase::IgnoreCase))
        {
            Stem.LeftChopInline(2);
            int32 PatchLevel = 1;
            int32 LastUnderscore = INDEX_NONE;
            if (Stem.FindLastChar(TEXT('_'), LastUnderscore) && LastUnderscore + 1 < Stem.Len())
            {
                const FString NumberText = Stem.Mid(LastUnderscore + 1);
                if (NumberText.IsNumeric())
                {
                    PatchLevel = FCString::Atoi(*NumberText) + 1;
                }
            }
            Result += 100 * FMath::Max(1, PatchLevel);
        }

        return Result;
    }

    static void AddCookContainerSourcesForPak(
        const FString& PakPath,
        int32 RequestedOrder,
        uint32& InOutSequence,
        TArray<FCookZenContainerSource>& OutSources)
    {
        const FString BasePath = PakPathToContainerBase(PakPath);
        const int32 MainOrder = GetCookContainerOrderForPak(PakPath, RequestedOrder);

        const FString MainUtoc = BasePath + TEXT(".utoc");
        if (IFileManager::Get().FileExists(*MainUtoc))
        {
            FCookZenContainerSource& Source = OutSources.AddDefaulted_GetRef();
            Source.UtocPath = MainUtoc;
            Source.Order = MainOrder;
            Source.Sequence = InOutSequence++;
        }

        // UE5.7 mounts the optional segment container with the SAME PakOrder
        // immediately after the main container. FFilePackageStoreBackend then
        // resolves equal-order containers by later mount sequence first. Mirror
        // that exactly: same order, later sequence.
        const FString OptionalUtoc = BasePath + TEXT(".o.utoc");
        if (IFileManager::Get().FileExists(*OptionalUtoc))
        {
            FCookZenContainerSource& Source = OutSources.AddDefaulted_GetRef();
            Source.UtocPath = OptionalUtoc;
            Source.Order = MainOrder;
            Source.Sequence = InOutSequence++;
        }
    }

    static bool ReadCookContainerHeader(
        const FString& UtocPath,
        FIoContainerHeader& OutHeader,
        FString& OutError)
    {
        OutError.Reset();

        FIoStoreReader Reader;
        TMap<FGuid, FAES::FAESKey> DecryptionKeys;
        const FIoStatus InitStatus = Reader.Initialize(
            SquadCookedMount::RemoveUtocExtension(UtocPath),
            DecryptionKeys);

        if (!InitStatus.IsOk())
        {
            OutError = InitStatus.ToString();
            return false;
        }

        FIoChunkId HeaderChunkId;
        bool bFoundHeader = false;
        Reader.EnumerateChunks(
            [&HeaderChunkId, &bFoundHeader](FIoStoreTocChunkInfo&& Info)
            {
                if (Info.ChunkType == EIoChunkType::ContainerHeader)
                {
                    HeaderChunkId = Info.Id;
                    bFoundHeader = true;
                    return false;
                }
                return true;
            });

        if (!bFoundHeader)
        {
            OutError = TEXT("ContainerHeader chunk is missing");
            return false;
        }

        TIoStatusOr<FIoBuffer> ReadResult =
            Reader.Read(HeaderChunkId, FIoReadOptions());
        if (!ReadResult.IsOk())
        {
            OutError = ReadResult.Status().ToString();
            return false;
        }

        FIoBuffer Buffer = ReadResult.ConsumeValueOrDie();
        if (Buffer.DataSize() == 0 || Buffer.DataSize() > static_cast<uint64>(MAX_int32))
        {
            OutError = TEXT("ContainerHeader chunk has an invalid size");
            return false;
        }

        TArray<uint8> Bytes;
        Bytes.SetNumUninitialized(static_cast<int32>(Buffer.DataSize()));
        FMemory::Memcpy(Bytes.GetData(), Buffer.Data(), Buffer.DataSize());

        FMemoryReader Ar(Bytes, true);
        FIoContainerHeader Header;
        Ar << Header;
        if (Ar.IsError() || Ar.IsCriticalError())
        {
            OutError = TEXT("FIoContainerHeader deserialization failed");
            return false;
        }

        OutHeader = MoveTemp(Header);
        return true;
    }

    static bool CopyCookContainerEntries(
        const FCookZenContainerSource& Source,
        const FIoContainerHeader& Header,
        TMap<FPackageId, FCookZenSnapshotEntry>& InOutEntries,
        TMap<FPackageId, TArray<FPackageId>>& InOutOptionalImports,
        TMap<FPackageId, FCookZenRedirect>& InOutRedirects,
        int32& OutNewEntries)
    {
        OutNewEntries = 0;

        const int64 RequiredStoreBytes =
            static_cast<int64>(Header.PackageIds.Num()) * sizeof(FFilePackageStoreEntry);
        if (Header.StoreEntries.Num() < RequiredStoreBytes)
        {
            return false;
        }

        const FFilePackageStoreEntry* StoreEntries =
            reinterpret_cast<const FFilePackageStoreEntry*>(Header.StoreEntries.GetData());

        for (int32 Index = 0; Index < Header.PackageIds.Num(); ++Index)
        {
            const FPackageId PackageId = Header.PackageIds[Index];
            if (!PackageId.IsValid() || InOutEntries.Contains(PackageId))
            {
                continue;
            }

            const FFilePackageStoreEntry& StoreEntry = StoreEntries[Index];
            FCookZenSnapshotEntry Snapshot;
            Snapshot.SourceUtoc = Source.UtocPath;
            Snapshot.Order = Source.Order;
            Snapshot.Sequence = Source.Sequence;
            Snapshot.Data.ImportedPackageIds.Append(
                StoreEntry.ImportedPackages.begin(),
                StoreEntry.ImportedPackages.Num());
            Snapshot.Data.ShaderMapHashes.Append(
                StoreEntry.ShaderMapHashes.begin(),
                StoreEntry.ShaderMapHashes.Num());

            InOutEntries.Add(PackageId, MoveTemp(Snapshot));
            ++OutNewEntries;
        }

#if WITH_EDITOR
        const int64 RequiredOptionalBytes =
            static_cast<int64>(Header.OptionalSegmentPackageIds.Num()) * sizeof(FFilePackageStoreEntry);
        if (Header.OptionalSegmentStoreEntries.Num() >= RequiredOptionalBytes)
        {
            const FFilePackageStoreEntry* OptionalEntries =
                reinterpret_cast<const FFilePackageStoreEntry*>(Header.OptionalSegmentStoreEntries.GetData());

            for (int32 Index = 0; Index < Header.OptionalSegmentPackageIds.Num(); ++Index)
            {
                const FPackageId PackageId = Header.OptionalSegmentPackageIds[Index];
                if (!PackageId.IsValid() || InOutOptionalImports.Contains(PackageId))
                {
                    continue;
                }

                const FFilePackageStoreEntry& OptionalEntry = OptionalEntries[Index];
                TArray<FPackageId> Imports;
                Imports.Append(
                    OptionalEntry.ImportedPackages.begin(),
                    OptionalEntry.ImportedPackages.Num());
                InOutOptionalImports.Add(PackageId, MoveTemp(Imports));
            }
        }
#endif

        for (const FIoContainerHeaderPackageRedirect& Redirect : Header.PackageRedirects)
        {
            if (!Redirect.SourcePackageId.IsValid() ||
                !Redirect.TargetPackageId.IsValid() ||
                InOutRedirects.Contains(Redirect.SourcePackageId))
            {
                continue;
            }

            const int32 NameIndex = Redirect.SourcePackageName.GetIndex();
            if (!Header.RedirectsNameMap.IsValidIndex(NameIndex))
            {
                continue;
            }

            const FDisplayNameEntryId NameEntry = Header.RedirectsNameMap[NameIndex];
            FCookZenRedirect RedirectData;
            RedirectData.SourcePackageName =
                NameEntry.ToName(Redirect.SourcePackageName.GetNumber());
            RedirectData.TargetPackageId = Redirect.TargetPackageId;
            InOutRedirects.Add(Redirect.SourcePackageId, MoveTemp(RedirectData));
        }

        return true;
    }

    static FAssetRegistrySerializationOptions MakeCookBridgeRegistryOptions()
    {
        FAssetRegistrySerializationOptions Options(
            UE::AssetRegistry::ESerializationTarget::ForDevelopment);
        Options.bSerializeAssetRegistry = true;
        Options.bSerializeDependencies = true;
        Options.bSerializeSearchableNameDependencies = true;
        Options.bSerializeManageDependencies = true;
        Options.bSerializePackageData = true;
        Options.bKeepDevelopmentAssetRegistryTags = true;
        Options.DisableFilters();
        return Options;
    }

    // CookCommandlet copies its command line into a private Params/Switches list
    // before PostEngineInit modules start. Appending -CookAgainstFixedBase to the
    // global FCommandLine here therefore cannot change ECookByTheBookOptions.
    //
    // UE 5.7's based-on-release ingestion has a narrower equivalent escape
    // hatch: when source verification is enabled, PKG_CookGenerated entries are
    // still accepted and receive a synthetic normalized filename without
    // requiring an uncooked package to exist. FConstructPackageData later keeps
    // only PackageName + NormalizedFileName, so this marker is confined to the
    // temporary release registry and is not propagated as cooker package state.
    static int32 MarkSyntheticRegistryAsFixedBaseSurrogate(
        FAssetRegistryState& State)
    {
        const bool bReevaluateUncooked =
            FParse::Param(
                FCommandLine::Get(),
                TEXT("DlcReevaluateUncookedAssets"));

        // EnumerateAllMutableAssets is private in UE 5.7. Use only the public
        // FAssetRegistryState API: copy the affected FAssetData records during
        // const enumeration, then replace them through UpdateAssetData.
        TArray<FAssetData> UpdatedAssets;
        TSet<FName> ChangedPackages;
        State.EnumerateAllAssets(
            [&UpdatedAssets, &ChangedPackages, bReevaluateUncooked](
                const FAssetData& AssetData)
            {
                // Match native DLC reevaluation semantics: zero-flag entries are
                // deliberately omitted by the cooker when this switch is set.
                if (bReevaluateUncooked && AssetData.PackageFlags == 0)
                {
                    return;
                }

                if ((AssetData.PackageFlags & PKG_CookGenerated) == 0)
                {
                    FAssetData Updated = AssetData;
                    Updated.PackageFlags |= PKG_CookGenerated;
                    ChangedPackages.Add(Updated.PackageName);
                    UpdatedAssets.Add(MoveTemp(Updated));
                }
            });

        for (FAssetData& Updated : UpdatedAssets)
        {
            State.UpdateAssetData(MoveTemp(Updated), false);
        }

        return ChangedPackages.Num();
    }

    static bool LoadRegistryFileForCookBridge(
        const FString& Filename,
        FAssetRegistryState& OutState)
    {
        TUniquePtr<FArchive> Reader(IFileManager::Get().CreateFileReader(*Filename));
        if (!Reader)
        {
            return false;
        }

        FAssetRegistryLoadOptions LoadOptions;
        FAssetRegistryVersion::Type Version = FAssetRegistryVersion::LatestVersion;
        if (!OutState.Load(*Reader, LoadOptions, &Version))
        {
            return false;
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge: loaded registry '%s' | assets=%d | packages=%d | version=%d"),
            *Filename,
            OutState.GetNumAssets(),
            OutState.GetNumPackages(),
            static_cast<int32>(Version));
        return true;
    }

    static bool SaveRegistryFileForCookBridge(
        const FString& Filename,
        FAssetRegistryState& State)
    {
        const FString Directory = FPaths::GetPath(Filename);
        IFileManager::Get().MakeDirectory(*Directory, true);

        FAssetRegistrySerializationOptions Options = MakeCookBridgeRegistryOptions();
        FBufferArchive Writer;
        if (!State.Save(Writer, Options))
        {
            return false;
        }

        return FFileHelper::SaveArrayToFile(Writer, *Filename);
    }

    static const TCHAR* PackageStoreStatusToString(EPackageStoreEntryStatus Status)
    {
        switch (Status)
        {
        case EPackageStoreEntryStatus::None: return TEXT("None");
        case EPackageStoreEntryStatus::Missing: return TEXT("Missing");
        case EPackageStoreEntryStatus::NotInstalled: return TEXT("NotInstalled");
        case EPackageStoreEntryStatus::Pending: return TEXT("Pending");
        case EPackageStoreEntryStatus::Ok: return TEXT("Ok");
        default: return TEXT("Unknown");
        }
    }

    static const TCHAR* PackageLoaderToString(EPackageLoader Loader)
    {
        switch (Loader)
        {
        case EPackageLoader::Unknown: return TEXT("Unknown");
        case EPackageLoader::LinkerLoad: return TEXT("LinkerLoad");
        case EPackageLoader::Zen: return TEXT("Zen");
        default: return TEXT("Mixed/Unknown");
        }
    }

    static FString DeriveCompanionLibraryNameFromPakPath(const FString& PakPath)
    {
        const FString Stem = FPaths::GetBaseFilename(PakPath);
        const int32 PakChunkIndex =
            Stem.Find(TEXT("pakchunk"), ESearchCase::IgnoreCase, ESearchDir::FromStart);

        if (PakChunkIndex <= 0)
        {
            return FString();
        }

        return Stem.Left(PakChunkIndex);
    }

    static bool IsLogicalShaderLibraryOpen(
        const TSet<FString>& OpenedLibraries,
        const FString& LogicalRoot)
    {
        if (LogicalRoot.IsEmpty())
        {
            return false;
        }

        if (OpenedLibraries.Contains(LogicalRoot))
        {
            return true;
        }

        for (const FString& Opened : OpenedLibraries)
        {
            if (Opened.StartsWith(LogicalRoot, ESearchCase::IgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}


bool FSquadCookedMountModule::BuildCrossLoaderImportIndex()
{
#if WITH_EDITOR
    if (bCrossLoaderImportIndexReady)
    {
        return true;
    }

    CrossLoaderParentPackageIds.Reset();
    CrossLoaderParentPackageNames.Reset();
    CrossLoaderParentPublicHashes.Reset();
    CrossLoaderParentHashConsumers.Reset();
    CrossLoaderSuperParentPublicHashes.Reset();
    CrossLoaderNonSuperParentPublicHashes.Reset();
    ExternalPackageNameToId.Reset();
    ExternalPackageImportedPackageIds.Reset();
    ExternalPackageSourceUtocs.Reset();
    ExternalPackageCrossLoaderParents.Reset();
    ExternalPackageStockUFunctionSuperParents.Reset();
    EditorSuperOverlayParentHashes.Reset();
    CrossLoaderRefreshAttempts.Reset();
    SquadCookedMount::GSCMExternalPackageIds.Reset();

    if (MountedPakPaths.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_FIX LINKER_REINDEX index: no mounted external paks are available."));
        return false;
    }

    TArray<FCookZenContainerSource> Sources;
    uint32 Sequence = 0;
    for (const FString& PakPath : MountedPakPaths)
    {
        AddCookContainerSourcesForPak(
            PakPath,
            100,
            Sequence,
            Sources);
    }

    Sources.Sort(
        [](const FCookZenContainerSource& A,
           const FCookZenContainerSource& B)
        {
            if (A.Order != B.Order)
            {
                return A.Order > B.Order;
            }
            return A.Sequence > B.Sequence;
        });

    TMap<FPackageId, FCookZenSnapshotEntry> AllEntries;
    TMap<FPackageId, TArray<FPackageId>> OptionalImports;
    TMap<FPackageId, FCookZenRedirect> Redirects;
    int32 ParsedContainers = 0;
    int32 FailedContainers = 0;

    for (const FCookZenContainerSource& Source : Sources)
    {
        FIoContainerHeader ContainerHeader;
        FString Error;
        if (!ReadCookContainerHeader(
                Source.UtocPath,
                ContainerHeader,
                Error))
        {
            ++FailedContainers;
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("SCM_FIX LINKER_REINDEX index: container header read failed | '%s' | %s"),
                *Source.UtocPath,
                *Error);
            continue;
        }

        int32 NewEntries = 0;
        if (!CopyCookContainerEntries(
                Source,
                ContainerHeader,
                AllEntries,
                OptionalImports,
                Redirects,
                NewEntries))
        {
            ++FailedContainers;
            continue;
        }
        ++ParsedContainers;
    }

    if (AllEntries.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_FIX LINKER_REINDEX index: no external package-store entries were reconstructed | parsedContainers=%d failedContainers=%d"),
            ParsedContainers,
            FailedContainers);
        return false;
    }

    TSet<FPackageId> ExternalPackageIds;
    ExternalPackageIds.Reserve(AllEntries.Num());
    for (const TPair<FPackageId, FCookZenSnapshotEntry>& Pair : AllEntries)
    {
        ExternalPackageIds.Add(Pair.Key);
    }
    SquadCookedMount::GSCMExternalPackageIds = ExternalPackageIds;

    // A package whose PackageStore entry imports only other mounted external
    // packages cannot have a mixed Zen -> LinkerLoad object reference. Skip
    // its package header entirely; this keeps the generic scan practical even
    // for 20k+ package mods dominated by textures/meshes.
    TMap<FString, TArray<FPackageId>> PackagesBySourceUtoc;
    int32 CandidateHeaders = 0;
    for (const TPair<FPackageId, FCookZenSnapshotEntry>& Pair : AllEntries)
    {
        bool bHasPotentialCrossLoaderImport = false;
        for (const FPackageId ImportedId : Pair.Value.Data.ImportedPackageIds)
        {
            if (ImportedId.IsValid() && !ExternalPackageIds.Contains(ImportedId))
            {
                bHasPotentialCrossLoaderImport = true;
                break;
            }
        }
        if (bHasPotentialCrossLoaderImport)
        {
            PackagesBySourceUtoc.FindOrAdd(Pair.Value.SourceUtoc).Add(Pair.Key);
            ++CandidateHeaders;
        }
    }

    int32 ScannedHeaders = 0;
    int32 FailedHeaders = 0;
    int32 ObjectImportRefs = 0;
    int32 CrossLoaderObjectRefs = 0;
    int32 PackagesWithCrossLoaderRefs = 0;
    int32 ResolvedParentNames = 0;
    int32 InvalidPackageImportRefs = 0;

    // Record the exact stock LinkerLoad packages used as UFunction supers by
    // each external Zen package. The JIT preflight first-loads only this set;
    // ordinary class/template parents stay under AsyncLoading2 scheduling.
    int32 StockUFunctionSuperEdges = 0;
    TSet<FPackageId> ExternalPackagesWithStockUFunctionSupers;
    const FString FunctionClassPath = UFunction::StaticClass()->GetPathName();
    const FPackageObjectIndex FunctionClassIndex =
        FPackageObjectIndex::FromScriptPath(
            FStringView(*FunctionClassPath, FunctionClassPath.Len()));

    TMap<FGuid, FAES::FAESKey> DecryptionKeys;

    for (TPair<FString, TArray<FPackageId>>& SourcePair : PackagesBySourceUtoc)
    {
        FIoStoreReader Reader;
        const FIoStatus InitStatus = Reader.Initialize(
            SquadCookedMount::RemoveUtocExtension(SourcePair.Key),
            DecryptionKeys);
        if (!InitStatus.IsOk())
        {
            FailedHeaders += SourcePair.Value.Num();
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("SCM_FIX LINKER_REINDEX index: package reader init failed | '%s' | %s"),
                *SourcePair.Key,
                *InitStatus.ToString());
            continue;
        }

        for (const FPackageId ExternalPackageId : SourcePair.Value)
        {
            const FCookZenSnapshotEntry* Snapshot =
                AllEntries.Find(ExternalPackageId);
            if (!Snapshot)
            {
                ++FailedHeaders;
                continue;
            }

            const FIoChunkId ChunkId = CreatePackageDataChunkId(ExternalPackageId);
            TIoStatusOr<FIoBuffer> SummaryResult = Reader.Read(
                ChunkId,
                FIoReadOptions(0, sizeof(FZenPackageSummary)));
            if (!SummaryResult.IsOk())
            {
                ++FailedHeaders;
                continue;
            }

            FIoBuffer SummaryBuffer = SummaryResult.ConsumeValueOrDie();
            if (SummaryBuffer.DataSize() < sizeof(FZenPackageSummary))
            {
                ++FailedHeaders;
                continue;
            }

            FZenPackageSummary Summary;
            FMemory::Memcpy(
                &Summary,
                SummaryBuffer.Data(),
                sizeof(FZenPackageSummary));

            static constexpr uint32 MaxReasonableZenHeaderSize = 64u * 1024u * 1024u;
            if (Summary.HeaderSize < sizeof(FZenPackageSummary) ||
                Summary.HeaderSize > MaxReasonableZenHeaderSize)
            {
                ++FailedHeaders;
                continue;
            }

            TIoStatusOr<FIoBuffer> HeaderResult = Reader.Read(
                ChunkId,
                FIoReadOptions(0, Summary.HeaderSize));
            if (!HeaderResult.IsOk())
            {
                ++FailedHeaders;
                continue;
            }

            FIoBuffer HeaderBuffer = HeaderResult.ConsumeValueOrDie();
            if (HeaderBuffer.DataSize() < Summary.HeaderSize ||
                HeaderBuffer.DataSize() > static_cast<uint64>(MAX_int32))
            {
                ++FailedHeaders;
                continue;
            }

            TArray<uint8> HeaderBytes;
            HeaderBytes.SetNumUninitialized(static_cast<int32>(HeaderBuffer.DataSize()));
            FMemory::Memcpy(
                HeaderBytes.GetData(),
                HeaderBuffer.Data(),
                HeaderBuffer.DataSize());

            SquadCookedMount::FDiagnosticZenHeaderView Header;
            FString ParseError;
            if (!SquadCookedMount::ParseDiagnosticZenHeader(
                    HeaderBytes,
                    Header,
                    ParseError))
            {
                ++FailedHeaders;
                continue;
            }

            ++ScannedHeaders;
            if (!Header.PackageName.IsNone())
            {
                ExternalPackageNameToId.Add(Header.PackageName, ExternalPackageId);
                // Cache the exact imported-package ordering that was used below to
                // classify PackageImport references. Overlay preparation must use
                // this same ordering; querying the live FPackageStore again during
                // startup can return an empty entry even though the reconstructed
                // container snapshot is complete.
                ExternalPackageImportedPackageIds.Add(
                    ExternalPackageId,
                    Snapshot->Data.ImportedPackageIds);
                ExternalPackageSourceUtocs.Add(
                    ExternalPackageId, Snapshot->SourceUtoc);
            }

            if (!bCookCommandletMode && !Header.PackageName.IsNone())
            {
                for (const FExportMapEntry& Export : Header.ExportMap)
                {
                    if (Export.ClassIndex != FunctionClassIndex ||
                        !Export.SuperIndex.IsPackageImport())
                    {
                        continue;
                    }

                    const FPackageImportReference SuperRef =
                        Export.SuperIndex.ToPackageImportRef();
                    const uint32 ParentIndex = SuperRef.GetImportedPackageIndex();
                    const uint32 HashIndex =
                        SuperRef.GetImportedPublicExportHashIndex();
                    if (ParentIndex >= static_cast<uint32>(
                            Snapshot->Data.ImportedPackageIds.Num()) ||
                        HashIndex >= static_cast<uint32>(
                            Header.ImportedPublicExportHashes.Num()))
                    {
                        continue;
                    }

                    const FPackageId ParentPackageId =
                        Snapshot->Data.ImportedPackageIds[ParentIndex];
                    if (!ParentPackageId.IsValid() ||
                        ParentPackageId == ExternalPackageId ||
                        ExternalPackageIds.Contains(ParentPackageId))
                    {
                        continue;
                    }

                    ExternalPackageStockUFunctionSuperParents
                        .FindOrAdd(ExternalPackageId)
                        .AddUnique(ParentPackageId);
                    ExternalPackagesWithStockUFunctionSupers.Add(ExternalPackageId);
                    ++StockUFunctionSuperEdges;
                }
            }

            TArray<FPackageId> CrossParents;
            auto RegisterObjectIndex =
                [this,
                 &ExternalPackageIds,
                 &Snapshot,
                 &Header,
                 &CrossParents,
                 &ObjectImportRefs,
                 &CrossLoaderObjectRefs,
                 &ResolvedParentNames,
                 &InvalidPackageImportRefs,
                 ExternalPackageId]
                (const FPackageObjectIndex& ObjectIndex, bool bSuperIndex)
                {
                    if (!ObjectIndex.IsPackageImport())
                    {
                        return;
                    }

                    ++ObjectImportRefs;
                    const FPackageImportReference ImportRef =
                        ObjectIndex.ToPackageImportRef();
                    const uint32 ImportedPackageIndex =
                        ImportRef.GetImportedPackageIndex();
                    const uint32 PublicHashIndex =
                        ImportRef.GetImportedPublicExportHashIndex();

                    if (ImportedPackageIndex >=
                            static_cast<uint32>(Snapshot->Data.ImportedPackageIds.Num()) ||
                        PublicHashIndex >=
                            static_cast<uint32>(Header.ImportedPublicExportHashes.Num()))
                    {
                        ++InvalidPackageImportRefs;
                        return;
                    }

                    const FPackageId ParentPackageId =
                        Snapshot->Data.ImportedPackageIds[ImportedPackageIndex];
                    if (!ParentPackageId.IsValid() ||
                        ExternalPackageIds.Contains(ParentPackageId))
                    {
                        return;
                    }

                    const uint64 ParentPublicExportHash =
                        Header.ImportedPublicExportHashes[PublicHashIndex];
                    if (ParentPublicExportHash == 0)
                    {
                        ++InvalidPackageImportRefs;
                        return;
                    }

                    ++CrossLoaderObjectRefs;
                    CrossLoaderParentPackageIds.Add(ParentPackageId);
                    CrossLoaderParentPublicHashes
                        .FindOrAdd(ParentPackageId)
                        .Add(ParentPublicExportHash);
                    if (!Header.PackageName.IsNone())
                    {
                        CrossLoaderParentHashConsumers
                            .FindOrAdd(ParentPackageId)
                            .FindOrAdd(ParentPublicExportHash)
                            .Add(ExternalPackageId, Header.PackageName);
                    }
                    if (bSuperIndex)
                    {
                        CrossLoaderSuperParentPublicHashes
                            .FindOrAdd(ParentPackageId)
                            .Add(ParentPublicExportHash);
                    }
                    else
                    {
                        CrossLoaderNonSuperParentPublicHashes
                            .FindOrAdd(ParentPackageId)
                            .Add(ParentPublicExportHash);
                    }
                    CrossParents.AddUnique(ParentPackageId);

                    FName ParentName = NAME_None;
                    if (Header.ImportedPackageNames.IsValidIndex(
                            static_cast<int32>(ImportedPackageIndex)))
                    {
                        ParentName = Header.ImportedPackageNames[ImportedPackageIndex];
                    }
#if WITH_PACKAGEID_NAME_MAP
                    if (ParentName.IsNone())
                    {
                        ParentName = ParentPackageId.GetName();
                    }
#endif
                    if (!ParentName.IsNone() &&
                        !CrossLoaderParentPackageNames.Contains(ParentPackageId))
                    {
                        CrossLoaderParentPackageNames.Add(ParentPackageId, ParentName);
                        ++ResolvedParentNames;
                    }

                };

            // ImportMap covers object references serialized inside export data.
            // ExportMap indices additionally cover object construction metadata
            // (Outer/Class/Super/Template), including Blueprint component
            // archetypes such as NavmeshComponent and VehicleArmorTarget.
            for (const FPackageObjectIndex& ImportIndex : Header.ImportMap)
            {
                RegisterObjectIndex(ImportIndex, false);
            }
            for (const FExportMapEntry& Export : Header.ExportMap)
            {
                RegisterObjectIndex(Export.OuterIndex, false);
                RegisterObjectIndex(Export.ClassIndex, false);
                RegisterObjectIndex(Export.SuperIndex, true);
                RegisterObjectIndex(Export.TemplateIndex, false);
            }

            if (!CrossParents.IsEmpty())
            {
                ++PackagesWithCrossLoaderRefs;
                ExternalPackageCrossLoaderParents.Add(
                    ExternalPackageId,
                    MoveTemp(CrossParents));
            }
        }
    }

    int32 EditorInitialFunctionSuperHashes = 0;
    int32 EditorInitialFunctionSuperPackages = 0;
    if (!bCookCommandletMode)
    {
        for (const TPair<FPackageId, TSet<uint64>>& Pair :
             CrossLoaderSuperParentPublicHashes)
        {
            const FPackageId ParentPackageId = Pair.Key;
            FName ParentPackageName = NAME_None;
            if (const FName* KnownName =
                    CrossLoaderParentPackageNames.Find(ParentPackageId))
            {
                ParentPackageName = *KnownName;
            }
#if WITH_PACKAGEID_NAME_MAP
            if (ParentPackageName.IsNone())
            {
                ParentPackageName = ParentPackageId.GetName();
            }
#endif
            if (ParentPackageName.IsNone())
            {
                continue;
            }

            UPackage* ParentPackage = FindPackage(
                nullptr,
                *ParentPackageName.ToString());
            FLinkerLoad* ParentLinker =
                ParentPackage ? ParentPackage->GetLinker() : nullptr;
            if (!ParentPackage || !ParentLinker)
            {
                continue;
            }

            TMap<uint64, UFunction*> UniqueFunctions;
            TSet<uint64> AmbiguousFunctionHashes;
            auto AddFunctionCandidate =
                [&UniqueFunctions, &AmbiguousFunctionHashes](
                    uint64 Hash,
                    UFunction* Function)
                {
                    if (!Hash || !Function ||
                        AmbiguousFunctionHashes.Contains(Hash))
                    {
                        return;
                    }

                    if (UFunction** Existing = UniqueFunctions.Find(Hash))
                    {
                        if (*Existing != Function)
                        {
                            UniqueFunctions.Remove(Hash);
                            AmbiguousFunctionHashes.Add(Hash);
                        }
                        return;
                    }
                    UniqueFunctions.Add(Hash, Function);
                };

            for (int32 ExportIndex = 0;
                 ExportIndex < ParentLinker->ExportMap.Num();
                 ++ExportIndex)
            {
                FString RelativePath;
                const uint64 Hash =
                    SquadCookedMount::ComputeLinkerLoadExportHash(
                        ParentLinker,
                        ExportIndex,
                        RelativePath);
                if (!Hash || !Pair.Value.Contains(Hash))
                {
                    continue;
                }

                const FObjectExport& ParentExport =
                    ParentLinker->ExportMap[ExportIndex];
                UFunction* Function = Cast<UFunction>(ParentExport.Object);
                if (!Function || Function->IsUnreachable() ||
                    Function->GetOutermost() != ParentPackage)
                {
                    continue;
                }
                AddFunctionCandidate(Hash, Function);
            }

            // Include regenerated functions that no longer have an ExportMap
            // slot (linkerIndex=-1). This is read-only and does not touch the
            // vanilla package lifecycle.
            ForEachObjectWithOuter(
                ParentPackage,
                [ParentPackage, &Pair, &AddFunctionCandidate](UObject* Object)
                {
                    UFunction* Function = Cast<UFunction>(Object);
                    if (!Function || Function->IsUnreachable() ||
                        Function->GetOutermost() != ParentPackage)
                    {
                        return;
                    }

                    FString RelativePath;
                    const uint64 Hash =
                        SquadCookedMount::ComputeLiveObjectExportHash(
                            Function,
                            ParentPackage,
                            RelativePath);
                    if (Hash && Pair.Value.Contains(Hash))
                    {
                        AddFunctionCandidate(Hash, Function);
                    }
                },
                /* bIncludeNestedObjects */ true);

            int32 AddedForPackage = 0;
            const TSet<uint64>* NonSuperHashes =
                CrossLoaderNonSuperParentPublicHashes.Find(ParentPackageId);
            for (const TPair<uint64, UFunction*>& FunctionPair : UniqueFunctions)
            {
                if (NonSuperHashes && NonSuperHashes->Contains(FunctionPair.Key))
                {
                    continue;
                }
                TSet<uint64>& OverlayHashes =
                    EditorSuperOverlayParentHashes.FindOrAdd(ParentPackageId);
                if (!OverlayHashes.Contains(FunctionPair.Key))
                {
                    OverlayHashes.Add(FunctionPair.Key);
                    ++EditorInitialFunctionSuperHashes;
                    ++AddedForPackage;
                }
            }
            if (AddedForPackage > 0)
            {
                ++EditorInitialFunctionSuperPackages;
            }
        }
    }

    bCrossLoaderImportIndexReady = ScannedHeaders > 0;

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_FIX LINKER_REINDEX INDEX_READY | externalPackages=%d | candidateHeaders=%d | scannedHeaders=%d | failedHeaders=%d | objectImportRefs=%d | crossLoaderRefs=%d | externalPackagesWithCrossRefs=%d | uniqueParentPackages=%d | resolvedParentNames=%d | invalidRefs=%d | editorFunctionSuperPackages=%d | editorFunctionSuperHashes=%d | externalPackagesWithStockUFunctionSupers=%d | stockUFunctionSuperEdges=%d | startupPrearm=POST_INDEX | parsedContainers=%d failedContainers=%d | hardcodedAssets=NO"),
        AllEntries.Num(),
        CandidateHeaders,
        ScannedHeaders,
        FailedHeaders,
        ObjectImportRefs,
        CrossLoaderObjectRefs,
        PackagesWithCrossLoaderRefs,
        CrossLoaderParentPackageIds.Num(),
        ResolvedParentNames,
        InvalidPackageImportRefs,
        EditorInitialFunctionSuperPackages,
        EditorInitialFunctionSuperHashes,
        ExternalPackagesWithStockUFunctionSupers.Num(),
        StockUFunctionSuperEdges,
        ParsedContainers,
        FailedContainers);

    return bCrossLoaderImportIndexReady;
#else
    return false;
#endif
}

int32 FSquadCookedMountModule::PreArmExternalUFunctionSuperOverlays()
{
#if WITH_EDITOR
    if (bCookCommandletMode || !bCrossLoaderImportIndexReady ||
        !IsInGameThread() || !FIoDispatcher::IsInitialized())
    {
        return 0;
    }

    // FCoreDelegates::OnSyncLoadPackage/GetOnAsyncLoadPackage only observe
    // explicit load requests. Zen dependencies created recursively inside
    // AsyncLoading2 do not pass through those delegates. Pre-arm the narrow
    // set discovered from immutable cooked headers so an external Blueprint is
    // already patched even when it is reached only as a dependency of an
    // editor/source package (for example BP_MI28 through BP_MI28_Child).
    TSet<FPackageId> RequiredParentIds;
    for (const TPair<FPackageId, TArray<FPackageId>>& Pair :
         ExternalPackageStockUFunctionSuperParents)
    {
        for (const FPackageId ParentId : Pair.Value)
        {
            if (ParentId.IsValid())
            {
                RequiredParentIds.Add(ParentId);
            }
        }
    }

    TArray<FPackageId> SortedParentIds;
    SortedParentIds.Reserve(RequiredParentIds.Num());
    for (const FPackageId ParentId : RequiredParentIds)
    {
        SortedParentIds.Add(ParentId);
    }
    SortedParentIds.Sort(
        [](const FPackageId& A, const FPackageId& B)
        {
            return A.Value() < B.Value();
        });

    int32 ParentAlreadyLoaded = 0;
    int32 ParentLoadedNow = 0;
    int32 ParentLoadFailed = 0;
    int32 ParentNameMissing = 0;

    // Loading a stock parent can itself broadcast OnSyncLoadPackage. Suppress
    // recursive JIT work while this deterministic parent-first phase runs.
    {
        TGuardValue<bool> ParentLoadGuard(
            bCrossLoaderRefreshInProgress,
            true);

        for (const FPackageId ParentId : SortedParentIds)
        {
            FName ParentName = NAME_None;
            if (const FName* KnownName =
                    CrossLoaderParentPackageNames.Find(ParentId))
            {
                ParentName = *KnownName;
            }
#if WITH_PACKAGEID_NAME_MAP
            if (ParentName.IsNone())
            {
                ParentName = ParentId.GetName();
            }
#endif
            if (ParentName.IsNone())
            {
                ++ParentNameMissing;
                continue;
            }

            const FString ParentNameText = ParentName.ToString();
            if (ParentNameText.StartsWith(
                    TEXT("/Script/"),
                    ESearchCase::IgnoreCase))
            {
                ++ParentAlreadyLoaded;
                continue;
            }

            UPackage* ParentPackage = FindPackage(nullptr, *ParentNameText);
            if (ParentPackage && ParentPackage->bHasBeenFullyLoaded)
            {
                ++ParentAlreadyLoaded;
                continue;
            }

            ParentPackage = LoadPackage(nullptr, *ParentNameText, LOAD_None);
            if (ParentPackage)
            {
                ++ParentLoadedNow;
            }
            else
            {
                ++ParentLoadFailed;
                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("SCM_FIX UFUNCTION_PREARM_PARENT_LOAD_FAIL | parent='%s' | id=0x%016llX"),
                    *ParentNameText,
                    static_cast<unsigned long long>(ParentId.Value()));
            }
        }
    }

    struct FPreArmTarget
    {
        FString PackageName;
        FPackageId PackageId;
    };

    TArray<FPreArmTarget> Targets;
    Targets.Reserve(ExternalPackageStockUFunctionSuperParents.Num());
    for (const TPair<FName, FPackageId>& Pair : ExternalPackageNameToId)
    {
        if (!ExternalPackageStockUFunctionSuperParents.Contains(Pair.Value))
        {
            continue;
        }

        FPreArmTarget& Target = Targets.AddDefaulted_GetRef();
        Target.PackageName = Pair.Key.ToString();
        Target.PackageId = Pair.Value;
    }
    Targets.Sort(
        [](const FPreArmTarget& A, const FPreArmTarget& B)
        {
            return A.PackageName < B.PackageName;
        });

    int32 OverlayPrepared = 0;
    int32 OverlayFailed = 0;
    int32 AlreadyLive = 0;
    for (const FPreArmTarget& Target : Targets)
    {
        if (UPackage* Existing = FindPackage(nullptr, *Target.PackageName))
        {
            if (Existing->bHasBeenFullyLoaded ||
                Existing->HasAnyFlags(RF_WasLoaded | RF_LoadCompleted))
            {
                ++AlreadyLive;
                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("SCM_FIX UFUNCTION_PREARM_TOO_LATE | package='%s' | id=0x%016llX | mutation=NO"),
                    *Target.PackageName,
                    static_cast<unsigned long long>(Target.PackageId.Value()));
                continue;
            }
        }

        if (PrepareGenericBlueprintSuperOverlayForPackage(
                Target.PackageName,
                /*bAllowKnownFailedStockUFunctionImports=*/false))
        {
            ++OverlayPrepared;
        }
        else
        {
            ++OverlayFailed;
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_FIX UFUNCTION_PREARM_SUMMARY | externalTargets=%d | uniqueStockParents=%d | parentAlreadyLoaded=%d | parentLoadedNow=%d | parentLoadFailed=%d | parentNameMissing=%d | overlaysPrepared=%d | overlaysFailed=%d | alreadyLiveTooLate=%d | dependencyLoadsCovered=YES | surrogateUFunctions=NO"),
        Targets.Num(),
        SortedParentIds.Num(),
        ParentAlreadyLoaded,
        ParentLoadedNow,
        ParentLoadFailed,
        ParentNameMissing,
        OverlayPrepared,
        OverlayFailed,
        AlreadyLive);

    return OverlayPrepared;
#else
    return 0;
#endif
}

void FSquadCookedMountModule::RefreshLiveUFunctionScriptBindingsAfterBlueprintCompile()
{
#if WITH_EDITOR
    if (!IsInGameThread() ||
        SquadCookedMount::GSCMLiveUFunctionScriptBindingDescriptors.IsEmpty())
    {
        return;
    }

    TArray<FPackageObjectIndex> ScriptIndices;
    SquadCookedMount::GSCMLiveUFunctionScriptBindingDescriptors.GetKeys(
        ScriptIndices);

    int32 Rebound = 0;
    int32 Unchanged = 0;
    int32 Missing = 0;
    int32 Ambiguous = 0;
    int32 RegistrationFailed = 0;

    for (const FPackageObjectIndex ScriptIndex : ScriptIndices)
    {
        const SquadCookedMount::FSCMLiveUFunctionScriptBindingDescriptor* Descriptor =
            SquadCookedMount::GSCMLiveUFunctionScriptBindingDescriptors.Find(
                ScriptIndex);
        if (!Descriptor || Descriptor->ParentPackageName.IsNone() ||
            Descriptor->PublicExportHash == 0)
        {
            ++Missing;
            continue;
        }

        UPackage* ParentPackage = FindPackage(
            nullptr,
            *Descriptor->ParentPackageName.ToString());
        if (!ParentPackage)
        {
            ++Missing;
            continue;
        }

        int32 Matches = 0;
        FString RelativePath;
        bool bExportLoadFailed = false;
        bool bLiveFallback = false;
        UFunction* Function =
            SquadCookedMount::FindUniqueLiveUFunctionByExportHash(
                ParentPackage,
                ParentPackage->GetLinker(),
                Descriptor->PublicExportHash,
                Matches,
                RelativePath,
                bExportLoadFailed,
                bLiveFallback);
        if (Matches != 1 || !Function)
        {
            if (Matches > 1)
            {
                ++Ambiguous;
            }
            else
            {
                ++Missing;
            }
            continue;
        }

        UObject* Previous = nullptr;
        if (const TStrongObjectPtr<UObject>* ExistingPin =
                SquadCookedMount::GSCMLiveUFunctionScriptPins.Find(ScriptIndex))
        {
            Previous = ExistingPin->Get();
        }
        if (Previous == Function)
        {
            ++Unchanged;
            continue;
        }

        FPackageObjectIndex NewScriptIndex;
        FString ScriptPath;
        if (!SquadCookedMount::RegisterLiveUFunctionScriptImport(
                ParentPackage,
                Function,
                Descriptor->PublicExportHash,
                NewScriptIndex,
                ScriptPath) ||
            NewScriptIndex != ScriptIndex)
        {
            ++RegistrationFailed;
            continue;
        }
        ++Rebound;
    }

    if (Rebound > 0 || Missing > 0 || Ambiguous > 0 ||
        RegistrationFailed > 0 || SquadCookedMount::IsVerboseSCMDiagnosticsEnabled())
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_FIX UFUNCTION_LIVE_REBIND_AFTER_BLUEPRINT_COMPILE | tracked=%d | rebound=%d | unchanged=%d | missing=%d | ambiguous=%d | registrationFailed=%d"),
            ScriptIndices.Num(),
            Rebound,
            Unchanged,
            Missing,
            Ambiguous,
            RegistrationFailed);
    }
#endif
}

int32 FSquadCookedMountModule::RefreshLoadedLinkerPackagesForZenImports(
    const TArray<FPackageId>* RestrictToPackageIds,
    const TCHAR* Reason,
    bool bForceSyncRefresh)
{
#if WITH_EDITOR
    if (!bCrossLoaderImportIndexReady || bCrossLoaderRefreshInProgress)
    {
        return 0;
    }

    // v3 never leaves packages merely "armed". The v2 experiment cleared
    // bHasBeenFullyLoaded without clearing RF_WasLoaded, then treated the
    // resulting async request as a successful reindex even when AsyncLoading2
    // had not rebuilt the package's public-export map. A half-mutated package
    // is worse than an unresolved import, especially across PIE teardown/GC.
    if (!bForceSyncRefresh)
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("SCM_FIX LINKER_REINDEX SKIP | reason='%s' | syncRefresh=NO is no longer supported; package state left untouched"),
            Reason ? Reason : TEXT("<none>"));
        return 0;
    }

    TGuardValue<bool> RefreshGuard(bCrossLoaderRefreshInProgress, true);

    TArray<FPackageId> WorkIds;
    if (RestrictToPackageIds)
    {
        WorkIds = *RestrictToPackageIds;
    }
    else
    {
        WorkIds.Reserve(CrossLoaderParentPackageIds.Num());
        for (const FPackageId PackageId : CrossLoaderParentPackageIds)
        {
            WorkIds.Add(PackageId);
        }
    }

    int32 LoadedCandidates = 0;
    int32 LinkerCandidates = 0;
    int32 AlreadyAttempted = 0;
    int32 AlreadyVerified = 0;
    int32 MarkedUnloaded = 0;
    int32 RefreshedPackages = 0;
    int32 VerifiedPackages = 0;
    int32 FailedRefreshes = 0;
    int32 FailedVerification = 0;
    int32 BusyPackages = 0;
    int32 NameMisses = 0;
    int32 RequiredHashCount = 0;
    int32 ResolvedHashCount = 0;
    int32 LoaderImportHashCount = 0;
    int32 EditorStockSkipped = 0;
    int32 EditorSpecialCandidates = 0;
    int32 EditorSuperOverlayHashSkipped = 0;
    int32 EditorFailedUFunctionHashSkipped = 0;
    int32 EditorSyntheticUFunctionHashSkipped = 0;

    for (const FPackageId PackageId : WorkIds)
    {
        if (!PackageId.IsValid() ||
            !CrossLoaderParentPackageIds.Contains(PackageId))
        {
            continue;
        }

        FName PackageName = NAME_None;
        if (const FName* KnownName = CrossLoaderParentPackageNames.Find(PackageId))
        {
            PackageName = *KnownName;
        }
#if WITH_PACKAGEID_NAME_MAP
        if (PackageName.IsNone())
        {
            PackageName = PackageId.GetName();
        }
#endif
        if (PackageName.IsNone())
        {
            ++NameMisses;
            continue;
        }

        const FString PackageNameText = PackageName.ToString();
        if (PackageNameText.StartsWith(TEXT("/Script/"), ESearchCase::IgnoreCase))
        {
            continue;
        }

        UPackage* Package = FindPackage(nullptr, *PackageNameText);
        if (!Package)
        {
            // Unloaded parents are the safe case: when an external Zen package
            // imports them, AsyncLoading2 owns their LinkerLoad lifecycle from
            // the start and registers their public exports normally.
            continue;
        }
        ++LoadedCandidates;

        FLinkerLoad* Linker = Package->GetLinker();
        if (!Linker)
        {
            continue;
        }
        ++LinkerCandidates;

        if (Package->HasAnyFlags(RF_NeedLoad | RF_NeedPostLoad))
        {
            ++BusyPackages;
            continue;
        }

        const TSet<uint64>* RawRequiredHashes =
            CrossLoaderParentPublicHashes.Find(PackageId);
        if (!RawRequiredHashes || RawRequiredHashes->IsEmpty())
        {
            continue;
        }

        TSet<uint64> EditorFilteredRequiredHashes;
        const TSet<uint64>* RequiredHashes = RawRequiredHashes;
        if (!bCookCommandletMode)
        {
            // Interactive editor owns a mutable required-hash view. Never use
            // the transient LoaderImport pin as a reason to reload a vanilla
            // Blueprint package. In particular, regenerated UFunctions with a
            // live Object + bExportLoadFailed are intentionally *not*
            // registered by forcing their package through MarkAsUnloaded() +
            // LoadPackageAsync. That lifecycle was proven to poison Squad's
            // regenerated Blueprint state across PIE teardown/restart.
            EditorFilteredRequiredHashes = *RawRequiredHashes;

            if (const TSet<uint64>* OverlayHashes =
                    EditorSuperOverlayParentHashes.Find(PackageId))
            {
                for (const uint64 OverlayHash : *OverlayHashes)
                {
                    if (EditorFilteredRequiredHashes.Remove(OverlayHash) > 0)
                    {
                        ++EditorSuperOverlayHashSkipped;
                    }
                }
            }

            int32 FailedUFunctionsSkippedForPackage = 0;
            for (int32 ExportIndex = 0;
                 ExportIndex < Linker->ExportMap.Num() &&
                 !EditorFilteredRequiredHashes.IsEmpty();
                 ++ExportIndex)
            {
                const FObjectExport& Candidate = Linker->ExportMap[ExportIndex];
                if (!Candidate.bExportLoadFailed || !Candidate.Object ||
                    Candidate.Object->IsUnreachable() ||
                    Candidate.Object->GetOutermost() != Package ||
                    !Candidate.Object->IsA<UFunction>())
                {
                    continue;
                }

                FString RelativePath;
                const uint64 CandidateHash =
                    SquadCookedMount::ComputeLinkerLoadExportHash(
                        Linker,
                        ExportIndex,
                        RelativePath);
                if (CandidateHash &&
                    EditorFilteredRequiredHashes.Remove(CandidateHash) > 0)
                {
                    ++FailedUFunctionsSkippedForPackage;
                    ++EditorFailedUFunctionHashSkipped;
                    EditorSuperOverlayParentHashes
                        .FindOrAdd(PackageId)
                        .Add(CandidateHash);
                }
            }

            if (FailedUFunctionsSkippedForPackage > 0)
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Display,
                    TEXT("SCM_FIX LINKER_REINDEX EDITOR_UFUNCTION_SKIP | reason='%s' | package='%s' | id=0x%016llX | failedUFunctionHashes=%d | mutation=NO | owner=GENERIC_SUPER_OVERLAY"),
                    Reason ? Reason : TEXT("<none>"),
                    *PackageNameText,
                    static_cast<unsigned long long>(PackageId.Value()),
                    FailedUFunctionsSkippedForPackage);
            }

            RequiredHashes = &EditorFilteredRequiredHashes;
        }

        if (RequiredHashes->IsEmpty())
        {
            continue;
        }
        RequiredHashCount += RequiredHashes->Num();

        auto VerifyRequiredPublicExports =
            [Linker, RequiredHashes](
                int32& OutResolved,
                int32& OutLoaderImport,
                int32& OutMissingObjects)
            {
                OutResolved = 0;
                OutLoaderImport = 0;
                OutMissingObjects = 0;

                TSet<uint64> Remaining = *RequiredHashes;
                for (int32 ExportIndex = 0;
                     ExportIndex < Linker->ExportMap.Num() && !Remaining.IsEmpty();
                     ++ExportIndex)
                {
                    FString RelativePath;
                    const uint64 Hash =
                        SquadCookedMount::ComputeLinkerLoadExportHash(
                            Linker,
                            ExportIndex,
                            RelativePath);
                    if (!Remaining.Remove(Hash))
                    {
                        continue;
                    }

                    ++OutResolved;
                    UObject* Object = Linker->ExportMap[ExportIndex].Object;
                    if (!Object)
                    {
                        ++OutMissingObjects;
                        continue;
                    }
                    if (Object->HasAnyInternalFlags(EInternalObjectFlags::LoaderImport))
                    {
                        ++OutLoaderImport;
                    }
                }

                return OutResolved == RequiredHashes->Num() &&
                       OutLoaderImport == RequiredHashes->Num() &&
                       OutMissingObjects == 0;
            };

        int32 PreResolved = 0;
        int32 PreLoaderImport = 0;
        int32 PreMissingObjects = 0;
        if (VerifyRequiredPublicExports(
                PreResolved,
                PreLoaderImport,
                PreMissingObjects))
        {
            ++AlreadyVerified;
            ++VerifiedPackages;
            ResolvedHashCount += PreResolved;
            LoaderImportHashCount += PreLoaderImport;
            // No package mutation happened here. Do not consume the one-shot
            // mutation guard: editor Blueprint regeneration can replace an export
            // later in the session, in which case the same live package may then
            // genuinely need the targeted failed/synthetic bridge.
            continue;
        }

        // UE5.7's hybrid LinkerLoad bridge computes a public-export hash for
        // every linker export, but FLinkerLoad::CreateExport() returns nullptr
        // when bExportLoadFailed is set even if editor Blueprint regeneration
        // has left a valid live Export.Object behind. Those are precisely the
        // objects external Zen packages still reference by public hash.
        //
        // Temporarily clear bExportLoadFailed only for an exact, unique
        // required-hash match with a live object in this package. This lets the
        // stock AsyncLoading2 CreateLinkerLoadExports path call
        // StoreGlobalObject(PackageId, Hash, Object). The linker flag is
        // restored in the load completion callback before the request is
        // released; GlobalImportStore keeps the registered mapping. No UObject
        // flags, package data, cooked Zen bytes, or disk files are modified.
        // Build an exact hash view of the current linker table. v6 uses the
        // all-export map not only for required imports but also to anchor the
        // outer chain of live regenerated objects that disappeared from
        // FLinkerLoad::ExportMap.
        const int32 OriginalLinkerExportCount = Linker->ExportMap.Num();
        TMap<uint64, int32> UniqueRequiredHashExports;
        TSet<uint64> AmbiguousRequiredHashes;
        TMap<uint64, int32> UniqueAllHashExports;
        TSet<uint64> AmbiguousAllHashes;
        TSet<uint64> MissingRequiredHashesBeforeSynthetic = *RequiredHashes;
        TMap<UObject*, int32> ObjectToExportIndex;

        for (int32 ExportIndex = 0; ExportIndex < Linker->ExportMap.Num(); ++ExportIndex)
        {
            FObjectExport& ExistingExport = Linker->ExportMap[ExportIndex];
            if (ExistingExport.Object &&
                !ObjectToExportIndex.Contains(ExistingExport.Object))
            {
                ObjectToExportIndex.Add(ExistingExport.Object, ExportIndex);
            }

            FString RelativePath;
            const uint64 Hash =
                SquadCookedMount::ComputeLinkerLoadExportHash(
                    Linker,
                    ExportIndex,
                    RelativePath);
            if (!Hash)
            {
                continue;
            }

            MissingRequiredHashesBeforeSynthetic.Remove(Hash);

            if (!AmbiguousAllHashes.Contains(Hash))
            {
                if (UniqueAllHashExports.Contains(Hash))
                {
                    UniqueAllHashExports.Remove(Hash);
                    AmbiguousAllHashes.Add(Hash);
                }
                else
                {
                    UniqueAllHashExports.Add(Hash, ExportIndex);
                }
            }

            if (!RequiredHashes->Contains(Hash) ||
                AmbiguousRequiredHashes.Contains(Hash))
            {
                continue;
            }

            if (UniqueRequiredHashExports.Contains(Hash))
            {
                UniqueRequiredHashExports.Remove(Hash);
                AmbiguousRequiredHashes.Add(Hash);
                continue;
            }
            UniqueRequiredHashExports.Add(Hash, ExportIndex);
        }

        // Some editor Blueprint regenerations keep the authoritative UObject
        // alive but remove its old disk export from FLinkerLoad::ExportMap.
        // Those objects have linkerIndex=-1 and cannot be reached by the v4
        // bExportLoadFailed bridge. Find only exact, unique live hash matches.
        TMap<uint64, UObject*> UniqueMissingLiveObjects;
        TSet<uint64> AmbiguousMissingLiveHashes;
        if (!MissingRequiredHashesBeforeSynthetic.IsEmpty())
        {
            ForEachObjectWithOuter(
                Package,
                [Package, &MissingRequiredHashesBeforeSynthetic,
                 &UniqueMissingLiveObjects,
                 &AmbiguousMissingLiveHashes](UObject* Object)
                {
                    if (!Object || Object->IsUnreachable() ||
                        Object->GetOutermost() != Package)
                    {
                        return;
                    }

                    FString RelativePath;
                    const uint64 Hash =
                        SquadCookedMount::ComputeLiveObjectExportHash(
                            Object,
                            Package,
                            RelativePath);
                    if (!Hash ||
                        !MissingRequiredHashesBeforeSynthetic.Contains(Hash) ||
                        AmbiguousMissingLiveHashes.Contains(Hash))
                    {
                        return;
                    }

                    if (UniqueMissingLiveObjects.Contains(Hash))
                    {
                        UniqueMissingLiveObjects.Remove(Hash);
                        AmbiguousMissingLiveHashes.Add(Hash);
                        return;
                    }

                    UniqueMissingLiveObjects.Add(Hash, Object);
                },
                /* bIncludeNestedObjects */ true);
        }

        if (!bCookCommandletMode && !UniqueMissingLiveObjects.IsEmpty())
        {
            TArray<uint64> SyntheticFunctionHashesToSkip;
            for (const TPair<uint64, UObject*>& Pair : UniqueMissingLiveObjects)
            {
                if (Pair.Value && Pair.Value->IsA<UFunction>())
                {
                    SyntheticFunctionHashesToSkip.Add(Pair.Key);
                }
            }

            for (const uint64 FunctionHash : SyntheticFunctionHashesToSkip)
            {
                if (EditorFilteredRequiredHashes.Remove(FunctionHash) > 0)
                {
                    ++EditorSyntheticUFunctionHashSkipped;
                }
                MissingRequiredHashesBeforeSynthetic.Remove(FunctionHash);
                UniqueMissingLiveObjects.Remove(FunctionHash);
                EditorSuperOverlayParentHashes
                    .FindOrAdd(PackageId)
                    .Add(FunctionHash);
            }

            if (!SyntheticFunctionHashesToSkip.IsEmpty())
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Display,
                    TEXT("SCM_FIX LINKER_REINDEX EDITOR_SYNTHETIC_UFUNCTION_SKIP | reason='%s' | package='%s' | id=0x%016llX | liveUFunctionHashes=%d | mutation=NO | owner=GENERIC_SUPER_OVERLAY"),
                    Reason ? Reason : TEXT("<none>"),
                    *PackageNameText,
                    static_cast<unsigned long long>(PackageId.Value()),
                    SyntheticFunctionHashesToSkip.Num());
            }

            RequiredHashes = &EditorFilteredRequiredHashes;
            if (RequiredHashes->IsEmpty())
            {
                continue;
            }
        }

        // Interactive editor safety policy (v6.2): do not force an already
        // loaded vanilla package through another full AsyncLoading2/EndLoad
        // lifecycle merely because LoaderImport is not currently pinned.
        //
        // UE5.7 clears LoaderImport pins when package refs are released, while
        // the GlobalImportStore mapping itself remains. Therefore the old
        // pre-check made ordinary, already-correct packages look unregistered
        // and caused v6.1 to MarkAsUnloaded()+LoadPackageAsync 1572 packages.
        // MarkAsUnloaded clears both bHasBeenFullyLoaded and RF_WasLoaded, so
        // that broad pass is a real package re-load lifecycle and can perturb
        // editor/PIE state.
        //
        // In interactive mode only run the expensive hybrid reindex when the
        // exact required hashes prove that stock UE cannot register the object:
        //   1) a unique linker export is bExportLoadFailed but has a valid live
        //      UObject; or
        //   2) the required hash is absent from ExportMap but has one exact live
        //      UObject match (synthetic bridge).
        // Cook commandlets keep the v6.1 behavior unchanged.
        bool bHasRecoverableFailedExport = false;
        for (const TPair<uint64, int32>& Pair : UniqueRequiredHashExports)
        {
            if (!Linker->ExportMap.IsValidIndex(Pair.Value))
            {
                continue;
            }

            const FObjectExport& Candidate = Linker->ExportMap[Pair.Value];
            UObject* CandidateObject = Candidate.Object;
            if (Candidate.bExportLoadFailed && CandidateObject &&
                !CandidateObject->IsUnreachable() &&
                CandidateObject->GetOutermost() == Package)
            {
                bHasRecoverableFailedExport = true;
                break;
            }
        }

        const bool bHasRecoverableSyntheticExport =
            !UniqueMissingLiveObjects.IsEmpty();
        const bool bNeedsInteractiveSpecialBridge =
            bHasRecoverableFailedExport || bHasRecoverableSyntheticExport;

        if (!bCookCommandletMode && !bNeedsInteractiveSpecialBridge)
        {
            ++EditorStockSkipped;
            UE_LOG(
                LogSquadCookedMount,
                VeryVerbose,
                TEXT("SCM_FIX LINKER_REINDEX EDITOR_STOCK_SKIP | reason='%s' | package='%s' | id=0x%016llX | requiredHashes=%d | linkerResolved=%d | loaderPinsNow=%d | missingFromLinker=%d | ambiguousHashes=%d | mutation=NO"),
                Reason ? Reason : TEXT("<none>"),
                *PackageNameText,
                static_cast<unsigned long long>(PackageId.Value()),
                RequiredHashes->Num(),
                PreResolved,
                PreLoaderImport,
                MissingRequiredHashesBeforeSynthetic.Num(),
                AmbiguousRequiredHashes.Num());
            continue;
        }

        if (!bCookCommandletMode)
        {
            ++EditorSpecialCandidates;
        }

        if (const TWeakObjectPtr<UPackage>* PreviousAttempt =
                CrossLoaderRefreshAttempts.Find(PackageId))
        {
            if (PreviousAttempt->Get() == Package)
            {
                // Never mutate the same live editor package twice. This guard
                // applies to both the targeted editor bridge and the unchanged
                // cook path. A later PIE cycle may scan again, but it cannot
                // re-arm a package that was already processed in this process.
                ++AlreadyAttempted;
                continue;
            }
        }

        CrossLoaderRefreshAttempts.Add(PackageId, Package);

        // Append a temporary export chain for each unique live match. The
        // objects are already fully constructed, so FLinkerLoad::CreateExport
        // returns Export.Object immediately and never dereferences the placeholder
        // ClassIndex. OuterIndex is real/synthetic and exists only so UE5.7's
        // stock package-relative public-hash calculation produces the exact
        // cooked hash. The complete synthetic tail is removed in the completion
        // callback after AsyncLoading2 has detached the linker, but before the
        // AsyncPackage request is released.
        TArray<UObject*> SyntheticExportObjects;
        int32 SyntheticRequiredExportCount = 0;
        int32 SyntheticSupportExportCount = 0;
        int32 SyntheticBuildFailures = 0;

        TFunction<int32(UObject*)> EnsureSyntheticExportForLiveObject;
        EnsureSyntheticExportForLiveObject =
            [&](UObject* LiveObject) -> int32
            {
                if (!LiveObject || LiveObject == Package ||
                    LiveObject->IsUnreachable() ||
                    LiveObject->GetOutermost() != Package)
                {
                    return INDEX_NONE;
                }

                if (const int32* ExistingByObject =
                        ObjectToExportIndex.Find(LiveObject))
                {
                    return *ExistingByObject;
                }

                FString LiveRelativePath;
                const uint64 LiveHash =
                    SquadCookedMount::ComputeLiveObjectExportHash(
                        LiveObject,
                        Package,
                        LiveRelativePath);
                if (LiveHash && !AmbiguousAllHashes.Contains(LiveHash))
                {
                    if (const int32* ExistingByHash =
                            UniqueAllHashExports.Find(LiveHash))
                    {
                        ObjectToExportIndex.Add(LiveObject, *ExistingByHash);
                        return *ExistingByHash;
                    }
                }

                UObject* LiveOuter = LiveObject->GetOuter();
                FPackageIndex OuterIndex;
                if (LiveOuter && LiveOuter != Package)
                {
                    const int32 OuterExportIndex =
                        EnsureSyntheticExportForLiveObject(LiveOuter);
                    if (OuterExportIndex == INDEX_NONE)
                    {
                        return INDEX_NONE;
                    }
                    OuterIndex = FPackageIndex::FromExport(OuterExportIndex);
                }
                else if (LiveOuter != Package)
                {
                    return INDEX_NONE;
                }

                // CreateLinkerLoadExports treats a null ClassIndex as a
                // deliberately filtered/missing-class export before it calls
                // CreateExport. For an already-existing Object we only need a
                // valid non-null placeholder; CreateExport returns Object before
                // class resolution. Prefer an import slot, otherwise an
                // original export slot. Never point at the synthetic tail.
                FPackageIndex NonNullClassIndex;
                if (Linker->ImportMap.Num() > 0)
                {
                    NonNullClassIndex = FPackageIndex::FromImport(0);
                }
                else if (OriginalLinkerExportCount > 0)
                {
                    NonNullClassIndex = FPackageIndex::FromExport(0);
                }
                else
                {
                    return INDEX_NONE;
                }

                // Do not call FObjectExport(UObject*, bool) here. Although the
                // UE5.7 header declares it COREUOBJECT_API, some installed
                // SquadEditor import libraries do not expose that constructor
                // symbol to external plugins. Copying an existing export uses
                // the inline copy constructor and keeps this bridge ABI-only.
                if (OriginalLinkerExportCount <= 0)
                {
                    return INDEX_NONE;
                }

                const int32 NewExportIndex = Linker->ExportMap.Num();
                FObjectExport SyntheticExport = Linker->ExportMap[0];

                SyntheticExport.ObjectName = LiveObject->GetFName();
#if WITH_EDITORONLY_DATA
                SyntheticExport.OldClassName = NAME_None;
#endif
                SyntheticExport.OuterIndex = OuterIndex;
                SyntheticExport.ClassIndex = NonNullClassIndex;
                SyntheticExport.ThisIndex =
                    FPackageIndex::FromExport(NewExportIndex);
                SyntheticExport.SuperIndex = FPackageIndex();
                SyntheticExport.TemplateIndex = FPackageIndex();
                SyntheticExport.ObjectFlags = LiveObject->GetMaskedFlags(RF_Load);
                SyntheticExport.SerialSize = 0;
                SyntheticExport.SerialOffset = 0;
                SyntheticExport.ScriptSerializationStartOffset = 0;
                SyntheticExport.ScriptSerializationEndOffset = 0;
                SyntheticExport.Object = LiveObject;
                SyntheticExport.HashNext = INDEX_NONE;
                SyntheticExport.bForcedExport = false;
                SyntheticExport.bNotForClient = false;
                SyntheticExport.bNotForServer = false;
                SyntheticExport.bNotAlwaysLoadedForEditorGame = true;
                SyntheticExport.bIsAsset = false;
                SyntheticExport.bIsInheritedInstance = false;
                SyntheticExport.bGeneratePublicHash = true;
                SyntheticExport.bExportLoadFailed = false;
                SyntheticExport.bWasFiltered = false;
                SyntheticExport.PackageFlags = 0;
                SyntheticExport.FirstExportDependency = -1;
                SyntheticExport.SerializationBeforeSerializationDependencies = 0;
                SyntheticExport.CreateBeforeSerializationDependencies = 0;
                SyntheticExport.SerializationBeforeCreateDependencies = 0;
                SyntheticExport.CreateBeforeCreateDependencies = 0;

                Linker->ExportMap.Add(MoveTemp(SyntheticExport));

                FString SyntheticRelativePath;
                const uint64 SyntheticHash =
                    SquadCookedMount::ComputeLinkerLoadExportHash(
                        Linker,
                        NewExportIndex,
                        SyntheticRelativePath);
                if (!SyntheticHash || SyntheticHash != LiveHash)
                {
                    Linker->ExportMap.Pop(EAllowShrinking::No);
                    return INDEX_NONE;
                }

                ObjectToExportIndex.Add(LiveObject, NewExportIndex);
                if (!AmbiguousAllHashes.Contains(SyntheticHash))
                {
                    if (UniqueAllHashExports.Contains(SyntheticHash))
                    {
                        UniqueAllHashExports.Remove(SyntheticHash);
                        AmbiguousAllHashes.Add(SyntheticHash);
                    }
                    else
                    {
                        UniqueAllHashExports.Add(
                            SyntheticHash,
                            NewExportIndex);
                    }
                }
                SyntheticExportObjects.Add(LiveObject);
                return NewExportIndex;
            };

        for (const TPair<uint64, UObject*>& Pair : UniqueMissingLiveObjects)
        {
            const int32 BeforeCount = Linker->ExportMap.Num();
            const int32 RequiredExportIndex =
                EnsureSyntheticExportForLiveObject(Pair.Value);
            const int32 AddedForChain = Linker->ExportMap.Num() - BeforeCount;

            if (RequiredExportIndex == INDEX_NONE)
            {
                ++SyntheticBuildFailures;
                continue;
            }

            FString SyntheticRelativePath;
            const uint64 RegisteredHash =
                SquadCookedMount::ComputeLinkerLoadExportHash(
                    Linker,
                    RequiredExportIndex,
                    SyntheticRelativePath);
            if (RegisteredHash != Pair.Key)
            {
                ++SyntheticBuildFailures;
                continue;
            }

            ++SyntheticRequiredExportCount;
            if (AddedForChain > 1)
            {
                SyntheticSupportExportCount += AddedForChain - 1;
            }
        }

        const int32 SyntheticExportCount =
            Linker->ExportMap.Num() - OriginalLinkerExportCount;
        if (SyntheticExportCount > 0)
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_FIX LINKER_REINDEX SYNTHETIC_EXPORT_BRIDGE_ARMED | reason='%s' | package='%s' | id=0x%016llX | missingRequired=%d | uniqueLive=%d | requiredSynthetic=%d | supportSynthetic=%d | totalAdded=%d | liveAmbiguous=%d | liveAbsent=%d | buildFailures=%d | originalExports=%d"),
                Reason ? Reason : TEXT("<none>"),
                *PackageNameText,
                static_cast<unsigned long long>(PackageId.Value()),
                MissingRequiredHashesBeforeSynthetic.Num(),
                UniqueMissingLiveObjects.Num(),
                SyntheticRequiredExportCount,
                SyntheticSupportExportCount,
                SyntheticExportCount,
                AmbiguousMissingLiveHashes.Num(),
                MissingRequiredHashesBeforeSynthetic.Num() -
                    UniqueMissingLiveObjects.Num() -
                    AmbiguousMissingLiveHashes.Num(),
                SyntheticBuildFailures,
                OriginalLinkerExportCount);
        }

        TArray<int32> TemporarilyClearedLoadFailedExports;
        int32 SkippedFailedExportNoObject = 0;
        int32 SkippedFailedExportUnreachable = 0;
        int32 SkippedFailedExportWrongPackage = 0;
        for (const TPair<uint64, int32>& Pair : UniqueRequiredHashExports)
        {
            FObjectExport& LinkerExport = Linker->ExportMap[Pair.Value];
            if (!LinkerExport.bExportLoadFailed)
            {
                continue;
            }

            UObject* LiveObject = LinkerExport.Object;
            if (!LiveObject)
            {
                ++SkippedFailedExportNoObject;
                continue;
            }
            if (LiveObject->IsUnreachable())
            {
                ++SkippedFailedExportUnreachable;
                continue;
            }
            if (LiveObject->GetOutermost() != Package)
            {
                ++SkippedFailedExportWrongPackage;
                continue;
            }

            LinkerExport.bExportLoadFailed = false;
            TemporarilyClearedLoadFailedExports.Add(Pair.Value);
        }

        if (!TemporarilyClearedLoadFailedExports.IsEmpty())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_FIX LINKER_REINDEX FAILED_EXPORT_BRIDGE_ARMED | reason='%s' | package='%s' | id=0x%016llX | promoted=%d | ambiguous=%d | noObject=%d | unreachable=%d | wrongPackage=%d"),
                Reason ? Reason : TEXT("<none>"),
                *PackageNameText,
                static_cast<unsigned long long>(PackageId.Value()),
                TemporarilyClearedLoadFailedExports.Num(),
                AmbiguousRequiredHashes.Num(),
                SkippedFailedExportNoObject,
                SkippedFailedExportUnreachable,
                SkippedFailedExportWrongPackage);
        }

        const bool bWasFullyLoaded = Package->bHasBeenFullyLoaded != 0;
        const bool bHadWasLoadedFlag = Package->HasAnyFlags(RF_WasLoaded);

        // Public UE5.7 API. Unlike the v2 direct bit write this clears both
        // bHasBeenFullyLoaded and RF_WasLoaded. That prevents the already-loaded
        // shortcut from winning before the hybrid LinkerLoad path gets a chance
        // to call StoreGlobalObject for existing linker exports.
        Package->MarkAsUnloaded();
        ++MarkedUnloaded;

        // Verify while the async package still owns its package ref. UE5.7
        // clears EInternalObjectFlags::LoaderImport when the last package ref
        // is released, so checking it after FlushAsyncLoading would produce a
        // false negative even when StoreGlobalObject populated PublicExportMap.
        bool bCompletionCalled = false;
        bool bCompletionSucceeded = false;
        bool bCompletionSamePackage = false;
        bool bCompletionVerified = false;
        bool bTemporaryFailedFlagsRestored = false;
        bool bSyntheticExportsRestored = SyntheticExportCount == 0;
        bool bSyntheticTailMismatch = false;
        int32 CompletionResolved = 0;
        int32 CompletionLoaderImports = 0;
        int32 CompletionMissingObjects = 0;
        FLinkerLoad* const OriginalLinker = Linker;

        FLoadPackageAsyncDelegate VerificationDelegate =
            FLoadPackageAsyncDelegate::CreateLambda(
                [Package, RequiredHashes, OriginalLinker,
                 TemporarilyClearedLoadFailedExports,
                 OriginalLinkerExportCount, SyntheticExportObjects,
                 SyntheticExportCount,
                 &bCompletionCalled, &bCompletionSucceeded,
                 &bCompletionSamePackage, &bCompletionVerified,
                 &bTemporaryFailedFlagsRestored,
                 &bSyntheticExportsRestored, &bSyntheticTailMismatch,
                 &CompletionResolved, &CompletionLoaderImports,
                 &CompletionMissingObjects](
                    const FName& LoadedPackageName,
                    UPackage* LoadedPackage,
                    EAsyncLoadingResult::Type Result)
                {
                    bCompletionCalled = true;
                    bCompletionSucceeded =
                        Result == EAsyncLoadingResult::Succeeded;
                    bCompletionSamePackage = LoadedPackage == Package;

                    FLinkerLoad* CompletionLinker =
                        LoadedPackage ? LoadedPackage->GetLinker() : nullptr;

                    if (bCompletionSucceeded && bCompletionSamePackage &&
                        CompletionLinker)
                    {
                        TSet<uint64> Remaining = *RequiredHashes;
                        for (int32 ExportIndex = 0;
                             ExportIndex < CompletionLinker->ExportMap.Num() &&
                             !Remaining.IsEmpty();
                             ++ExportIndex)
                        {
                            FString RelativePath;
                            const uint64 Hash =
                                SquadCookedMount::ComputeLinkerLoadExportHash(
                                    CompletionLinker,
                                    ExportIndex,
                                    RelativePath);
                            if (!Remaining.Remove(Hash))
                            {
                                continue;
                            }

                            ++CompletionResolved;
                            UObject* Object =
                                CompletionLinker->ExportMap[ExportIndex].Object;
                            if (!Object)
                            {
                                ++CompletionMissingObjects;
                                continue;
                            }
                            if (Object->HasAnyInternalFlags(
                                    EInternalObjectFlags::LoaderImport))
                            {
                                ++CompletionLoaderImports;
                            }
                        }

                        bCompletionVerified =
                            CompletionResolved == RequiredHashes->Num() &&
                            CompletionLoaderImports == RequiredHashes->Num() &&
                            CompletionMissingObjects == 0;
                    }

                    // Restore editor LinkerLoad metadata before AsyncPackage is
                    // released. The GlobalImportStore mapping written by the
                    // stock hybrid loader is independent from this diagnostic
                    // failure bit and remains available to external Zen imports.
                    if (OriginalLinker)
                    {
                        for (const int32 ExportIndex :
                             TemporarilyClearedLoadFailedExports)
                        {
                            if (OriginalLinker->ExportMap.IsValidIndex(ExportIndex))
                            {
                                OriginalLinker->ExportMap[ExportIndex].bExportLoadFailed = true;
                            }
                        }
                    }
                    bTemporaryFailedFlagsRestored = true;

                    if (OriginalLinker && SyntheticExportCount > 0)
                    {
                        bool bTailMatches =
                            OriginalLinker->ExportMap.Num() ==
                                OriginalLinkerExportCount + SyntheticExportCount &&
                            SyntheticExportObjects.Num() == SyntheticExportCount;
                        if (bTailMatches)
                        {
                            for (int32 SyntheticIndex = 0;
                                 SyntheticIndex < SyntheticExportCount;
                                 ++SyntheticIndex)
                            {
                                const int32 ExportIndex =
                                    OriginalLinkerExportCount + SyntheticIndex;
                                if (!OriginalLinker->ExportMap.IsValidIndex(ExportIndex) ||
                                    OriginalLinker->ExportMap[ExportIndex].Object !=
                                        SyntheticExportObjects[SyntheticIndex])
                                {
                                    bTailMatches = false;
                                    break;
                                }
                            }
                        }

                        if (bTailMatches)
                        {
                            OriginalLinker->ExportMap.SetNum(
                                OriginalLinkerExportCount,
                                EAllowShrinking::No);
                            bSyntheticExportsRestored = true;
                        }
                        else
                        {
                            bSyntheticTailMismatch = true;
                            bCompletionVerified = false;
                        }
                    }
                });

        const int32 RefreshRequestId = LoadPackageAsync(
            PackageNameText,
            MoveTemp(VerificationDelegate));
        if (RefreshRequestId != INDEX_NONE)
        {
            FlushAsyncLoading(RefreshRequestId);
        }

        // If the request could not reach its completion callback, still put
        // LinkerLoad metadata back exactly as we found it. This is deliberately
        // fail-closed: no failed-export promotion is allowed to leak beyond the
        // single reindex attempt.
        if (!bTemporaryFailedFlagsRestored && OriginalLinker)
        {
            for (const int32 ExportIndex : TemporarilyClearedLoadFailedExports)
            {
                if (OriginalLinker->ExportMap.IsValidIndex(ExportIndex))
                {
                    OriginalLinker->ExportMap[ExportIndex].bExportLoadFailed = true;
                }
            }
            bTemporaryFailedFlagsRestored = true;
        }

        if (!bSyntheticExportsRestored && OriginalLinker &&
            SyntheticExportCount > 0)
        {
            bool bTailMatches =
                OriginalLinker->ExportMap.Num() ==
                    OriginalLinkerExportCount + SyntheticExportCount &&
                SyntheticExportObjects.Num() == SyntheticExportCount;
            if (bTailMatches)
            {
                for (int32 SyntheticIndex = 0;
                     SyntheticIndex < SyntheticExportCount;
                     ++SyntheticIndex)
                {
                    const int32 ExportIndex =
                        OriginalLinkerExportCount + SyntheticIndex;
                    if (!OriginalLinker->ExportMap.IsValidIndex(ExportIndex) ||
                        OriginalLinker->ExportMap[ExportIndex].Object !=
                            SyntheticExportObjects[SyntheticIndex])
                    {
                        bTailMatches = false;
                        break;
                    }
                }
            }
            if (bTailMatches)
            {
                OriginalLinker->ExportMap.SetNum(
                    OriginalLinkerExportCount,
                    EAllowShrinking::No);
                bSyntheticExportsRestored = true;
            }
            else
            {
                bSyntheticTailMismatch = true;
            }
        }

        UPackage* RefreshedPackage = FindPackage(nullptr, *PackageNameText);
        const bool bRefreshSucceeded =
            RefreshRequestId != INDEX_NONE &&
            bCompletionCalled &&
            bCompletionSucceeded &&
            bCompletionSamePackage &&
            RefreshedPackage == Package &&
            Package->bHasBeenFullyLoaded != 0 &&
            Package->HasAnyFlags(RF_WasLoaded) &&
            !Package->HasAnyFlags(RF_NeedLoad | RF_NeedPostLoad) &&
            bSyntheticExportsRestored &&
            !bSyntheticTailMismatch;

        if (!bRefreshSucceeded)
        {
            ++FailedRefreshes;
            if (bWasFullyLoaded && !Package->bHasBeenFullyLoaded)
            {
                Package->MarkAsFullyLoaded();
            }
            if (bHadWasLoadedFlag && !Package->HasAnyFlags(RF_WasLoaded))
            {
                Package->SetFlags(RF_WasLoaded);
            }

            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("SCM_FIX LINKER_REINDEX PACKAGE_FAIL | reason='%s' | package='%s' | id=0x%016llX | request=%d | samePackage=%s | fullyLoaded=%s | wasLoaded=%s | syntheticRestored=%s | syntheticTailMismatch=%s"),
                Reason ? Reason : TEXT("<none>"),
                *PackageNameText,
                static_cast<unsigned long long>(PackageId.Value()),
                RefreshRequestId,
                RefreshedPackage == Package ? TEXT("YES") : TEXT("NO"),
                Package->bHasBeenFullyLoaded ? TEXT("YES") : TEXT("NO"),
                Package->HasAnyFlags(RF_WasLoaded) ? TEXT("YES") : TEXT("NO"),
                bSyntheticExportsRestored ? TEXT("YES") : TEXT("NO"),
                bSyntheticTailMismatch ? TEXT("YES") : TEXT("NO"));
            continue;
        }

        ++RefreshedPackages;

        // Completion-time values were sampled before AsyncPackage->Release(),
        // while LoaderImport pins were still active. They therefore distinguish
        // a real StoreGlobalObject pass from the already-loaded empty-map
        // shortcut that made v2's refreshed=N counter misleading.
        ResolvedHashCount += CompletionResolved;
        LoaderImportHashCount += CompletionLoaderImports;

        if (bCompletionVerified)
        {
            ++VerifiedPackages;
            if (SyntheticExportCount > 0)
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Display,
                    TEXT("SCM_FIX LINKER_REINDEX SYNTHETIC_EXPORT_BRIDGE_VERIFIED | reason='%s' | package='%s' | id=0x%016llX | requiredSynthetic=%d | supportSynthetic=%d | totalAdded=%d | requiredHashes=%d | loaderImports=%d | restored=%s"),
                    Reason ? Reason : TEXT("<none>"),
                    *PackageNameText,
                    static_cast<unsigned long long>(PackageId.Value()),
                    SyntheticRequiredExportCount,
                    SyntheticSupportExportCount,
                    SyntheticExportCount,
                    RequiredHashes->Num(),
                    CompletionLoaderImports,
                    bSyntheticExportsRestored ? TEXT("YES") : TEXT("NO"));
            }
            if (!TemporarilyClearedLoadFailedExports.IsEmpty())
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Display,
                    TEXT("SCM_FIX LINKER_REINDEX FAILED_EXPORT_BRIDGE_VERIFIED | reason='%s' | package='%s' | id=0x%016llX | promoted=%d | requiredHashes=%d | loaderImports=%d | restored=YES"),
                    Reason ? Reason : TEXT("<none>"),
                    *PackageNameText,
                    static_cast<unsigned long long>(PackageId.Value()),
                    TemporarilyClearedLoadFailedExports.Num(),
                    RequiredHashes->Num(),
                    CompletionLoaderImports);
            }
            else
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Verbose,
                    TEXT("SCM_FIX LINKER_REINDEX PACKAGE_VERIFIED | reason='%s' | package='%s' | id=0x%016llX | requiredHashes=%d | loaderImports=%d | linkerExports=%d | phase=COMPLETION"),
                    Reason ? Reason : TEXT("<none>"),
                    *PackageNameText,
                    static_cast<unsigned long long>(PackageId.Value()),
                    RequiredHashes->Num(),
                    CompletionLoaderImports,
                    Package->GetLinker() ? Package->GetLinker()->ExportMap.Num() : 0);
            }
        }
        else
        {
            ++FailedVerification;

            // v6 fallback diagnostic. The synthetic bridge above should have
            // registered every unique live match. Anything still unresolved at
            // this point is ambiguous, genuinely absent, or a synthetic-tail
            // build/restore failure. Re-scan read-only so the log preserves the
            // exact remaining hash state without attempting a second mutation.
            TSet<uint64> MissingRequiredHashes = *RequiredHashes;
            if (OriginalLinker)
            {
                for (int32 ExportIndex = 0;
                     ExportIndex < OriginalLinker->ExportMap.Num() &&
                     !MissingRequiredHashes.IsEmpty();
                     ++ExportIndex)
                {
                    FString RelativePath;
                    const uint64 Hash =
                        SquadCookedMount::ComputeLinkerLoadExportHash(
                            OriginalLinker,
                            ExportIndex,
                            RelativePath);
                    MissingRequiredHashes.Remove(Hash);
                }
            }

            TMap<uint64, UObject*> UniqueLiveHashObjects;
            TMap<uint64, FString> UniqueLiveHashPaths;
            TSet<uint64> AmbiguousLiveHashes;
            if (!MissingRequiredHashes.IsEmpty())
            {
                ForEachObjectWithOuter(
                    Package,
                    [Package, &MissingRequiredHashes,
                     &UniqueLiveHashObjects, &UniqueLiveHashPaths,
                     &AmbiguousLiveHashes](UObject* Object)
                    {
                        if (!Object || Object->IsUnreachable() ||
                            Object->GetOutermost() != Package)
                        {
                            return;
                        }

                        FString RelativePath;
                        const uint64 Hash =
                            SquadCookedMount::ComputeLiveObjectExportHash(
                                Object,
                                Package,
                                RelativePath);
                        if (!Hash || !MissingRequiredHashes.Contains(Hash) ||
                            AmbiguousLiveHashes.Contains(Hash))
                        {
                            return;
                        }

                        if (UniqueLiveHashObjects.Contains(Hash))
                        {
                            UniqueLiveHashObjects.Remove(Hash);
                            UniqueLiveHashPaths.Remove(Hash);
                            AmbiguousLiveHashes.Add(Hash);
                            return;
                        }

                        UniqueLiveHashObjects.Add(Hash, Object);
                        UniqueLiveHashPaths.Add(Hash, MoveTemp(RelativePath));
                    },
                    /* bIncludeNestedObjects */ true);
            }

            int32 LiveMatchedHashes = 0;
            int32 LiveAmbiguousHashes = 0;
            int32 LiveAbsentHashes = 0;
            for (const uint64 MissingHash : MissingRequiredHashes)
            {
                if (UObject* const* LiveObjectPtr =
                        UniqueLiveHashObjects.Find(MissingHash))
                {
                    UObject* LiveObject = *LiveObjectPtr;
                    ++LiveMatchedHashes;
                    const FString* RelativePath =
                        UniqueLiveHashPaths.Find(MissingHash);
                    UE_LOG(
                        LogSquadCookedMount,
                        Display,
                        TEXT("SCM_DIAG LINKER_REINDEX UNRESOLVED_HASH_LIVE_MATCH | package='%s' | id=0x%016llX | hash=0x%016llX | relativePath='%s' | object='%s' | class='%s' | linkerIndex=%d | objectLinker='%s' | flags=0x%08X | internalFlags=0x%08X"),
                        *PackageNameText,
                        static_cast<unsigned long long>(PackageId.Value()),
                        static_cast<unsigned long long>(MissingHash),
                        RelativePath ? **RelativePath : TEXT("<none>"),
                        *LiveObject->GetPathName(),
                        *LiveObject->GetClass()->GetPathName(),
                        LiveObject->GetLinkerIndex(),
                        LiveObject->GetLinker()
                            ? *LiveObject->GetLinker()->GetDebugName()
                            : TEXT("<none>"),
                        static_cast<uint32>(LiveObject->GetFlags()),
                        static_cast<uint32>(LiveObject->GetInternalFlags()));
                }
                else if (AmbiguousLiveHashes.Contains(MissingHash))
                {
                    ++LiveAmbiguousHashes;
                    UE_LOG(
                        LogSquadCookedMount,
                        Warning,
                        TEXT("SCM_DIAG LINKER_REINDEX UNRESOLVED_HASH_LIVE_AMBIGUOUS | package='%s' | id=0x%016llX | hash=0x%016llX"),
                        *PackageNameText,
                        static_cast<unsigned long long>(PackageId.Value()),
                        static_cast<unsigned long long>(MissingHash));
                }
                else
                {
                    ++LiveAbsentHashes;
                    UE_LOG(
                        LogSquadCookedMount,
                        Warning,
                        TEXT("SCM_DIAG LINKER_REINDEX UNRESOLVED_HASH_LIVE_ABSENT | package='%s' | id=0x%016llX | hash=0x%016llX"),
                        *PackageNameText,
                        static_cast<unsigned long long>(PackageId.Value()),
                        static_cast<unsigned long long>(MissingHash));
                }
            }

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("SCM_DIAG LINKER_REINDEX UNRESOLVED_HASH_SCAN | package='%s' | id=0x%016llX | missingRequired=%d | liveMatched=%d | liveAmbiguous=%d | liveAbsent=%d | mutation=NO"),
                *PackageNameText,
                static_cast<unsigned long long>(PackageId.Value()),
                MissingRequiredHashes.Num(),
                LiveMatchedHashes,
                LiveAmbiguousHashes,
                LiveAbsentHashes);

            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("SCM_FIX LINKER_REINDEX PACKAGE_UNVERIFIED | reason='%s' | package='%s' | id=0x%016llX | requiredHashes=%d | resolvedHashes=%d | loaderImports=%d | missingObjects=%d | promotedFailedExports=%d | completionCalled=%s | completionResult=%s | retry=NO"),
                Reason ? Reason : TEXT("<none>"),
                *PackageNameText,
                static_cast<unsigned long long>(PackageId.Value()),
                RequiredHashes->Num(),
                CompletionResolved,
                CompletionLoaderImports,
                CompletionMissingObjects,
                TemporarilyClearedLoadFailedExports.Num(),
                bCompletionCalled ? TEXT("YES") : TEXT("NO"),
                bCompletionSucceeded ? TEXT("SUCCEEDED") : TEXT("FAILED"));
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_FIX LINKER_REINDEX PASS | reason='%s' | requested=%d | loaded=%d | linker=%d | alreadyAttempted=%d | alreadyVerified=%d | markedUnloaded=%d | refreshed=%d | verified=%d | refreshFailed=%d | verifyFailed=%d | busy=%d | nameMisses=%d | requiredHashes=%d | resolvedHashes=%d | loaderImportHashes=%d | editorStockSkipped=%d | editorSpecialCandidates=%d | editorSuperOverlayHashSkipped=%d | editorFailedUFunctionHashSkipped=%d | editorSyntheticUFunctionHashSkipped=%d | repeatMutation=NO"),
        Reason ? Reason : TEXT("<none>"),
        WorkIds.Num(),
        LoadedCandidates,
        LinkerCandidates,
        AlreadyAttempted,
        AlreadyVerified,
        MarkedUnloaded,
        RefreshedPackages,
        VerifiedPackages,
        FailedRefreshes,
        FailedVerification,
        BusyPackages,
        NameMisses,
        RequiredHashCount,
        ResolvedHashCount,
        LoaderImportHashCount,
        EditorStockSkipped,
        EditorSpecialCandidates,
        EditorSuperOverlayHashSkipped,
        EditorFailedUFunctionHashSkipped,
        EditorSyntheticUFunctionHashSkipped);

    return VerifiedPackages;
#else
    return 0;
#endif
}

void FSquadCookedMountModule::PrepareCrossLoaderParentsForExternalPackage(
    const FString& PackageName,
    const TCHAR* Reason)
{
#if WITH_EDITOR
    if (!bCrossLoaderImportIndexReady || bCrossLoaderRefreshInProgress ||
        PackageName.IsEmpty())
    {
        return;
    }

    const FName PackageFName(*PackageName);
    FPackageId ExternalPackageId;
    if (const FPackageId* KnownId = ExternalPackageNameToId.Find(PackageFName))
    {
        ExternalPackageId = *KnownId;
    }
    else
    {
        ExternalPackageId = FPackageId::FromName(PackageFName);
    }

    const TArray<FPackageId>* Parents =
        ExternalPackageCrossLoaderParents.Find(ExternalPackageId);
    if (!Parents || Parents->IsEmpty())
    {
        return;
    }

    int32 StockUFunctionParentsRequested = 0;
    int32 StockUFunctionParentsLoaded = 0;
    int32 StockUFunctionParentsAlreadyLoaded = 0;
    int32 StockUFunctionParentLoadFailed = 0;

    if (!bCookCommandletMode)
    {
        // Only UFunction::SuperStruct parents are synchronously first-loaded.
        // Their real regenerated UFunction must exist before the external Zen
        // header is converted to a ScriptImport. Ordinary template/class
        // parents are not force-loaded; AsyncLoading2 retains their normal
        // dependency ordering and we only normalize them when already live.
        const TArray<FPackageId>* FunctionSuperParents =
            ExternalPackageStockUFunctionSuperParents.Find(ExternalPackageId);
        if (FunctionSuperParents && !FunctionSuperParents->IsEmpty())
        {
            TGuardValue<bool> ParentLoadGuard(
                bCrossLoaderRefreshInProgress,
                true);

            for (const FPackageId ParentPackageId : *FunctionSuperParents)
            {
                ++StockUFunctionParentsRequested;

                FName ParentPackageName = NAME_None;
                if (const FName* KnownName =
                        CrossLoaderParentPackageNames.Find(ParentPackageId))
                {
                    ParentPackageName = *KnownName;
                }
#if WITH_PACKAGEID_NAME_MAP
                if (ParentPackageName.IsNone())
                {
                    ParentPackageName = ParentPackageId.GetName();
                }
#endif
                if (ParentPackageName.IsNone())
                {
                    ++StockUFunctionParentLoadFailed;
                    continue;
                }

                const FString ParentPackageNameText = ParentPackageName.ToString();
                if (ParentPackageNameText.StartsWith(
                        TEXT("/Script/"),
                        ESearchCase::IgnoreCase))
                {
                    ++StockUFunctionParentsAlreadyLoaded;
                    continue;
                }

                if (FindPackage(nullptr, *ParentPackageNameText))
                {
                    ++StockUFunctionParentsAlreadyLoaded;
                    continue;
                }

                UPackage* LoadedParent = LoadPackage(
                    nullptr,
                    *ParentPackageNameText,
                    LOAD_None);
                if (LoadedParent)
                {
                    ++StockUFunctionParentsLoaded;
                }
                else
                {
                    ++StockUFunctionParentLoadFailed;
                }
            }
        }
    }

    // Do NOT refresh/reload stock packages that provide UFunction::SuperStruct.
    // The live UFunction bridge below resolves the authoritative class-owned
    // function directly. MarkAsUnloaded/LinkerLoad refresh on such a Blueprint
    // can regenerate its class/functions and invalidate the object identity we
    // are about to bind. Non-UFunction parents retain the existing bridge.
    TArray<FPackageId> ParentsToRefresh;
    ParentsToRefresh.Reserve(Parents->Num());
    const TArray<FPackageId>* FunctionSuperParentsForRefresh =
        ExternalPackageStockUFunctionSuperParents.Find(ExternalPackageId);
    for (const FPackageId ParentPackageId : *Parents)
    {
        if (!FunctionSuperParentsForRefresh ||
            !FunctionSuperParentsForRefresh->Contains(ParentPackageId))
        {
            ParentsToRefresh.Add(ParentPackageId);
        }
    }

    const int32 RefreshedParents = ParentsToRefresh.IsEmpty()
        ? 0
        : RefreshLoadedLinkerPackagesForZenImports(
            &ParentsToRefresh,
            Reason ? Reason : TEXT("ExternalLoad"),
            /*bForceSyncRefresh=*/true);

    bool bOverlayPrepared = false;
    if (!bCookCommandletMode)
    {
        // Convert only exact UFunction SuperStruct imports used by this package.
        // Do not widen the mutation to other failed stock UFunctions.
        bOverlayPrepared = PrepareGenericBlueprintSuperOverlayForPackage(
            PackageName,
            /*bAllowKnownFailedStockUFunctionImports=*/false);
    }

    if (StockUFunctionParentsRequested > 0 || RefreshedParents > 0 ||
        bOverlayPrepared || SquadCookedMount::IsVerboseSCMDiagnosticsEnabled())
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("SCM_FIX CROSS_LOADER_JIT_PREFLIGHT | package='%s' | reason='%s' | crossParents=%d | functionSuperParents=%d | firstLoaded=%d | alreadyLoaded=%d | loadFailed=%d | refreshedParents=%d | overlayPrepared=%s | surrogateUFunctions=NO"),
            *PackageName,
            Reason ? Reason : TEXT("<none>"),
            Parents->Num(),
            StockUFunctionParentsRequested,
            StockUFunctionParentsLoaded,
            StockUFunctionParentsAlreadyLoaded,
            StockUFunctionParentLoadFailed,
            RefreshedParents,
            bOverlayPrepared ? TEXT("YES") : TEXT("NO"));
    }
#endif
}

void FSquadCookedMountModule::OnPreBeginPIE(const bool bIsSimulating)
{
#if WITH_EDITOR
    if (bCookCommandletMode)
    {
        return;
    }

    // Lifecycle guard: never run another broad package mutation here. The
    // editor startup pass repairs packages that were already loaded before
    // external Zen became active; later newly-loaded parents are handled JIT
    // by PrepareCrossLoaderParentsForExternalPackage. This makes the bridge stable
    // across repeated PIE teardown / duplication / GC cycles.
    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("SCM_FIX LINKER_REINDEX PreBeginPIE_SAFE | simulating=%s | initialRefreshDone=%s | broadRefresh=SKIPPED | repeatMutation=NO"),
        bIsSimulating ? TEXT("YES") : TEXT("NO"),
        bCrossLoaderInitialEditorRefreshDone ? TEXT("YES") : TEXT("NO"));
#endif
}


bool FSquadCookedMountModule::BuildCookEarlyTriggerFromIoStoreMetadata(
    const FAssetRegistryState& ExternalState)
{
    CookEarlyTriggerPackageNames.Reset();

    // This is a read-only scan. DiscoverBaseGameContainersForCook only finds
    // retail .pak/.utoc/.ucas triplets; it does not mount them.
    if (!DiscoverBaseGameContainersForCook())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK IoStore trigger graph: retail Squad containers were not found."));
        return false;
    }

    const FString ModsDir =
        FPaths::Combine(FPaths::ProjectDir(), SquadCookedMount::CookedModsFolderName);

    TArray<FString> AllExternalPaks;
    IFileManager::Get().FindFilesRecursive(
        AllExternalPaks,
        *ModsDir,
        TEXT("*.pak"),
        true,
        false,
        false);
    AllExternalPaks.Sort();

    TArray<FString> SelectedExternalPaks;
    for (const FString& PakPath : AllExternalPaks)
    {
        const FString CleanName = FPaths::GetCleanFilename(PakPath);
        if (PakNameFilter.IsEmpty() ||
            CleanName.Contains(PakNameFilter, ESearchCase::IgnoreCase))
        {
            SelectedExternalPaks.Add(PakPath);
        }
    }

    TArray<FCookZenContainerSource> Sources;
    uint32 Sequence = 0;
    for (const FString& PakPath : CookBasePakPaths)
    {
        AddCookContainerSourcesForPak(PakPath, 0, Sequence, Sources);
    }
    for (const FString& PakPath : SelectedExternalPaks)
    {
        AddCookContainerSourcesForPak(PakPath, 100, Sequence, Sources);
    }

    Sources.Sort(
        [](const FCookZenContainerSource& A, const FCookZenContainerSource& B)
        {
            if (A.Order != B.Order)
            {
                return A.Order > B.Order;
            }
            return A.Sequence > B.Sequence;
        });

    if (Sources.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK IoStore trigger graph: no ContainerHeader sources were found."));
        return false;
    }

    TMap<FPackageId, FCookZenSnapshotEntry> AllEntries;
    TMap<FPackageId, TArray<FPackageId>> OptionalImports;
    TMap<FPackageId, FCookZenRedirect> AllRedirects;
    int32 ParsedContainers = 0;
    int32 FailedContainers = 0;
    int32 TotalNewEntries = 0;

    for (const FCookZenContainerSource& Source : Sources)
    {
        FIoContainerHeader Header;
        FString Error;
        if (!ReadCookContainerHeader(Source.UtocPath, Header, Error))
        {
            ++FailedContainers;
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("COOK IoStore trigger graph: failed ContainerHeader | order=%d seq=%u | '%s' | %s"),
                Source.Order,
                Source.Sequence,
                *Source.UtocPath,
                *Error);
            continue;
        }

        int32 NewEntries = 0;
        if (!CopyCookContainerEntries(
                Source,
                Header,
                AllEntries,
                OptionalImports,
                AllRedirects,
                NewEntries))
        {
            ++FailedContainers;
            continue;
        }

        ++ParsedContainers;
        TotalNewEntries += NewEntries;
    }

#if WITH_EDITOR
    for (TPair<FPackageId, TArray<FPackageId>>& Pair : OptionalImports)
    {
        if (FCookZenSnapshotEntry* Entry = AllEntries.Find(Pair.Key))
        {
            Entry->Data.OptionalSegmentImportedPackageIds = MoveTemp(Pair.Value);
            Entry->Data.bHasOptionalSegment = true;
        }
    }
#endif

    if (ParsedContainers == 0 || AllEntries.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK IoStore trigger graph: no package-store metadata was reconstructed."));
        return false;
    }

    // OnSyncLoadPackage gives us a package name, while ContainerHeader stores
    // package IDs. Build a generic ID->name map from the cooked mod registry
    // plus the SDK's current registry; do not hardcode any scenario package.
    TMap<FPackageId, FName> KnownNamesById;
    auto AddKnownName = [&KnownNamesById](FName PackageName)
    {
        if (PackageName.IsNone())
        {
            return;
        }
        const FPackageId PackageId = FPackageId::FromName(PackageName);
        if (PackageId.IsValid() && !KnownNamesById.Contains(PackageId))
        {
            KnownNamesById.Add(PackageId, PackageName);
        }
    };

    ExternalState.EnumerateAllAssets(
        [&AddKnownName](const FAssetData& AssetData)
        {
            AddKnownName(AssetData.PackageName);
        });

    FAssetRegistryModule& AssetRegistryModule =
        FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));
    AssetRegistryModule.Get().EnumerateAllAssets(
        [&AddKnownName](const FAssetData& AssetData)
        {
            AddKnownName(AssetData.PackageName);
            return true;
        });

    TArray<FPackageId> WorkList;
    WorkList.Reserve(CookTargetExternalSeedPackageIds.Num() * 8);
    for (const FPackageId SeedId : CookTargetExternalSeedPackageIds)
    {
        if (SeedId.IsValid())
        {
            WorkList.Add(SeedId);
        }
    }

    TSet<FPackageId> Visited;
    static constexpr int32 MaxTriggerClosureIds = 100000;
    int32 MissingMetadataIds = 0;
    int32 UnmappedClosureIds = 0;
    int32 SkippedEngineOrScript = 0;
    int32 TriggerExternal = 0;
    int32 TriggerGame = 0;
    int32 TriggerOther = 0;

    for (int32 WorkIndex = 0;
         WorkIndex < WorkList.Num() && Visited.Num() < MaxTriggerClosureIds;
         ++WorkIndex)
    {
        const FPackageId PackageId = WorkList[WorkIndex];
        if (!PackageId.IsValid() || Visited.Contains(PackageId))
        {
            continue;
        }
        Visited.Add(PackageId);

        if (const FCookZenRedirect* Redirect = AllRedirects.Find(PackageId))
        {
            if (Redirect->TargetPackageId.IsValid())
            {
                WorkList.Add(Redirect->TargetPackageId);
            }
        }

        const FCookZenSnapshotEntry* Entry = AllEntries.Find(PackageId);
        if (!Entry)
        {
            ++MissingMetadataIds;
            continue;
        }

        for (const FPackageId ImportedId : Entry->Data.ImportedPackageIds)
        {
            if (ImportedId.IsValid())
            {
                WorkList.Add(ImportedId);
            }
        }
#if WITH_EDITOR
        for (const FPackageId ImportedId : Entry->Data.OptionalSegmentImportedPackageIds)
        {
            if (ImportedId.IsValid())
            {
                WorkList.Add(ImportedId);
            }
        }
#endif

        const FName* KnownName = KnownNamesById.Find(PackageId);
        if (!KnownName)
        {
            ++UnmappedClosureIds;
            continue;
        }

        const FString PackageText = KnownName->ToString();
        if (PackageText.StartsWith(TEXT("/Script/"), ESearchCase::IgnoreCase) ||
            PackageText.StartsWith(TEXT("/Engine/"), ESearchCase::IgnoreCase))
        {
            ++SkippedEngineOrScript;
            continue;
        }

        CookEarlyTriggerPackageNames.Add(*KnownName);

        bool bExternal = false;
        for (const FString& Root : CookExternalLongRoots)
        {
            if (PackageText.StartsWith(Root, ESearchCase::IgnoreCase))
            {
                bExternal = true;
                break;
            }
        }

        if (bExternal)
        {
            ++TriggerExternal;
        }
        else if (PackageText.StartsWith(TEXT("/Game/"), ESearchCase::IgnoreCase))
        {
            ++TriggerGame;
        }
        else
        {
            ++TriggerOther;
        }
    }

    if (Visited.Num() >= MaxTriggerClosureIds)
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("COOK IoStore trigger graph: closure hit safety cap of %d package IDs."),
            MaxTriggerClosureIds);
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK IoStore trigger graph READY | seeds=%d | sources=%d parsed=%d failed=%d snapshotEntries=%d discoveredEntries=%d | closureIds=%d mappedTriggers=%d external=%d game=%d other=%d skippedEngineScript=%d unmappedIds=%d missingMetadataIds=%d"),
        CookTargetExternalSeedPackageIds.Num(),
        Sources.Num(),
        ParsedContainers,
        FailedContainers,
        AllEntries.Num(),
        TotalNewEntries,
        Visited.Num(),
        CookEarlyTriggerPackageNames.Num(),
        TriggerExternal,
        TriggerGame,
        TriggerOther,
        SkippedEngineOrScript,
        UnmappedClosureIds,
        MissingMetadataIds);

    if (CookEarlyTriggerPackageNames.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK IoStore trigger graph: no named project/mod packages were resolved from the seed closure."));
        return false;
    }

    return true;
}


bool FSquadCookedMountModule::PrepareCookShaderLibraries()
{
    // CookCommandlet is launched by SquadSDK with -nullrhi. UE 5.7
    // deliberately keeps FShaderCodeLibrary disabled when the process cannot
    // ever render (FApp::CanEverRender() == false). Treat that as the normal
    // cooker path instead of failing the cooked dependency bridge.
    if (!FApp::CanEverRender())
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK shader gate: runtime ShaderCodeLibrary intentionally skipped because FApp::CanEverRender()=false (expected for -nullrhi); continuing with PackageStore/IoStore dependency bridge."));
        return true;
    }

    if (!EnsureBaseShaderArchives())
    {
        return false;
    }

    if (!FShaderCodeLibrary::IsEnabled())
    {
        if (!StageLooseGlobalShaderLibrary())
        {
            UE_LOG(
                LogSquadCookedMount,
                Error,
                TEXT("COOK shader gate: failed to stage the reconstructed Global shader archive."));
            return false;
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK shader gate: initializing runtime ShaderCodeLibrary before IoStore package exposure | shaderPlatform=%d"),
            static_cast<int32>(GMaxRHIShaderPlatform));

        FShaderCodeLibrary::InitForRuntime(GMaxRHIShaderPlatform);
    }

    if (!FShaderCodeLibrary::IsEnabled())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK shader gate: ShaderCodeLibrary is still disabled after Global bootstrap."));
        return false;
    }

    OpenLooseShaderLibrariesForRoot(TEXT("SquadGame"));

    const bool bSquadGameOpen =
        IsLogicalShaderLibraryOpen(
            OpenedShaderLibraries,
            TEXT("SquadGame"));

    if (bSquadGameOpen)
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK shader gate | Global bootstrap=READY | SquadGame=OPEN | totalShaders=%u"),
            FShaderCodeLibrary::GetShaderCount());
    }
    else
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK shader gate | Global bootstrap=READY | SquadGame=MISSING | totalShaders=%u"),
            FShaderCodeLibrary::GetShaderCount());
    }

    return bSquadGameOpen;
}

bool FSquadCookedMountModule::DiscoverBaseGameContainersForCook()
{
    if (!bCookCommandletMode)
    {
        return false;
    }

    const FString ResolvedBasePaksDir = ResolveBaseGamePaksDir();
    if (ResolvedBasePaksDir.IsEmpty())
    {
        return false;
    }

    TArray<FString> BasePakFiles;
    IFileManager::Get().FindFilesRecursive(
        BasePakFiles,
        *ResolvedBasePaksDir,
        TEXT("*.pak"),
        true,
        false,
        false);
    BasePakFiles.Sort();

    CookBasePakPaths.Reset();
    int32 Triplets = 0;

    for (const FString& PakPath : BasePakFiles)
    {
        const FString BasePath = PakPathToContainerBase(PakPath);
        const FString UtocPath = BasePath + TEXT(".utoc");
        const FString UcasPath = BasePath + TEXT(".ucas");
        if (!IFileManager::Get().FileExists(*UtocPath) ||
            !IFileManager::Get().FileExists(*UcasPath))
        {
            continue;
        }

        ++Triplets;
        CookBasePakPaths.Add(PakPath);
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK retail base discovery | dir='%s' | triplets=%d | mounted=0 (passive header scan only)"),
        *ResolvedBasePaksDir,
        Triplets);

    return Triplets > 0;
}

// v0.3.17t: early retail-Zen probe removed. Retail /Game stays LinkerLoad-only before AssetManager completion.

// Cook-only compatibility adapter for *authoritative* regenerated stock objects.
// The normal package-import path remains owned by AsyncLoading2; this function
// never calls MarkAsUnloaded and never manufactures object lifetime flags.
bool FSquadCookedMountModule::PrepareCookCrossLoaderCompatibilityOverlays(
    const TSet<FPackageId>& RepairPackageIds,
    const TMap<FPackageId, FString>& ExpectedSourceUtocs)
{
#if WITH_EDITOR
    if (!bCookCommandletMode || !IsInGameThread() ||
        !FIoDispatcher::IsInitialized() || !bCrossLoaderImportIndexReady)
    {
        return false;
    }

    struct FRequirement
    {
        FPackageId ParentId;
        FName ParentName = NAME_None;
        uint64 Hash = 0;
        bool bFunctionSuper = false;
        bool bTemplate = false;
    };
    struct FHeaderInput
    {
        FPackageId Id;
        FName Name = NAME_None;
        TArray<FPackageId> ImportedIds;
        FString SourceUtoc;
        uint32 HeaderFingerprint = 0;
    };
    struct FLiveBinding
    {
        FPackageObjectIndex ScriptIndex;
        FName PackageName = NAME_None;
        FString RelativePath;
        TStrongObjectPtr<UObject> PinnedObject;
        uint64 PublicHash = 0;
    };

    // Bound cost by the DLC dependency workset. A terminal error is preferable
    // to silently keeping hundreds of thousands of stock Blueprints alive.
    constexpr int32 MaxParentPreloads = 512;
    constexpr int32 MaxScriptBindings = 4096;
    constexpr uint64 MaxStagedBytes = 512ull * 1024ull * 1024ull;
    constexpr uint64 MaxPhysicalIncrease = 3ull * 1024ull * 1024ull * 1024ull;
    const uint64 InitialPhysical = FPlatformMemory::GetStats().UsedPhysical;
    TMap<FString, TUniquePtr<FIoStoreReader>> Readers;
    TMap<FPackageId, FHeaderInput> Headers;
    TMap<FString, FRequirement> Requirements;
    TMap<FString, FLiveBinding> Bindings;
    TMap<FIoChunkId, TArray<uint8>> StagedChunks;
    uint64 StagedBytes = 0;
    int32 ParentsLoaded = 0;
    int32 NormalExports = 0;
    int32 Unresolved = 0;
    int32 PrunedDependencies = 0;

    auto MakeKey = [](FPackageId ParentId, uint64 Hash)
    {
        return FString::Printf(TEXT("%016llX:%016llX"),
            static_cast<unsigned long long>(ParentId.Value()),
            static_cast<unsigned long long>(Hash));
    };

    auto GetReader = [&Readers](const FString& Utoc) -> FIoStoreReader*
    {
        if (TUniquePtr<FIoStoreReader>* Existing = Readers.Find(Utoc))
        {
            return Existing->Get();
        }
        TUniquePtr<FIoStoreReader> NewReader = MakeUnique<FIoStoreReader>();
        TMap<FGuid, FAES::FAESKey> Keys;
        if (!NewReader->Initialize(
                SquadCookedMount::RemoveUtocExtension(Utoc), Keys).IsOk())
        {
            return nullptr;
        }
        FIoStoreReader* Result = NewReader.Get();
        Readers.Add(Utoc, MoveTemp(NewReader));
        return Result;
    };

    auto ReadHeader = [](FIoStoreReader& Reader, FPackageId Id,
                         TArray<uint8>& OutBytes, bool bFullChunk) -> bool
    {
        const FIoChunkId ChunkId = CreatePackageDataChunkId(Id);
        TIoStatusOr<FIoBuffer> SummaryResult = Reader.Read(
            ChunkId, FIoReadOptions(0, sizeof(FZenPackageSummary)));
        if (!SummaryResult.IsOk())
        {
            return false;
        }
        FIoBuffer SummaryBuffer = SummaryResult.ConsumeValueOrDie();
        if (SummaryBuffer.DataSize() < sizeof(FZenPackageSummary))
        {
            return false;
        }
        FZenPackageSummary Summary{};
        FMemory::Memcpy(&Summary, SummaryBuffer.Data(),
            sizeof(Summary));
        if (Summary.HeaderSize < sizeof(Summary) ||
            Summary.HeaderSize > (64u * 1024u * 1024u))
        {
            return false;
        }
        TIoStatusOr<FIoBuffer> Result = Reader.Read(
            ChunkId, bFullChunk ? FIoReadOptions() : FIoReadOptions(0, Summary.HeaderSize));
        if (!Result.IsOk())
        {
            return false;
        }
        FIoBuffer Buffer = Result.ConsumeValueOrDie();
        if (Buffer.DataSize() < Summary.HeaderSize ||
            Buffer.DataSize() > static_cast<uint64>(MAX_int32))
        {
            return false;
        }
        OutBytes.SetNumUninitialized(static_cast<int32>(Buffer.DataSize()));
        FMemory::Memcpy(OutBytes.GetData(), Buffer.Data(), Buffer.DataSize());
        return true;
    };

    const FString FunctionPath = UFunction::StaticClass()->GetPathName();
    const FPackageObjectIndex FunctionClassIndex = FPackageObjectIndex::FromScriptPath(
        FStringView(*FunctionPath, FunctionPath.Len()));

    // Pass 1: immutable provenance + exact structural requirements. Header
    // bytes and their PackageStore import-ID arrays are read from the same
    // high-priority owning container, never from independently chosen paks.
    for (const FPackageId ExternalId : RepairPackageIds)
    {
        const FString* Source = ExpectedSourceUtocs.Find(ExternalId);
        const TArray<FPackageId>* ImportedIds =
            ExternalPackageImportedPackageIds.Find(ExternalId);
        const FString* IndexedSource = ExternalPackageSourceUtocs.Find(ExternalId);
        if (!Source || !ImportedIds || !IndexedSource ||
            !Source->Equals(*IndexedSource, ESearchCase::IgnoreCase) ||
            !GetReader(*Source))
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT SOURCE_MISSING | id=0x%016llX | mutation=NO"),
                static_cast<unsigned long long>(ExternalId.Value()));
            return false;
        }
        TArray<uint8> Data;
        if (!ReadHeader(*GetReader(*Source), ExternalId, Data, false))
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT HEADER_READ_FAILED | id=0x%016llX | utoc='%s'"),
                static_cast<unsigned long long>(ExternalId.Value()), **Source);
            return false;
        }
        SquadCookedMount::FDiagnosticZenHeaderView Header;
        FString ParseError;
        if (!SquadCookedMount::ParseDiagnosticZenHeader(Data, Header, ParseError) ||
            FPackageId::FromName(Header.PackageName) != ExternalId ||
            !SquadCookedMount::ValidateZenDependencyBundleLayout(Header))
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT SOURCE_OR_LAYOUT_MISMATCH | id=0x%016llX | source='%s' | error='%s' | mutation=NO"),
                static_cast<unsigned long long>(ExternalId.Value()), **Source,
                *ParseError);
            return false;
        }

        // If a consumer has already started loading, its import map was
        // captured by AsyncLoading2; publishing a replacement is too late.
        if (UPackage* Existing = FindPackage(nullptr, *Header.PackageName.ToString()))
        {
            if (Existing->bHasBeenFullyLoaded ||
                Existing->HasAnyFlags(RF_WasLoaded | RF_LoadCompleted))
            {
                UE_LOG(LogSquadCookedMount, Error,
                    TEXT("SCM_COMPAT CONSUMER_ALREADY_LOADED | package='%s' | mutation=NO"),
                    *Header.PackageName.ToString());
                return false;
            }
        }
        FHeaderInput& Input = Headers.FindOrAdd(ExternalId);
        Input.Id = ExternalId;
        Input.Name = Header.PackageName;
        Input.SourceUtoc = *Source;
        Input.ImportedIds = *ImportedIds;
        Input.HeaderFingerprint = FCrc::MemCrc32(Data.GetData(), Data.Num());

        bool bMalformedStructuralRef = false;
        auto AddRequirement = [this, &Header, &Input, &Requirements,
                               &MakeKey, &bMalformedStructuralRef](
            FPackageObjectIndex Index, bool bFunctionSuper, bool bTemplate)
        {
            if (!Index.IsPackageImport())
            {
                return;
            }
            const FPackageImportReference Ref = Index.ToPackageImportRef();
            if (!Input.ImportedIds.IsValidIndex(static_cast<int32>(Ref.GetImportedPackageIndex())) ||
                !Header.ImportedPublicExportHashes.IsValidIndex(
                    static_cast<int32>(Ref.GetImportedPublicExportHashIndex())))
            {
                bMalformedStructuralRef = true;
                return;
            }
            const FPackageId ParentId = Input.ImportedIds[Ref.GetImportedPackageIndex()];
            const uint64 Hash = Header.ImportedPublicExportHashes[
                Ref.GetImportedPublicExportHashIndex()];
            if (!ParentId.IsValid() || Hash == 0)
            {
                bMalformedStructuralRef = true;
                return;
            }
            if (SquadCookedMount::GSCMExternalPackageIds.Contains(ParentId))
            {
                return;
            }
            const FString Key = MakeKey(ParentId, Hash);
            FRequirement& Req = Requirements.FindOrAdd(Key);
            Req.ParentId = ParentId;
            Req.Hash = Hash;
            Req.bFunctionSuper |= bFunctionSuper;
            Req.bTemplate |= bTemplate;
            const uint32 PackageIndex = Ref.GetImportedPackageIndex();
            if (Header.ImportedPackageNames.IsValidIndex(
                    static_cast<int32>(PackageIndex)))
            {
                const FName ClaimedParentName =
                    Header.ImportedPackageNames[PackageIndex];
                if (!Req.ParentName.IsNone() &&
                    !ClaimedParentName.IsNone() &&
                    Req.ParentName != ClaimedParentName)
                {
                    bMalformedStructuralRef = true;
                }
                if (!ClaimedParentName.IsNone())
                {
                    Req.ParentName = ClaimedParentName;
                }
            }
            if (Req.ParentName.IsNone())
            {
                if (const FName* Name = CrossLoaderParentPackageNames.Find(ParentId))
                {
                    Req.ParentName = *Name;
                }
            }
#if WITH_PACKAGEID_NAME_MAP
            if (Req.ParentName.IsNone())
            {
                Req.ParentName = ParentId.GetName();
            }
#endif
        };
        for (const FExportMapEntry& Export : Header.ExportMap)
        {
            // Parent construction metadata only; ordinary serialization imports
            // remain in native PackageImport form unless they share these keys.
            AddRequirement(Export.TemplateIndex, false, true);
            if (Export.ClassIndex == FunctionClassIndex)
            {
                AddRequirement(Export.SuperIndex, true, false);
            }
        }
        if (bMalformedStructuralRef)
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT STRUCTURAL_IMPORT_INVALID | package='%s' | source='%s' | mutation=NO"),
                *Header.PackageName.ToString(), *Input.SourceUtoc);
            return false;
        }
    }

    // Pass 2: load only structural stock parents, exactly once, then resolve
    // identity. Loading 10k parent packages is explicitly prohibited.
    TMap<FPackageId, UPackage*> ParentPackages;
    // Preloading a later parent can trigger GC. Keep already loaded parent
    // UPackage identities stable through all three validation passes; these
    // local references are released on success and on every failure path.
    TMap<FPackageId, TStrongObjectPtr<UPackage>> ParentPackagePins;
    for (const TPair<FString, FRequirement>& Pair : Requirements)
    {
        const FRequirement& Req = Pair.Value;
        if (ParentPackages.Contains(Req.ParentId))
        {
            continue;
        }
        if (Req.ParentName.IsNone() ||
            FPackageId::FromName(Req.ParentName) != Req.ParentId ||
            ParentPackages.Num() >= MaxParentPreloads)
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT PARENT_IDENTITY_OR_BUDGET_FAILED | id=0x%016llX | name='%s' | budget=%d | mutation=NO"),
                static_cast<unsigned long long>(Req.ParentId.Value()),
                *Req.ParentName.ToString(), MaxParentPreloads);
            return false;
        }
        UPackage* Parent = FindPackage(nullptr, *Req.ParentName.ToString());
        if (!Parent || !Parent->bHasBeenFullyLoaded)
        {
            Parent = LoadPackage(nullptr, *Req.ParentName.ToString(), LOAD_None);
            ++ParentsLoaded;
        }
        if (!Parent || Parent->IsUnreachable() ||
            FPackageId::FromName(Parent->GetFName()) != Req.ParentId)
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT PARENT_LOAD_FAILED | parent='%s' | id=0x%016llX | mutation=NO"),
                *Req.ParentName.ToString(),
                static_cast<unsigned long long>(Req.ParentId.Value()));
            return false;
        }
        ParentPackages.Add(Req.ParentId, Parent);
        ParentPackagePins.Add(Req.ParentId, TStrongObjectPtr<UPackage>(Parent));
        const uint64 CurrentPhysical = FPlatformMemory::GetStats().UsedPhysical;
        if (CurrentPhysical > InitialPhysical &&
            CurrentPhysical - InitialPhysical > MaxPhysicalIncrease)
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT PHYSICAL_MEMORY_BUDGET_EXCEEDED | deltaMiB=%llu | budgetMiB=3072 | mutation=NO"),
                static_cast<unsigned long long>(
                    (CurrentPhysical - InitialPhysical) / (1024ull * 1024ull)));
            return false;
        }
    }

    struct FParentIndex
    {
        TSet<uint64> NormalLinkerHashes;
        TMap<uint64, UObject*> UniqueLive;
        TSet<uint64> AmbiguousLive;
    };
    TMap<FPackageId, TSet<uint64>> NeededHashes;
    for (const TPair<FString, FRequirement>& Pair : Requirements)
    {
        NeededHashes.FindOrAdd(Pair.Value.ParentId).Add(Pair.Value.Hash);
    }
    TMap<FPackageId, FParentIndex> ParentIndices;
    for (const TPair<FPackageId, UPackage*>& ParentPair : ParentPackages)
    {
        UPackage* Parent = ParentPair.Value;
        const TSet<uint64>* Needed = NeededHashes.Find(ParentPair.Key);
        if (!Needed)
        {
            continue;
        }
        FParentIndex& Index = ParentIndices.FindOrAdd(ParentPair.Key);
        if (FLinkerLoad* Linker = Parent->GetLinker())
        {
            for (int32 i = 0; i < Linker->ExportMap.Num(); ++i)
            {
                if (Linker->ExportMap[i].bExportLoadFailed)
                {
                    continue;
                }
                FString Path;
                const uint64 Hash =
                    SquadCookedMount::ComputeLinkerLoadExportHash(Linker, i, Path);
                if (Needed->Contains(Hash))
                {
                    Index.NormalLinkerHashes.Add(Hash);
                }
            }
        }
        ForEachObjectWithOuter(Parent,
            [Parent, Needed, &Index](UObject* Object)
            {
                if (!Object || Object->IsUnreachable() ||
                    Object->GetOutermost() != Parent ||
                    Object->HasAnyFlags(RF_NeedLoad | RF_BeingRegenerated | RF_NewerVersionExists))
                {
                    return;
                }
                FString Path;
                const uint64 Hash =
                    SquadCookedMount::ComputeLiveObjectExportHash(Object, Parent, Path);
                if (!Needed->Contains(Hash) || Index.AmbiguousLive.Contains(Hash))
                {
                    return;
                }
                if (Index.UniqueLive.Contains(Hash))
                {
                    Index.UniqueLive.Remove(Hash);
                    Index.AmbiguousLive.Add(Hash);
                }
                else
                {
                    Index.UniqueLive.Add(Hash, Object);
                }
            }, true);
    }

    for (const TPair<FString, FRequirement>& Pair : Requirements)
    {
        const FRequirement& Req = Pair.Value;
        UPackage* Parent = ParentPackages.FindRef(Req.ParentId);
        const FParentIndex* Index = ParentIndices.Find(Req.ParentId);
        if (!Parent || !Index)
        {
            return false;
        }
        if (Index->NormalLinkerHashes.Contains(Req.Hash) && !Req.bFunctionSuper)
        {
            ++NormalExports;
            continue;
        }
        UObject* Candidate = Index->UniqueLive.FindRef(Req.Hash);
        const int32 Matches = Index->AmbiguousLive.Contains(Req.Hash) ? 2 :
            (Candidate ? 1 : 0);

        // A missing *ordinary* linker export remains the engine's responsibility.
        // For a parent UFunction or an unrepresented constructor archetype, the
        // exact live owner and public hash must be proven before any patch.
        if (Matches == 0 && !Req.bFunctionSuper)
        {
            // No normal stock export and no authoritative live template:
            // the child cannot resolve this hash. Abort before publishing.
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT MISSING_STRUCTURAL_PARENT | parent='%s' | hash=0x%016llX | mutation=NO"),
                *Req.ParentName.ToString(),
                static_cast<unsigned long long>(Req.Hash));
            return false;
        }
        if (Matches != 1 || !Candidate ||
            (Req.bFunctionSuper && !Cast<UFunction>(Candidate)) ||
            (!Req.bFunctionSuper && !Candidate->HasAnyFlags(RF_DefaultSubObject | RF_ArchetypeObject)) ||
            Candidate->HasAnyInternalFlags(
                EInternalObjectFlags::AsyncLoadingPhase1 |
                EInternalObjectFlags::AsyncLoadingPhase2))
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT AMBIGUOUS_OR_UNREADY | parent='%s' | hash=0x%016llX | matches=%d | object='%s' | mutation=NO"),
                *Req.ParentName.ToString(),
                static_cast<unsigned long long>(Req.Hash), Matches,
                Candidate ? *Candidate->GetPathName() : TEXT("<null>"));
            return false;
        }
        if (Req.bFunctionSuper &&
            !Cast<UClass>(Candidate->GetOuter()))
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT UFUNCTION_OWNER_INVALID | object='%s' | mutation=NO"),
                *Candidate->GetPathName());
            return false;
        }
        if (Bindings.Num() >= MaxScriptBindings)
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT SCRIPT_BINDING_BUDGET | max=%d | mutation=NO"),
                MaxScriptBindings);
            return false;
        }
        const FString Relative = Candidate->GetPathName(Parent);
        const FString ScriptPath = Candidate->GetPathName();
        const FString RegistrationPath = FString::Printf(
            TEXT("%s/%s"), *Parent->GetName(), *Relative);
        const FPackageObjectIndex ScriptIndex = FPackageObjectIndex::FromScriptPath(
            FStringView(*ScriptPath, ScriptPath.Len()));
        if (!ScriptIndex.IsScriptImport() ||
            ScriptIndex != FPackageObjectIndex::FromScriptPath(
                FStringView(*RegistrationPath, RegistrationPath.Len())))
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT SCRIPT_PATH_MISMATCH | object='%s' | mutation=NO"),
                *ScriptPath);
            return false;
        }
        for (const TPair<FString, FLiveBinding>& Existing : Bindings)
        {
            if (Existing.Value.ScriptIndex == ScriptIndex &&
                Existing.Value.PinnedObject.Get() != Candidate)
            {
                UE_LOG(LogSquadCookedMount, Error,
                    TEXT("SCM_COMPAT SCRIPT_INDEX_COLLISION | object='%s' | mutation=NO"),
                    *ScriptPath);
                return false;
            }
        }
        FLiveBinding& Binding = Bindings.FindOrAdd(Pair.Key);
        Binding.ScriptIndex = ScriptIndex;
        Binding.PackageName = Parent->GetFName();
        Binding.RelativePath = Relative;
        Binding.PublicHash = Req.Hash;
        Binding.PinnedObject = TStrongObjectPtr<UObject>(Candidate);
    }

    // Pass 3: reconstruct exact package-data bytes, rewrite all consumers of
    // every selected identity, prune ScriptImport dependency callbacks and
    // validate the rewritten layout before publishing a single chunk.
    for (const TPair<FPackageId, FHeaderInput>& Pair : Headers)
    {
        const FHeaderInput& Input = Pair.Value;
        FIoStoreReader* Reader = GetReader(Input.SourceUtoc);
        TArray<uint8> Bytes;
        if (!Reader || !ReadHeader(*Reader, Input.Id, Bytes, true))
        {
            return false;
        }
        SquadCookedMount::FDiagnosticZenHeaderView Header;
        FString Error;
        const FZenPackageSummary* Summary =
            reinterpret_cast<const FZenPackageSummary*>(Bytes.GetData());
        const bool bSnapshotUnchanged =
            Bytes.Num() >= static_cast<int32>(sizeof(FZenPackageSummary)) &&
            Summary->HeaderSize <= static_cast<uint32>(Bytes.Num()) &&
            FCrc::MemCrc32(Bytes.GetData(), Summary->HeaderSize) ==
                Input.HeaderFingerprint;
        if (!bSnapshotUnchanged ||
            !SquadCookedMount::ParseDiagnosticZenHeader(Bytes, Header, Error) ||
            Header.PackageName != Input.Name ||
            !SquadCookedMount::ValidateZenDependencyBundleLayout(Header))
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT HEADER_CHANGED | id=0x%016llX | error='%s' | mutation=NO"),
                static_cast<unsigned long long>(Input.Id.Value()), *Error);
            return false;
        }

        auto ResolveBinding = [&Header, &Input, &Bindings, &MakeKey](
            FPackageObjectIndex Index) -> const FLiveBinding*
        {
            if (!Index.IsPackageImport())
            {
                return nullptr;
            }
            const FPackageImportReference Ref = Index.ToPackageImportRef();
            if (!Input.ImportedIds.IsValidIndex(static_cast<int32>(Ref.GetImportedPackageIndex())) ||
                !Header.ImportedPublicExportHashes.IsValidIndex(
                    static_cast<int32>(Ref.GetImportedPublicExportHashIndex())))
            {
                return nullptr;
            }
            return Bindings.Find(MakeKey(
                Input.ImportedIds[Ref.GetImportedPackageIndex()],
                Header.ImportedPublicExportHashes[
                    Ref.GetImportedPublicExportHashIndex()]));
        };

        int32 Edits = 0;
        for (int32 ExportIndex = 0; ExportIndex < Header.ExportMap.Num(); ++ExportIndex)
        {
            FExportMapEntry& E = const_cast<FExportMapEntry&>(Header.ExportMap[ExportIndex]);
            for (FPackageObjectIndex* Index : {
                    &E.ClassIndex, &E.OuterIndex, &E.SuperIndex, &E.TemplateIndex })
            {
                if (const FLiveBinding* Binding = ResolveBinding(*Index))
                {
                    *Index = Binding->ScriptIndex;
                    ++Edits;
                }
            }
        }
        TSet<int32> ReplacedLocalImports;
        for (int32 i = 0; i < Header.ImportMap.Num(); ++i)
        {
            const FLiveBinding* Binding = ResolveBinding(Header.ImportMap[i]);
            if (Binding)
            {
                FPackageObjectIndex& Index = const_cast<FPackageObjectIndex&>(Header.ImportMap[i]);
                Index = Binding->ScriptIndex;
                ReplacedLocalImports.Add(i);
                ++Edits;
            }
        }
        if (Edits == 0)
        {
            continue;
        }
        PrunedDependencies += SquadCookedMount::PruneZenDependenciesForLocalImports(
            Header, ReplacedLocalImports);
        // Pruning uses fixed-size inline Zen sections: dependency entry slots
        // after the compacted live prefix are zeroed padding. Runtime iterates
        // EntryCount, NOT the entire serialized slot array; validate precisely
        // that prefix and every referenced local import/export index.
        int32 NextEntry = 0;
        bool bDependencyValid = true;
        for (const FDependencyBundleHeader& DepHeader : Header.DependencyBundleHeaders)
        {
            int64 Count = 0;
            for (int32 Command = 0; Command < 2; ++Command)
            {
                for (int32 Dependency = 0; Dependency < 2; ++Dependency)
                {
                    Count += DepHeader.EntryCount[Command][Dependency];
                }
            }
            if (DepHeader.FirstEntryIndex < 0)
            {
                bDependencyValid &= (Count == 0);
                continue;
            }
            if (Count <= 0 || DepHeader.FirstEntryIndex != NextEntry ||
                Count > Header.DependencyBundleEntries.Num() - NextEntry)
            {
                bDependencyValid = false;
                break;
            }
            for (int64 Offset = 0; Offset < Count; ++Offset)
            {
                const FPackageIndex DepIndex =
                    Header.DependencyBundleEntries[NextEntry + Offset].LocalImportOrExportIndex;
                if (DepIndex.IsImport())
                {
                    if (!Header.ImportMap.IsValidIndex(DepIndex.ToImport()) ||
                        Header.ImportMap[DepIndex.ToImport()].IsScriptImport())
                    {
                        bDependencyValid = false;
                    }
                }
                else if (!DepIndex.IsExport() ||
                         DepIndex.ToExport() >= Header.ExportMap.Num() + Header.CellExportCount)
                {
                    bDependencyValid = false;
                }
            }
            NextEntry += static_cast<int32>(Count);
        }
        if (!bDependencyValid)
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT DEPENDENCY_REBUILD_INVALID | package='%s' | mutation=NO"),
                *Input.Name.ToString());
            return false;
        }
        StagedBytes += static_cast<uint64>(Bytes.Num());
        if (StagedBytes > MaxStagedBytes)
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT STAGING_BUDGET_EXCEEDED | bytes=%llu | budget=%llu | mutation=NO"),
                static_cast<unsigned long long>(StagedBytes),
                static_cast<unsigned long long>(MaxStagedBytes));
            return false;
        }
        StagedChunks.Add(CreatePackageDataChunkId(Input.Id), MoveTemp(Bytes));
    }

    if (StagedChunks.IsEmpty())
    {
        UE_LOG(LogSquadCookedMount, Display,
            TEXT("SCM_COMPAT NO_COMPATIBILITY_OVERLAYS | sources=%d | normal=%d | unresolved=%d | mutation=NO"),
            Headers.Num(), NormalExports, Unresolved);
        return true;
    }
    if (SquadCookedMount::GSCMGenericBlueprintSuperOverlay.IsValid())
    {
        UE_LOG(LogSquadCookedMount, Error,
            TEXT("SCM_COMPAT OVERLAY_BACKEND_ALREADY_MOUNTED | mutation=NO"));
        return false;
    }

    // Commit is irreversible: AddScriptObject has no symmetric unregister API.
    // No further fallible preparation work occurs after this point. Strong pins
    // exist before registration and live until commandlet termination.
    for (TPair<FString, FLiveBinding>& Pair : Bindings)
    {
        FLiveBinding& Binding = Pair.Value;
        UObject* Object = Binding.PinnedObject.Get();
        if (!Object || Object->IsUnreachable())
        {
            return false;
        }
    }
    static TMap<FPackageObjectIndex, TStrongObjectPtr<UObject>> CookScriptPins;
    for (TPair<FString, FLiveBinding>& Pair : Bindings)
    {
        FLiveBinding& Binding = Pair.Value;
        NotifyRegistrationEvent(
            Binding.PackageName,
            FName(*Binding.RelativePath),
            ENotifyRegistrationType::NRT_NoExportObject,
            ENotifyRegistrationPhase::NRP_Finished,
            nullptr,
            true,
            Binding.PinnedObject.Get());
        CookScriptPins.Add(Binding.ScriptIndex, MoveTemp(Binding.PinnedObject));
    }
    TSharedPtr<SquadCookedMount::FSCMGenericBlueprintSuperIoOverlayBackend> Backend =
        MakeShared<SquadCookedMount::FSCMGenericBlueprintSuperIoOverlayBackend>();
    const int32 ChunkCount = StagedChunks.Num();
    for (TPair<FIoChunkId, TArray<uint8>>& Pair : StagedChunks)
    {
        Backend->AddOrReplaceChunk(Pair.Key, MoveTemp(Pair.Value));
    }
    SquadCookedMount::GSCMGenericBlueprintSuperOverlay = Backend;
    FIoDispatcher::Get().Mount(Backend.ToSharedRef(), 1000);
    bGenericBlueprintSuperIoOverlayMounted = true;

    UE_LOG(LogSquadCookedMount, Display,
        TEXT("SCM_COMPAT ACTIVE | repairPackages=%d | structuralTargets=%d | normalExports=%d | scriptBindings=%d | stagedHeaders=%d | prunedDependencies=%d | preloadedParents=%d | unresolvedNative=%d | bytes=%llu | syntheticExports=NO | massReindex=NO"),
        Headers.Num(), Requirements.Num(), NormalExports,
        Bindings.Num(), ChunkCount, PrunedDependencies,
        ParentsLoaded, Unresolved,
        static_cast<unsigned long long>(StagedBytes));
    return true;
#else
    return false;
#endif
}


bool FSquadCookedMountModule::BuildAndMountCookSelectiveZenBackend(
    const FAssetRegistryState& ExternalState)
{
    if (bCookSelectiveZenBackendMounted)
    {
        return true;
    }

    if (!PakPlatformFile || MountedCookedLongRoots.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK selective Zen: missing PakPlatformFile or rooted external cooked mounts."));
        return false;
    }

    TArray<FCookZenContainerSource> Sources;
    uint32 Sequence = 0;

    for (const FString& PakPath : CookBasePakPaths)
    {
        AddCookContainerSourcesForPak(PakPath, 0, Sequence, Sources);
    }
    for (const FString& PakPath : MountedPakPaths)
    {
        AddCookContainerSourcesForPak(PakPath, 100, Sequence, Sources);
    }

    // Passive retail ContainerHeader parsing must not itself make retail
    // packages visible to the commandlet. Keep a reverse map so that, after
    // the dependency closure is known, only the owning retail pak files are
    // actually mounted into IoDispatcher.
    TMap<FString, FString> RetailContainerToPak;
    auto MakeContainerKey = [](const FString& Path)
    {
        FString Key = SquadCookedMount::NormalizeFilename(
            FPaths::ConvertRelativePathToFull(Path));
        Key.ToLowerInline();
        return Key;
    };

    for (const FString& PakPath : CookBasePakPaths)
    {
        const FString BasePath = PakPathToContainerBase(PakPath);
        RetailContainerToPak.Add(
            MakeContainerKey(BasePath + TEXT(".utoc")),
            PakPath);

        const FString OptionalUtoc = BasePath + TEXT(".o.utoc");
        if (IFileManager::Get().FileExists(*OptionalUtoc))
        {
            RetailContainerToPak.Add(
                MakeContainerKey(OptionalUtoc),
                PakPath);
        }
    }

    Sources.Sort(
        [](const FCookZenContainerSource& A, const FCookZenContainerSource& B)
        {
            if (A.Order != B.Order)
            {
                return A.Order > B.Order;
            }
            return A.Sequence > B.Sequence;
        });

    if (Sources.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK selective Zen: no readable IoStore container sources were discovered."));
        return false;
    }

    TMap<FPackageId, FCookZenSnapshotEntry> AllEntries;
    TMap<FPackageId, TArray<FPackageId>> OptionalImports;
    TMap<FPackageId, FCookZenRedirect> AllRedirects;

    int32 ParsedContainers = 0;
    int32 FailedContainers = 0;
    int32 TotalNewEntries = 0;

    for (const FCookZenContainerSource& Source : Sources)
    {
        FIoContainerHeader Header;
        FString Error;
        if (!ReadCookContainerHeader(Source.UtocPath, Header, Error))
        {
            ++FailedContainers;
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("COOK selective Zen: failed to read container header | order=%d seq=%u | '%s' | %s"),
                Source.Order,
                Source.Sequence,
                *Source.UtocPath,
                *Error);
            continue;
        }

        int32 NewEntries = 0;
        if (!CopyCookContainerEntries(
                Source,
                Header,
                AllEntries,
                OptionalImports,
                AllRedirects,
                NewEntries))
        {
            ++FailedContainers;
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("COOK selective Zen: malformed package-store entry table | '%s'"),
                *Source.UtocPath);
            continue;
        }

        ++ParsedContainers;
        TotalNewEntries += NewEntries;
    }

#if WITH_EDITOR
    for (TPair<FPackageId, TArray<FPackageId>>& Pair : OptionalImports)
    {
        if (FCookZenSnapshotEntry* Entry = AllEntries.Find(Pair.Key))
        {
            Entry->Data.OptionalSegmentImportedPackageIds = MoveTemp(Pair.Value);
            Entry->Data.bHasOptionalSegment = true;
        }
    }
#endif

    if (ParsedContainers == 0 || AllEntries.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK selective Zen: no package metadata could be reconstructed from discovered IoStore ContainerHeaders."));
        return false;
    }

    // Build the read-only identity graph. Never globally rearm stock LinkerLoad
    // exports: MarkAsUnloaded on thousands of stock packages invalidates
    // Blueprint regeneration identities and was not a sound cook repair.
    if (!BuildCrossLoaderImportIndex())
    {
        UE_LOG(LogSquadCookedMount, Error,
            TEXT("SCM_COMPAT CROSS_LOADER_INDEX_UNAVAILABLE | activation=REFUSED"));
        return false;
    }

    TSet<FPackageId> RootPackageIds;
    int32 ExternalAssetPackages = 0;
    ExternalState.EnumerateAllAssets(
        [this, &RootPackageIds, &ExternalAssetPackages](const FAssetData& AssetData)
        {
            if (AssetData.PackageName.IsNone())
            {
                return;
            }

            ++ExternalAssetPackages;
            const FString PackageName = AssetData.PackageName.ToString();
            for (const FString& LongRoot : CookExternalLongRoots)
            {
                if (PackageName.StartsWith(LongRoot, ESearchCase::IgnoreCase))
                {
                    const FPackageId PackageId = FPackageId::FromName(AssetData.PackageName);
                    if (PackageId.IsValid())
                    {
                        RootPackageIds.Add(PackageId);
                    }
                    break;
                }
            }
        });

    // The targeted AssetRegistry graph is used only to arm activation before
    // the first relevant loose/LinkerLoad package can win. Once activated,
    // keep the Zen representation complete for every package in the referenced
    // external cooked root(s). This is required for dynamic/UnexpectedLoad
    // paths that are not serialized as hard imports of the DLC itself.
    if (RootPackageIds.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK selective Zen: external AssetRegistry contains no packages under the targeted cooked roots."));
        return false;
    }

    // Traverse package IDs exactly as they were serialized into the cooked
    // container headers. Package names are not required for imported packages;
    // this avoids accidentally substituting the SDK's loose representation.
    TArray<FPackageId> WorkList;
    WorkList.Reserve(RootPackageIds.Num() * 2);
    for (const FPackageId RootId : RootPackageIds)
    {
        WorkList.Add(RootId);
    }

    TSet<FPackageId> Visited;
    TSet<FPackageId> Closure;
    TSet<FPackageId> EnabledRedirectSources;
    int32 MissingMetadataIds = 0;

    for (int32 WorkIndex = 0; WorkIndex < WorkList.Num(); ++WorkIndex)
    {
        const FPackageId PackageId = WorkList[WorkIndex];
        if (!PackageId.IsValid() || Visited.Contains(PackageId))
        {
            continue;
        }
        Visited.Add(PackageId);

        if (const FCookZenRedirect* Redirect = AllRedirects.Find(PackageId))
        {
            EnabledRedirectSources.Add(PackageId);
            if (Redirect->TargetPackageId.IsValid())
            {
                WorkList.Add(Redirect->TargetPackageId);
            }
        }

        const FCookZenSnapshotEntry* Entry = AllEntries.Find(PackageId);
        if (!Entry)
        {
            ++MissingMetadataIds;
            continue;
        }

        Closure.Add(PackageId);
        for (const FPackageId ImportedId : Entry->Data.ImportedPackageIds)
        {
            if (ImportedId.IsValid())
            {
                WorkList.Add(ImportedId);
            }
        }
#if WITH_EDITOR
        for (const FPackageId ImportedId : Entry->Data.OptionalSegmentImportedPackageIds)
        {
            if (ImportedId.IsValid())
            {
                WorkList.Add(ImportedId);
            }
        }
#endif
    }

    int32 ResolvedRoots = 0;
    int32 MissingRoots = 0;
    for (const FPackageId RootId : RootPackageIds)
    {
        if (Closure.Contains(RootId) || EnabledRedirectSources.Contains(RootId))
        {
            ++ResolvedRoots;
        }
        else
        {
            ++MissingRoots;
        }
    }

    if (ResolvedRoots == 0 || Closure.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK selective Zen: none of the external cooked root packages resolved to IoStore metadata | roots=%d missing=%d."),
            RootPackageIds.Num(),
            MissingRoots);
        return false;
    }

    // Before mounting any retail container or the priority-10 backend, inspect
    // the complete final Zen closure for UPackages that already exist with a
    // legacy LinkerLoad. This is the decisive contamination diagnostic: once a
    // package instance has been created through LinkerLoad, changing
    // FPackageStore priority later cannot retroactively recreate that package
    // as Zen for existing imports.
    TMap<FPackageId, FName> ClosureNamesById;
    auto AddClosureName = [&Closure, &ClosureNamesById](FName PackageName)
    {
        if (PackageName.IsNone())
        {
            return;
        }
        const FPackageId PackageId = FPackageId::FromName(PackageName);
        if (PackageId.IsValid() && Closure.Contains(PackageId) &&
            !ClosureNamesById.Contains(PackageId))
        {
            ClosureNamesById.Add(PackageId, PackageName);
        }
    };

    ExternalState.EnumerateAllAssets(
        [&AddClosureName](const FAssetData& AssetData)
        {
            AddClosureName(AssetData.PackageName);
        });

    if (FModuleManager::Get().IsModuleLoaded(TEXT("AssetRegistry")))
    {
        FAssetRegistryModule& AssetRegistryModule =
            FModuleManager::GetModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));
        AssetRegistryModule.Get().EnumerateAllAssets(
            [&AddClosureName](const FAssetData& AssetData)
            {
                AddClosureName(AssetData.PackageName);
                return true;
            });
    }

    int32 ClosureAlreadyLoaded = 0;
    int32 ClosureWithLinkerLoad = 0;
    int32 LoggedClosureLinkers = 0;
    static constexpr int32 MaxLoggedClosureLinkers = 64;
    TSet<FPackageId> PreloadedLinkerPackageIds;

    for (const TPair<FPackageId, FName>& Pair : ClosureNamesById)
    {
        const FString PackageText = Pair.Value.ToString();
        if (UPackage* ExistingPackage = FindPackage(nullptr, *PackageText))
        {
            ++ClosureAlreadyLoaded;
            if (ExistingPackage->GetLinker())
            {
                ++ClosureWithLinkerLoad;
                PreloadedLinkerPackageIds.Add(Pair.Key);
                if (LoggedClosureLinkers < MaxLoggedClosureLinkers)
                {
                    ++LoggedClosureLinkers;
                    UE_LOG(
                        LogSquadCookedMount,
                        Warning,
                        TEXT("COOK closure preloaded LinkerLoad | package='%s' | packageId=0x%016llX"),
                        *PackageText,
                        static_cast<unsigned long long>(Pair.Key.Value()));
                }
            }
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK closure pre-activation state | closure=%d | named=%d | unnamed=%d | alreadyLoaded=%d | withLinkerLoad=%d | loggedLinkers=%d"),
        Closure.Num(),
        ClosureNamesById.Num(),
        FMath::Max(0, Closure.Num() - ClosureNamesById.Num()),
        ClosureAlreadyLoaded,
        ClosureWithLinkerLoad,
        LoggedClosureLinkers);

    CookPreloadedLinkerPackageIds = PreloadedLinkerPackageIds;

    // The cooked external packages themselves must use their Zen representation,
    // but their vanilla /Game (and other non-external) imports must NOT be
    // overridden by retail Zen. The loose SDK packages are intentionally left
    // to the stock editor LinkerLoad backend. UE5.7's LinkerLoad support
    // reconstructs package-relative public-export hashes and registers those
    // exports with GlobalImportStore, so mixed Zen-child -> LinkerLoad-parent
    // imports are supported without replacing the entire vanilla dependency
    // graph.
    TSet<FPackageId> ExternalZenPackageIds;
    ExternalZenPackageIds.Reserve(RootPackageIds.Num());

    int32 ExternalRootsWithoutMetadata = 0;
    for (const FPackageId RootId : RootPackageIds)
    {
        if (AllEntries.Contains(RootId))
        {
            ExternalZenPackageIds.Add(RootId);
        }
        else
        {
            ++ExternalRootsWithoutMetadata;
        }
    }

    if (ExternalZenPackageIds.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK selective Zen: external-only package set is empty after IoStore metadata resolution."));
        return false;
    }

    // Keep the serialized ImportedPackageIds on every external entry unchanged.
    // Only package-store ownership is split: external IDs are priority-10 Zen,
    // while every non-external imported ID falls through to the stock editor
    // PackageStore backend (normally LinkerLoad).
    TSet<FPackageId> CrossRootImportedPackageIds;
    for (const FPackageId ExternalId : ExternalZenPackageIds)
    {
        const FCookZenSnapshotEntry* Snapshot = AllEntries.Find(ExternalId);
        if (!Snapshot)
        {
            continue;
        }

        for (const FPackageId ImportedId : Snapshot->Data.ImportedPackageIds)
        {
            if (ImportedId.IsValid() && !ExternalZenPackageIds.Contains(ImportedId))
            {
                CrossRootImportedPackageIds.Add(ImportedId);
            }
        }
#if WITH_EDITOR
        for (const FPackageId ImportedId : Snapshot->Data.OptionalSegmentImportedPackageIds)
        {
            if (ImportedId.IsValid() && !ExternalZenPackageIds.Contains(ImportedId))
            {
                CrossRootImportedPackageIds.Add(ImportedId);
            }
        }
#endif
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK Zen external-only split | dependencyClosure=%d | externalZen=%d | externalMissingMetadata=%d | crossRootImports=%d | preloadedLinkerInDependencyClosure=%d"),
        Closure.Num(),
        ExternalZenPackageIds.Num(),
        ExternalRootsWithoutMetadata,
        CrossRootImportedPackageIds.Num(),
        PreloadedLinkerPackageIds.Num());

    // Do NOT mount retail Squad PAK/IoStore containers here. External cooked
    // containers were already mounted by MountAllCookedMods. Mounting retail
    // containers would make vanilla /Game payloads available to Zen again and
    // recreate the mixed retail-Zen/SDK-LinkerLoad graph observed in 0.3.17o.
    CookSelectiveZenClosurePackageIds = ExternalZenPackageIds;

    // The visible Zen ownership closure stays broad to preserve unexpected and
    // dynamic imports. Repair is a distinct transitive workset rooted only in
    // the actual DLC target seeds; its source UTOCs come from the exact same
    // snapshot that will populate the priority-10 PackageStore backend.
    TSet<FPackageId> CookRepairIds;
    TArray<FPackageId> RepairQueue;
    for (const FPackageId Seed : CookTargetExternalSeedPackageIds)
    {
        RepairQueue.Add(Seed);
    }
    for (int32 i = 0; i < RepairQueue.Num(); ++i)
    {
        const FPackageId Current = RepairQueue[i];
        if (!ExternalZenPackageIds.Contains(Current) ||
            CookRepairIds.Contains(Current))
        {
            continue;
        }
        CookRepairIds.Add(Current);
        if (const FCookZenSnapshotEntry* Snapshot = AllEntries.Find(Current))
        {
            for (const FPackageId Imported : Snapshot->Data.ImportedPackageIds)
            {
                if (ExternalZenPackageIds.Contains(Imported) &&
                    !CookRepairIds.Contains(Imported))
                {
                    RepairQueue.Add(Imported);
                }
            }
        }
    }
    // The read-only cross-loader index intentionally includes ONLY packages
    // with an external Zen -> loose LinkerLoad import. CookRepairIds, however,
    // is the entire external dependency closure. Missing from the *candidate*
    // index is not evidence of a mismatched PackageStore source; those packages
    // do not require compatibility edits at all.
    TSet<FPackageId> CrossLoaderRepairIds;
    TMap<FPackageId, FString> ExpectedSources;
    int32 NoCrossLoaderImports = 0;
    for (const FPackageId Id : CookRepairIds)
    {
        const FCookZenSnapshotEntry* Snapshot = AllEntries.Find(Id);
        if (!Snapshot)
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT REPAIR_PACKAGE_NOT_IN_SNAPSHOT | id=0x%016llX | mutation=NO"),
                static_cast<unsigned long long>(Id.Value()));
            return false;
        }
        const TArray<FPackageId>* IndexedIds =
            ExternalPackageImportedPackageIds.Find(Id);
        const FString* IndexedSource = ExternalPackageSourceUtocs.Find(Id);
        if (!IndexedIds && !IndexedSource)
        {
            ++NoCrossLoaderImports;
            continue;
        }
        if (!IndexedIds || !IndexedSource ||
            *IndexedIds != Snapshot->Data.ImportedPackageIds ||
            !IndexedSource->Equals(Snapshot->SourceUtoc, ESearchCase::IgnoreCase))
        {
            UE_LOG(LogSquadCookedMount, Error,
                TEXT("SCM_COMPAT IMPORTED_PACKAGE_IDS_SOURCE_MISMATCH | id=0x%016llX | indexed=%d snapshot=%d | indexedUtoc='%s' snapshotUtoc='%s' | mutation=NO"),
                static_cast<unsigned long long>(Id.Value()),
                IndexedIds ? IndexedIds->Num() : -1,
                Snapshot->Data.ImportedPackageIds.Num(),
                IndexedSource ? **IndexedSource : TEXT("<missing>"),
                *Snapshot->SourceUtoc);
            return false;
        }
        CrossLoaderRepairIds.Add(Id);
        ExpectedSources.Add(Id, Snapshot->SourceUtoc);
    }
    UE_LOG(LogSquadCookedMount, Display,
        TEXT("SCM_COMPAT REPAIR_SELECTION | closure=%d | crossLoaderCandidates=%d | stockImportFree=%d | provenanceMatched=YES"),
        CookRepairIds.Num(), CrossLoaderRepairIds.Num(), NoCrossLoaderImports);

    // A DLC with no Zen -> LinkerLoad references needs only the unmodified
    // selective Zen PackageStore backend, not an artificial terminal failure.
    if (!CrossLoaderRepairIds.IsEmpty() &&
        !PrepareCookCrossLoaderCompatibilityOverlays(CrossLoaderRepairIds, ExpectedSources))
    {
        UE_LOG(LogSquadCookedMount, Error,
            TEXT("SCM_COMPAT FAILED_TERMINAL | seeds=%d | repairPackages=%d | crossLoaderCandidates=%d | externalVisible=%d | noRetry=YES"),
            CookTargetExternalSeedPackageIds.Num(), CookRepairIds.Num(),
            CrossLoaderRepairIds.Num(), ExternalZenPackageIds.Num());
        return false;
    }

    TMap<FPackageId, FCookZenOwnedEntry> BackendEntries;
    BackendEntries.Reserve(ExternalZenPackageIds.Num());
    for (const FPackageId PackageId : ExternalZenPackageIds)
    {
        if (const FCookZenSnapshotEntry* Snapshot = AllEntries.Find(PackageId))
        {
            BackendEntries.Add(PackageId, Snapshot->Data);
        }
    }

    TMap<FPackageId, FCookZenRedirect> BackendRedirects;
    BackendRedirects.Reserve(EnabledRedirectSources.Num());
    for (const FPackageId SourceId : EnabledRedirectSources)
    {
        if (!ExternalZenPackageIds.Contains(SourceId))
        {
            continue;
        }
        if (const FCookZenRedirect* Redirect = AllRedirects.Find(SourceId))
        {
            if (ExternalZenPackageIds.Contains(Redirect->TargetPackageId))
            {
                BackendRedirects.Add(SourceId, *Redirect);
            }
        }
    }

    TSharedRef<FCookSelectiveZenPackageStoreBackend> Backend =
        MakeShared<FCookSelectiveZenPackageStoreBackend>(
            MoveTemp(BackendEntries),
            MoveTemp(BackendRedirects));

    // UE5.7 mounts the normal editor LinkerLoad backend at priority +1 and
    // ordinary cooked stores at 0. Priority 10 wins only where this backend
    // returns Ok; every package outside ExternalZenPackageIds returns Missing and
    // therefore falls straight through to stock editor behavior.
    FPackageStore::Get().Mount(Backend, 10);
    bCookSelectiveZenBackendMounted = true;

    // Verify the split against the real PackageStore after mounting priority 10.
    // Every non-external import should be answered by the stock editor backend.
    int32 CrossRootNamed = 0;
    int32 CrossRootLinkerLoad = 0;
    int32 CrossRootZen = 0;
    int32 CrossRootMissing = 0;
    int32 CrossRootUnresolvedNames = 0;
    int32 LoggedCrossRoot = 0;
    static constexpr int32 MaxLoggedCrossRoot = 32;

    // UE 5.7 requires all FPackageStore query calls to execute inside
    // FPackageStoreReadScope; GetPackageStoreEntry() asserts ThreadReadCount otherwise.
    FPackageStore& MountedPackageStore = FPackageStore::Get();
    FPackageStoreReadScope MountedPackageStoreReadScope(MountedPackageStore);

    for (const FPackageId ImportedId : CrossRootImportedPackageIds)
    {
        const FName* ImportedName = ClosureNamesById.Find(ImportedId);
        if (!ImportedName)
        {
            ++CrossRootUnresolvedNames;
            continue;
        }

        ++CrossRootNamed;
        FPackageStoreEntry ImportedEntry;
        const EPackageStoreEntryStatus ImportedStatus =
            MountedPackageStore.GetPackageStoreEntry(
                ImportedId,
                *ImportedName,
                ImportedEntry);

        if (ImportedStatus != EPackageStoreEntryStatus::Ok)
        {
            ++CrossRootMissing;
        }
        else if (ImportedEntry.LoaderType == EPackageLoader::LinkerLoad)
        {
            ++CrossRootLinkerLoad;
        }
        else if (ImportedEntry.LoaderType == EPackageLoader::Zen)
        {
            ++CrossRootZen;
        }

        if (LoggedCrossRoot < MaxLoggedCrossRoot)
        {
            ++LoggedCrossRoot;
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK external->base PackageStore | import='%s' | id=0x%016llX | status=%s | loader=%s(%d)"),
                *ImportedName->ToString(),
                static_cast<unsigned long long>(ImportedId.Value()),
                PackageStoreStatusToString(ImportedStatus),
                PackageLoaderToString(ImportedEntry.LoaderType),
                static_cast<int32>(ImportedEntry.LoaderType));
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK external->base PackageStore summary | total=%d | named=%d | unresolvedNames=%d | linkerLoad=%d | zen=%d | missing=%d"),
        CrossRootImportedPackageIds.Num(),
        CrossRootNamed,
        CrossRootUnresolvedNames,
        CrossRootLinkerLoad,
        CrossRootZen,
        CrossRootMissing);

    FString RootList;
    for (const FString& LongRoot : MountedCookedLongRoots)
    {
        if (!RootList.IsEmpty())
        {
            RootList += TEXT(",");
        }
        RootList += LongRoot;
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK selective Zen backend MOUNTED | priority=10 | roots=[%s] | rootPackages=%d targetedTriggerSeeds=%d assetRows=%d resolvedRoots=%d missingRoots=%d | dependencyClosure=%d externalZenEntries=%d crossRootImports=%d preloadedLinkerInDependencyClosure=%d redirects=%d | retailRequired=0 retailMounted=0 | snapshotEntries=%d discoveredEntries=%d parsedContainers=%d failedContainers=%d unresolvedImportIds=%d"),
        *RootList,
        RootPackageIds.Num(),
        CookTargetExternalSeedPackageIds.Num(),
        ExternalAssetPackages,
        ResolvedRoots,
        MissingRoots,
        Closure.Num(),
        Backend->NumEntries(),
        CrossRootImportedPackageIds.Num(),
        PreloadedLinkerPackageIds.Num(),
        Backend->NumRedirects(),
        AllEntries.Num(),
        TotalNewEntries,
        ParsedContainers,
        FailedContainers,
        MissingMetadataIds);

    return true;
}

bool FSquadCookedMountModule::SetupCookCommandletBridge()
{
    if (bCookBridgeReady)
    {
        return true;
    }

    const FString ActiveBefore =
        FPlatformFileManager::Get().GetPlatformFile().GetName();

    int32 PreloadedTargetPackages = 0;
    int32 PreloadedTargetWithLinker = 0;
    int32 LoggedPreloadedLinkers = 0;
    for (const FName TargetPackageName : CookEarlyTriggerPackageNames)
    {
        if (UPackage* ExistingPackage = FindPackage(nullptr, *TargetPackageName.ToString()))
        {
            ++PreloadedTargetPackages;
            if (ExistingPackage->GetLinker())
            {
                ++PreloadedTargetWithLinker;
                if (LoggedPreloadedLinkers < 32)
                {
                    ++LoggedPreloadedLinkers;
                    UE_LOG(
                        LogSquadCookedMount,
                        Warning,
                        TEXT("COOK targeted preloaded LinkerLoad package | package='%s'"),
                        *TargetPackageName.ToString());
                }
            }
        }
    }
    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK targeted pre-activation state | triggerPackages=%d | alreadyLoaded=%d | withLinkerLoad=%d"),
        CookEarlyTriggerPackageNames.Num(),
        PreloadedTargetPackages,
        PreloadedTargetWithLinker);

    if (!PreparePakPlatformFileEarly())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: failed to prepare non-active Pak/IoStore backend."));
        return false;
    }

    // Shader libraries must be ready before any cooked package becomes visible.
    // This is the same invariant used by the interactive editor path; cooked
    // materials can deserialize during CookCommandlet dependency loading too.
    if (!PrepareCookShaderLibraries())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: shader-first gate failed; refusing to expose cooked packages with unresolved shader maps."));
        return false;
    }

    // Primary cook activation is reached from the first synchronous content
    // load after UAssetManager reports its initial scan complete. This keeps
    // PackageStore mutation out of both AssetRegistry and SquadAssetManager
    // startup while still running before that package chooses Linker/Zen. Mount only the
    // external cooked mod here; retail containers stay unmounted while their
    // metadata is reconstructed directly from .utoc headers.
    MountAllCookedMods(/*bPostProcess=*/false);

    FAssetRegistryState ExternalState;
    const bool bHaveExternalRegistry =
        CollectCookedModAssetRegistries(ExternalState);

    if (!bHaveExternalRegistry)
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: no cooked external AssetRegistry was found after external IoStore mount; selective dependency closure cannot be built."));
        return false;
    }

    // Discover the matching retail install but do not expose all of it through
    // FIoDispatcher/FFilePackageStoreBackend. BuildAndMountCookSelectiveZenBackend
    // will read ContainerHeaders directly and mount only retail paks that own a
    // package in the final dependency closure.
    if (!DiscoverBaseGameContainersForCook())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: retail Squad IoStore could not be discovered. Configure [SquadCookedMount] BaseGamePaksDir if auto-detection is not correct."));
        return false;
    }

    FString BasedOnReleaseVersion;
    FParse::Value(
        FCommandLine::Get(),
        TEXT("BasedOnReleaseVersion="),
        BasedOnReleaseVersion);

    const bool bNativeCookAgainstFixedBase =
        SquadCookedMount::IsCookAgainstFixedBaseEffective();

    if (!BasedOnReleaseVersion.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge: BasedOnReleaseVersion='%s' | native CookAgainstFixedBase=%s"),
            *BasedOnReleaseVersion,
            bNativeCookAgainstFixedBase ? TEXT("YES (command line)") : TEXT("NO (synthetic registry surrogate will be used)"));
    }

    // Prepare every reversible cook-side artifact first. FPackageStore has
    // no public Unmount API, so the selective Zen backend is deliberately
    // the final state-changing step.
    if (!bSyntheticBasedOnReleaseReady && !PrepareSyntheticBasedOnRelease(ExternalState))
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: failed to prepare the synthetic based-on-release registry."));
        return false;
    }

    if (!BuildAndMountCookSelectiveZenBackend(ExternalState))
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: failed to build the plugin-only selective Zen PackageStore backend."));
        return false;
    }

    DiagnoseCookPackageStore(ExternalState);

    const FString ActiveAfter =
        FPlatformFileManager::Get().GetPlatformFile().GetName();

    bCookBridgeReady = true;

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK base bridge READY | activePlatform before='%s' after='%s' | PakFileActive=%s | mountedPaks=%d | externalPackages=%d"),
        *ActiveBefore,
        *ActiveAfter,
        bPakPlatformFileActive ? TEXT("YES") : TEXT("NO"),
        MountedPakPaths.Num(),
        bHaveExternalRegistry ? ExternalState.GetNumPackages() : 0);

    return true;
}

bool FSquadCookedMountModule::CollectCookedModAssetRegistries(
    FAssetRegistryState& OutCombinedState)
{
    if (!PakPlatformFile)
    {
        return false;
    }

    FAssetRegistrySerializationOptions MergeOptions =
        MakeCookBridgeRegistryOptions();

    bool bAny = false;
    TSet<FString> LoadedRegistryCandidates;

    for (const FString& PakPath : MountedPakPaths)
    {
        IPlatformFile* ValidationPlatform =
            PreviousTopmostPlatformFile
            ? PreviousTopmostPlatformFile
            : &FPlatformFileManager::Get().GetPlatformPhysical();

        TRefCountPtr<FPakFile> PakFile =
            new FPakFile(ValidationPlatform, *PakPath, false, true);
        if (!PakFile.IsValid() || !PakFile->IsValid())
        {
            continue;
        }

        SquadCookedMount::FFindAssetRegistryVisitor Visitor;
        PakFile->PakVisitPrunedFilenames(Visitor);

        TArray<FString> Candidates;
        for (const FString& Match : Visitor.Matches)
        {
            SquadCookedMount::AddUniqueCandidate(Candidates, Match);
            if (FPaths::IsRelative(Match))
            {
                SquadCookedMount::AddUniqueCandidate(
                    Candidates,
                    FPaths::Combine(PakFile->GetMountPoint(), Match));
            }
        }

        const FString PakDir = FPaths::GetPath(PakPath);
        SquadCookedMount::AddUniqueCandidate(
            Candidates,
            FPaths::Combine(PakDir, TEXT("DevelopmentAssetRegistry.bin")));
        SquadCookedMount::AddUniqueCandidate(
            Candidates,
            FPaths::Combine(PakDir, TEXT("AssetRegistry.bin")));

        for (const FString& Candidate : Candidates)
        {
            const FString NormalizedCandidate =
                SquadCookedMount::NormalizeFilename(Candidate);
            if (LoadedRegistryCandidates.Contains(NormalizedCandidate))
            {
                continue;
            }

            TArray<uint8> Bytes;
            if (!ReadFileThroughPak(Candidate, Bytes))
            {
                continue;
            }

            FMemoryReader Reader(Bytes, true);
            FAssetRegistryState ModState;
            FAssetRegistryLoadOptions LoadOptions;
            FAssetRegistryVersion::Type Version =
                FAssetRegistryVersion::LatestVersion;

            if (!ModState.Load(Reader, LoadOptions, &Version))
            {
                continue;
            }

            if (!bAny)
            {
                OutCombinedState.InitializeFromExisting(
                    ModState,
                    MergeOptions,
                    FAssetRegistryState::EInitializationMode::Rebuild);
                bAny = true;
            }
            else
            {
                OutCombinedState.InitializeFromExisting(
                    ModState,
                    MergeOptions,
                    FAssetRegistryState::EInitializationMode::Append);
            }

            LoadedRegistryCandidates.Add(NormalizedCandidate);

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK base bridge: collected external registry '%s' | assets=%d | packages=%d | version=%d"),
                *Candidate,
                ModState.GetNumAssets(),
                ModState.GetNumPackages(),
                static_cast<int32>(Version));

            // One registry per logical mod pak is enough. Companion chunks
            // normally contain no UFS registry file.
            break;
        }
    }

    return bAny;
}

bool FSquadCookedMountModule::CollectCookedModAssetRegistriesPassive(
    FAssetRegistryState& OutCombinedState)
{
    const FString ModsDir =
        FPaths::Combine(FPaths::ProjectDir(), SquadCookedMount::CookedModsFolderName);

    TArray<FString> AllPakFiles;
    IFileManager::Get().FindFilesRecursive(
        AllPakFiles,
        *ModsDir,
        TEXT("*.pak"),
        true,
        false,
        false);

    TArray<FString> Selected;
    for (const FString& PakPath : AllPakFiles)
    {
        const FString CleanName = FPaths::GetCleanFilename(PakPath);
        if (PakNameFilter.IsEmpty() ||
            CleanName.Contains(PakNameFilter, ESearchCase::IgnoreCase))
        {
            Selected.Add(PakPath);
        }
    }

    FPlatformFileManager& PlatformFileManager = FPlatformFileManager::Get();
    IPlatformFile& ActivePlatformFile = PlatformFileManager.GetPlatformFile();

    // Read the pak as a standalone FPakFile. If a PakFile wrapper is already
    // active, use its lower level to avoid recursively opening the .pak through
    // itself. No FPakPlatformFile instance is initialized or mounted here.
    IPlatformFile* PakReadLowerLevel = &ActivePlatformFile;
    if (FCString::Stricmp(
            ActivePlatformFile.GetName(),
            FPakPlatformFile::GetTypeName()) == 0 &&
        ActivePlatformFile.GetLowerLevel())
    {
        PakReadLowerLevel = ActivePlatformFile.GetLowerLevel();
    }

    FAssetRegistrySerializationOptions MergeOptions =
        MakeCookBridgeRegistryOptions();

    bool bAny = false;
    TSet<FString> LoadedRegistryCandidates;
    int32 ValidPakIndexes = 0;
    int32 RegistryCount = 0;

    for (const FString& PakPath : Selected)
    {
        TRefCountPtr<FPakFile> PakFile =
            new FPakFile(PakReadLowerLevel, *PakPath, false, true);
        if (!PakFile.IsValid() || !PakFile->IsValid())
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("COOK passive registry phase: invalid PAK index '%s'."),
                *PakPath);
            continue;
        }
        ++ValidPakIndexes;

        SquadCookedMount::FFindAssetRegistryVisitor Visitor;
        PakFile->PakVisitPrunedFilenames(Visitor);

        TArray<FString> Candidates;
        for (const FString& Match : Visitor.Matches)
        {
            SquadCookedMount::AddUniqueCandidate(Candidates, Match);
            if (FPaths::IsRelative(Match))
            {
                SquadCookedMount::AddUniqueCandidate(
                    Candidates,
                    FPaths::Combine(PakFile->GetMountPoint(), Match));
            }
        }

        const FString PakDir = FPaths::GetPath(PakPath);
        SquadCookedMount::AddUniqueCandidate(
            Candidates,
            FPaths::Combine(PakDir, TEXT("DevelopmentAssetRegistry.bin")));
        SquadCookedMount::AddUniqueCandidate(
            Candidates,
            FPaths::Combine(PakDir, TEXT("AssetRegistry.bin")));

        for (const FString& Candidate : Candidates)
        {
            const FString NormalizedCandidate =
                SquadCookedMount::NormalizeFilename(Candidate);
            if (LoadedRegistryCandidates.Contains(NormalizedCandidate))
            {
                continue;
            }

            TArray<uint8> Bytes;
            bool bRead = false;

            FPakEntry Entry;
            if (PakFile->Find(NormalizedCandidate, &Entry) == FPakFile::EFindResult::Found)
            {
                bRead = SquadCookedMount::ReadPakEntryBytesPassive(
                    *PakFile,
                    PakReadLowerLevel,
                    Entry,
                    Bytes);
            }

            // Preserve the old bridge's loose-file fallback. This is still a
            // passive physical/platform-file read and does not expose IoStore.
            if (!bRead && IFileManager::Get().FileExists(*NormalizedCandidate))
            {
                bRead = FFileHelper::LoadFileToArray(Bytes, *NormalizedCandidate);
            }

            if (!bRead)
            {
                continue;
            }

            FMemoryReader Reader(Bytes, true);
            FAssetRegistryState ModState;
            FAssetRegistryLoadOptions LoadOptions;
            FAssetRegistryVersion::Type Version =
                FAssetRegistryVersion::LatestVersion;

            if (!ModState.Load(Reader, LoadOptions, &Version))
            {
                continue;
            }

            if (!bAny)
            {
                OutCombinedState.InitializeFromExisting(
                    ModState,
                    MergeOptions,
                    FAssetRegistryState::EInitializationMode::Rebuild);
                bAny = true;
            }
            else
            {
                OutCombinedState.InitializeFromExisting(
                    ModState,
                    MergeOptions,
                    FAssetRegistryState::EInitializationMode::Append);
            }

            LoadedRegistryCandidates.Add(NormalizedCandidate);
            ++RegistryCount;

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK passive registry phase: read registry directly from PAK | pak='%s' | entry='%s' | assets=%d | packages=%d | version=%d"),
                *PakPath,
                *NormalizedCandidate,
                ModState.GetNumAssets(),
                ModState.GetNumPackages(),
                static_cast<int32>(Version));

            // One registry per logical primary pak is sufficient. Rootless
            // companion chunks normally contain no AssetRegistry entry.
            break;
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK passive registry phase: scan complete | PAKs=%d selected=%d validIndexes=%d registries=%d combinedPackages=%d | IoStoreMounted=NO"),
        AllPakFiles.Num(),
        Selected.Num(),
        ValidPakIndexes,
        RegistryCount,
        bAny ? OutCombinedState.GetNumPackages() : 0);

    return bAny;
}

bool FSquadCookedMountModule::PrepareSyntheticBasedOnRelease(
    const FAssetRegistryState& ExternalState)
{
    FString ReleaseVersion;
    if (!FParse::Value(
            FCommandLine::Get(),
            TEXT("BasedOnReleaseVersion="),
            ReleaseVersion) ||
        ReleaseVersion.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("COOK base bridge: no -BasedOnReleaseVersion was supplied; synthetic base registry skipped."));
        return false;
    }

    FString ExistingRootOverride;
    FParse::Value(
        FCommandLine::Get(),
        TEXT("BasedOnReleaseVersionRoot="),
        ExistingRootOverride);

    if (!ExistingRootOverride.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("COOK base bridge: command line already contains -BasedOnReleaseVersionRoot='%s'. Automatic synthetic-root replacement is skipped to avoid ambiguous duplicate command-line values."),
            *ExistingRootOverride);
        return false;
    }

    const FString SourceRoot =
        SquadCookedMount::NormalizeDirectory(
            FPaths::Combine(FPaths::ProjectDir(), TEXT("Releases")));
    const FString SourceReleaseDir =
        FPaths::Combine(SourceRoot, ReleaseVersion);

    TArray<FString> Platforms;
    FString TargetPlatformArg;
    if (FParse::Value(
            FCommandLine::Get(),
            TEXT("TargetPlatform="),
            TargetPlatformArg))
    {
        TargetPlatformArg.ParseIntoArray(Platforms, TEXT("+"), true);
    }

    if (Platforms.Num() == 0)
    {
        IFileManager::Get().FindFiles(
            Platforms,
            *FPaths::Combine(SourceReleaseDir, TEXT("*")),
            false,
            true);
    }

    const FString SyntheticRoot =
        SquadCookedMount::NormalizeDirectory(
            FPaths::Combine(
                FPaths::ProjectSavedDir(),
                TEXT("SquadCookedMount/CookBase")));

    FAssetRegistrySerializationOptions MergeOptions =
        MakeCookBridgeRegistryOptions();

    int32 SavedRegistries = 0;
    TSet<FString> UniquePlatforms;
    for (FString Platform : Platforms)
    {
        Platform.TrimStartAndEndInline();
        if (Platform.IsEmpty() || UniquePlatforms.Contains(Platform))
        {
            continue;
        }
        UniquePlatforms.Add(Platform);

        const TArray<FString> RelativeRegistryPaths = {
            FPaths::Combine(TEXT("Metadata"), GetDevelopmentAssetRegistryFilename()),
            TEXT("AssetRegistry.bin")
        };

        for (const FString& RelativeRegistryPath : RelativeRegistryPaths)
        {
            const FString SourceRegistry =
                FPaths::Combine(
                    SourceRoot,
                    ReleaseVersion,
                    Platform,
                    RelativeRegistryPath);

            if (!IFileManager::Get().FileExists(*SourceRegistry))
            {
                continue;
            }

            FAssetRegistryState BaseState;
            if (!LoadRegistryFileForCookBridge(SourceRegistry, BaseState))
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("COOK base bridge: failed to load original release registry '%s'."),
                    *SourceRegistry);
                continue;
            }

            FAssetRegistryState MergedState;
            MergedState.InitializeFromExisting(
                BaseState,
                MergeOptions,
                FAssetRegistryState::EInitializationMode::Rebuild);
            MergedState.InitializeFromExisting(
                ExternalState,
                MergeOptions,
                FAssetRegistryState::EInitializationMode::Append);

            const bool bNativeCookAgainstFixedBase =
                SquadCookedMount::IsCookAgainstFixedBaseEffective();
            int32 SurrogatePackageCount = 0;
            if (!bNativeCookAgainstFixedBase)
            {
                SurrogatePackageCount =
                    MarkSyntheticRegistryAsFixedBaseSurrogate(MergedState);
            }

            const FString DestinationRegistry =
                FPaths::Combine(
                    SyntheticRoot,
                    ReleaseVersion,
                    Platform,
                    RelativeRegistryPath);

            if (!SaveRegistryFileForCookBridge(
                    DestinationRegistry,
                    MergedState))
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Error,
                    TEXT("COOK base bridge: failed to save merged release registry '%s'."),
                    *DestinationRegistry);
                continue;
            }

            ++SavedRegistries;
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK base bridge: merged base registry | platform='%s' | basePackages=%d + externalPackages=%d -> mergedPackages=%d | fixedBaseSurrogatePackages=%d | '%s'"),
                *Platform,
                BaseState.GetNumPackages(),
                ExternalState.GetNumPackages(),
                MergedState.GetNumPackages(),
                SurrogatePackageCount,
                *DestinationRegistry);
        }
    }

    if (SavedRegistries == 0)
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK base bridge: no source release registries found under '%s'. Synthetic based-on-release root was not enabled."),
            *SourceReleaseDir);
        return false;
    }

    if (!SquadCookedMount::IsCookAgainstFixedBaseEffective())
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK base bridge: native -CookAgainstFixedBase is absent. Temporary merged registries use PKG_CookGenerated only as a UE5.7 based-on-release source-verification surrogate; original Releases data is unchanged."));
    }

    const FString RootArg = FString::Printf(
        TEXT(" -BasedOnReleaseVersionRoot=\"%s\""),
        *SyntheticRoot);
    FCommandLine::Append(*RootArg);

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK base bridge: appended synthetic -BasedOnReleaseVersionRoot='%s' | generated registries=%d"),
        *SyntheticRoot,
        SavedRegistries);

    bSyntheticBasedOnReleaseReady = true;
    return true;
}

void FSquadCookedMountModule::DiagnoseCookPackageStore(
    const FAssetRegistryState& ExternalState) const
{
    // UE 5.7 requires every FPackageStore::GetPackageStoreEntry call to run
    // inside FPackageStoreReadScope. PackageStore.cpp checks ThreadReadCount
    // before consulting any backend.
    FPackageStore& PackageStore = FPackageStore::Get();
    FPackageStoreReadScope PackageStoreReadScope(PackageStore);

    TMap<FPackageId, FName> KnownNamesById;
    auto AddPackageName = [&KnownNamesById](FName PackageName)
    {
        if (!PackageName.IsNone())
        {
            KnownNamesById.FindOrAdd(FPackageId::FromName(PackageName), PackageName);
        }
    };

    auto IsUnderCookedExternalRoot = [this](FName PackageName)
    {
        if (PackageName.IsNone())
        {
            return false;
        }

        const FString PackageText = PackageName.ToString();
        for (const FString& Root : MountedCookedLongRoots)
        {
            if (PackageText.StartsWith(Root, ESearchCase::IgnoreCase))
            {
                return true;
            }
        }
        return false;
    };

    // Keep the diagnostic bounded and generic: sample packages discovered from
    // the mounted cooked registries themselves instead of naming any mod/class.
    static constexpr int32 MaxTargetSamples = 32;
    TArray<FName> TargetSamples;
    TSet<FName> SeenTargets;

    ExternalState.EnumerateAllAssets(
        [this, &AddPackageName, &IsUnderCookedExternalRoot, &TargetSamples, &SeenTargets](const FAssetData& AssetData)
        {
            AddPackageName(AssetData.PackageName);
            const FPackageId PackageId = FPackageId::FromName(AssetData.PackageName);
            const bool bSelectedByZenClosure =
                CookSelectiveZenClosurePackageIds.IsEmpty() ||
                CookSelectiveZenClosurePackageIds.Contains(PackageId);

            if (TargetSamples.Num() < MaxTargetSamples &&
                IsUnderCookedExternalRoot(AssetData.PackageName) &&
                bSelectedByZenClosure &&
                !SeenTargets.Contains(AssetData.PackageName))
            {
                SeenTargets.Add(AssetData.PackageName);
                TargetSamples.Add(AssetData.PackageName);
            }
        });

    if (FModuleManager::Get().IsModuleLoaded(TEXT("AssetRegistry")))
    {
        FAssetRegistryModule& AssetRegistryModule =
            FModuleManager::GetModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));

        AssetRegistryModule.Get().EnumerateAllAssets(
            [&AddPackageName](const FAssetData& AssetData)
            {
                AddPackageName(AssetData.PackageName);
                return true;
            });
    }

    TArray<FString> RootList;
    RootList.Reserve(MountedCookedLongRoots.Num());
    for (const FString& Root : MountedCookedLongRoots)
    {
        RootList.Add(Root);
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK PackageStore diagnostic | roots=%d [%s] | knownPackageIds=%d | sampledTargets=%d"),
        RootList.Num(),
        *FString::Join(RootList, TEXT(", ")),
        KnownNamesById.Num(),
        TargetSamples.Num());

    int32 TotalImports = 0;
    int32 TotalResolvedImports = 0;
    int32 TotalZenImports = 0;
    int32 TotalNonZenImports = 0;
    int32 TotalMissingImports = 0;
    int32 TotalUnresolvedNames = 0;
    int32 LoggedNonZen = 0;
    int32 LoggedMissing = 0;

    for (const FName TargetName : TargetSamples)
    {
        FPackageStoreEntry TargetEntry;
        const EPackageStoreEntryStatus TargetStatus =
            PackageStore.GetPackageStoreEntry(
                FPackageId::FromName(TargetName),
                TargetName,
                TargetEntry);

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("COOK PackageStore sample | package='%s' | status=%s | loader=%s(%d) | imports=%d | shaderMaps=%d"),
            *TargetName.ToString(),
            PackageStoreStatusToString(TargetStatus),
            PackageLoaderToString(TargetEntry.LoaderType),
            static_cast<int32>(TargetEntry.LoaderType),
            TargetEntry.ImportedPackageIds.Num(),
            TargetEntry.ShaderMapHashes.Num());

        if (TargetStatus != EPackageStoreEntryStatus::Ok)
        {
            continue;
        }

        TotalImports += TargetEntry.ImportedPackageIds.Num();

        for (const FPackageId ImportedId : TargetEntry.ImportedPackageIds)
        {
            const FName* ImportedName = KnownNamesById.Find(ImportedId);
            if (!ImportedName)
            {
                ++TotalUnresolvedNames;
                continue;
            }

            ++TotalResolvedImports;

            FPackageStoreEntry ImportedEntry;
            const EPackageStoreEntryStatus ImportedStatus =
                PackageStore.GetPackageStoreEntry(
                    ImportedId,
                    *ImportedName,
                    ImportedEntry);

            if (ImportedStatus != EPackageStoreEntryStatus::Ok)
            {
                ++TotalMissingImports;
                if (LoggedMissing < 32)
                {
                    ++LoggedMissing;
                    UE_LOG(
                        LogSquadCookedMount,
                        Warning,
                        TEXT("COOK PackageStore missing dependency | owner='%s' | import='%s' | id=0x%llX | status=%s"),
                        *TargetName.ToString(),
                        *ImportedName->ToString(),
                        ImportedId.Value(),
                        PackageStoreStatusToString(ImportedStatus));
                }
                continue;
            }

            if (ImportedEntry.LoaderType == EPackageLoader::Zen)
            {
                ++TotalZenImports;
            }
            else
            {
                ++TotalNonZenImports;
                if (LoggedNonZen < 32)
                {
                    ++LoggedNonZen;
                    UE_LOG(
                        LogSquadCookedMount,
                        Warning,
                        TEXT("COOK PackageStore non-Zen dependency | owner='%s' | import='%s' | external=%s | selected=%s/%s(%d)"),
                        *TargetName.ToString(),
                        *ImportedName->ToString(),
                        IsUnderCookedExternalRoot(*ImportedName) ? TEXT("YES") : TEXT("NO"),
                        PackageStoreStatusToString(ImportedStatus),
                        PackageLoaderToString(ImportedEntry.LoaderType),
                        static_cast<int32>(ImportedEntry.LoaderType));
                }
            }
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("COOK PackageStore diagnostic summary | sampledTargets=%d | imports=%d | resolvedNames=%d | unresolvedNames=%d | zen=%d | nonZen=%d | missing=%d"),
        TargetSamples.Num(),
        TotalImports,
        TotalResolvedImports,
        TotalUnresolvedNames,
        TotalZenImports,
        TotalNonZenImports,
        TotalMissingImports);
}

bool FSquadCookedMountModule::PreparePakPlatformFileEarly()
{
    if (bPakPlatformFileInitialized && PakPlatformFile)
    {
        return true;
    }

    if (!FIoDispatcher::IsInitialized())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("EARLY IoStore bootstrap skipped: FIoDispatcher is not initialized yet."));
        return false;
    }

    FPlatformFileManager& PlatformFileManager = FPlatformFileManager::Get();
    IPlatformFile& ActivePlatformFile = PlatformFileManager.GetPlatformFile();

    if (FCString::Stricmp(ActivePlatformFile.GetName(), TEXT("PakFile")) == 0)
    {
        PakPlatformFile = static_cast<FPakPlatformFile*>(&ActivePlatformFile);
        PreviousTopmostPlatformFile = &PlatformFileManager.GetPlatformPhysical();
        bPakPlatformFileInitialized = true;
        bPakPlatformFileActive = true;

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("EARLY IoStore bootstrap: PakFile is already the active platform file."));
        return true;
    }

    PreviousTopmostPlatformFile = &ActivePlatformFile;

    // IMPORTANT: obtain the wrapper from the manager so its lifetime and
    // shutdown bookkeeping remain owned by FPlatformFileManager.
    IPlatformFile* CreatedOrExistingPak =
        PlatformFileManager.GetPlatformFile(TEXT("PakFile"));

    if (!CreatedOrExistingPak)
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("EARLY IoStore bootstrap: FPlatformFileManager could not provide PakFile."));
        return false;
    }

    PakPlatformFile = static_cast<FPakPlatformFile*>(CreatedOrExistingPak);

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("EARLY IoStore bootstrap: initializing manager-owned PakFile over '%s' WITHOUT making it globally active."),
        PreviousTopmostPlatformFile->GetName());

    if (!PakPlatformFile->Initialize(
            PreviousTopmostPlatformFile,
            TEXT("-UseIoStore")))
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("EARLY IoStore bootstrap: FPakPlatformFile::Initialize failed."));
        PakPlatformFile = nullptr;
        PreviousTopmostPlatformFile = nullptr;
        return false;
    }

    bPakPlatformFileInitialized = true;
    bPakPlatformFileActive = false;

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("EARLY IoStore backend READY | activePlatform=%s | FIoDispatcher=%s | PackageStore backends=%s"),
        PlatformFileManager.GetPlatformFile().GetName(),
        FIoDispatcher::IsInitialized() ? TEXT("YES") : TEXT("NO"),
        FPackageStore::Get().HasAnyBackendsMounted() ? TEXT("YES") : TEXT("NO"));

    return true;
}

bool FSquadCookedMountModule::PromotePakPlatformFile()
{
    if (bCookCommandletMode)
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("COOK safety: refusing to promote PakPlatformFile over the commandlet platform-file chain."));
        return false;
    }

    if (!PreparePakPlatformFileEarly())
    {
        return false;
    }

    if (bPakPlatformFileActive)
    {
        return true;
    }

    FPlatformFileManager& PlatformFileManager = FPlatformFileManager::Get();

    UE_LOG(
        LogSquadCookedMount,
        Warning,
        TEXT("Promoting EARLY-prepared PakPlatformFile over '%s' after initial AssetRegistry scan."),
        PlatformFileManager.GetPlatformFile().GetName());

    PlatformFileManager.SetPlatformFile(*PakPlatformFile);
    PakPlatformFile->InitializeAfterSetActive();
    PlatformFileManager.InitializeNewAsyncIO();
    bPakPlatformFileActive = true;

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Prepared PakPlatformFile ACTIVE globally. Active=%s | FIoDispatcher=%s | PackageStore backends=%s"),
        PlatformFileManager.GetPlatformFile().GetName(),
        FIoDispatcher::IsInitialized() ? TEXT("YES") : TEXT("NO"),
        FPackageStore::Get().HasAnyBackendsMounted() ? TEXT("YES") : TEXT("NO"));

    return true;
}

void FSquadCookedMountModule::MountAllCookedMods(bool bPostProcess)
{
    const FString ModsDir =
        FPaths::Combine(FPaths::ProjectDir(), SquadCookedMount::CookedModsFolderName);

    TArray<FString> AllPakFiles;
    IFileManager::Get().FindFilesRecursive(
        AllPakFiles,
        *ModsDir,
        TEXT("*.pak"),
        true,
        false,
        false);

    TArray<FString> Selected;

    for (const FString& PakPath : AllPakFiles)
    {
        const FString CleanName = FPaths::GetCleanFilename(PakPath);

        if (PakNameFilter.IsEmpty() ||
            CleanName.Contains(PakNameFilter, ESearchCase::IgnoreCase))
        {
            Selected.Add(PakPath);
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("CookedMods scan: phase=%s | total PAKs=%d | selected=%d | filter='%s'"),
        bPostProcess ? TEXT("POST") : TEXT("EARLY"),
        AllPakFiles.Num(),
        Selected.Num(),
        *PakNameFilter
    );

    // Interactive EARLY mounting is deliberately two-pass. Rooted primary
    // mod paks open/validate their shader library first; only then are
    // rootless IoStore companion chunks exposed. Do not depend on filesystem
    // enumeration order (e.g. pakchunk0 happening to precede pakchunk22).
    if (!bPostProcess)
    {
        TArray<FString> RootedPrimaryPaks;
        TArray<FString> RootlessCompanionPaks;

        IPlatformFile* ValidationPlatform =
            PreviousTopmostPlatformFile
            ? PreviousTopmostPlatformFile
            : &FPlatformFileManager::Get().GetPlatformPhysical();

        for (const FString& PakPath : Selected)
        {
            TRefCountPtr<FPakFile> ProbePak =
                new FPakFile(ValidationPlatform, *PakPath, false, true);

            if (!ProbePak.IsValid() || !ProbePak->IsValid())
            {
                RootedPrimaryPaks.Add(PakPath);
                continue;
            }

            const FString ProbeMount =
                SquadCookedMount::NormalizeDirectory(
                    ProbePak->GetMountPoint());

            if (ProbeMount.IsEmpty() || ProbeMount == TEXT("/"))
            {
                RootlessCompanionPaks.Add(PakPath);
            }
            else
            {
                RootedPrimaryPaks.Add(PakPath);
            }
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("EARLY mount ordering | rootedPrimary=%d | rootlessCompanion=%d"),
            RootedPrimaryPaks.Num(),
            RootlessCompanionPaks.Num());

        for (const FString& PakPath : RootedPrimaryPaks)
        {
            MountTriplet(PakPath, /*bPostProcess=*/false);
        }

        for (const FString& PakPath : RootlessCompanionPaks)
        {
            MountTriplet(PakPath, /*bPostProcess=*/false);
        }
        return;
    }

    for (const FString& PakPath : Selected)
    {
        MountTriplet(PakPath, bPostProcess);
    }
}

bool FSquadCookedMountModule::MountTriplet(const FString& PakPath, bool bPostProcess)
{
    FString BasePath = FPaths::ChangeExtension(PakPath, TEXT(""));
    if (BasePath.EndsWith(TEXT(".")))
    {
        BasePath.LeftChopInline(1);
    }

    const FString UtocPath = BasePath + TEXT(".utoc");
    const FString UcasPath = BasePath + TEXT(".ucas");

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Candidate: %s | UTOC=%s | UCAS=%s"),
        *PakPath,
        IFileManager::Get().FileExists(*UtocPath) ? TEXT("OK") : TEXT("MISSING"),
        IFileManager::Get().FileExists(*UcasPath) ? TEXT("OK") : TEXT("MISSING")
    );

    if (!IFileManager::Get().FileExists(*UtocPath) ||
        !IFileManager::Get().FileExists(*UcasPath))
    {
        return false;
    }

    IPlatformFile* ValidationPlatform =
        PreviousTopmostPlatformFile
        ? PreviousTopmostPlatformFile
        : &FPlatformFileManager::Get().GetPlatformPhysical();

    TRefCountPtr<FPakFile> PakFile =
        new FPakFile(ValidationPlatform, *PakPath, false, true);

    if (!PakFile.IsValid() || !PakFile->IsValid())
    {
        return false;
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("PAK index valid | MountPoint=%s | Files=%d"),
        *PakFile->GetMountPoint(),
        PakFile->GetNumFiles()
    );

    FString LongRoot;
    FString PreferredContentPath;
    RegisterCookedMountPointFromPak(*PakFile, LongRoot, PreferredContentPath);

    const bool bAlreadyMounted = MountedPakPaths.Contains(PakPath);

    // EARLY phase safety rule:
    //  - a rooted primary mod container must open its reconstructed shader
    //    library before package exposure;
    //  - rootless pakchunk companions do not own a separate logical shader
    //    library. They may be exposed early only after the primary mod library
    //    (derived from "<ModName>pakchunk...") is already open.
    if (!bPostProcess && !bAlreadyMounted)
    {
        const bool bRequireRuntimeShaderLibrary =
            !bCookCommandletMode || FApp::CanEverRender();

        if (!bRequireRuntimeShaderLibrary)
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("COOK NullRHI mount gate: runtime shader library is intentionally disabled; allowing cooked IoStore exposure | pak='%s' | root='%s'"),
                *FPaths::GetCleanFilename(PakPath),
                *LongRoot);
        }
        else if (!LongRoot.IsEmpty())
        {
            RebuildShaderArchivesForMod(UtocPath, LongRoot);

            const bool bModShaderReady =
                OpenCookedShaderLibrary(LongRoot, PreferredContentPath);

            if (!bModShaderReady)
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("EARLY mount SKIPPED for root='%s': shader library was not available before package exposure. Will retry during POST pass."),
                    *LongRoot);
                return false;
            }

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("EARLY shader-first gate PASSED | root='%s' | totalShaders=%u"),
                *LongRoot,
                FShaderCodeLibrary::GetShaderCount());
        }
        else
        {
            const FString CompanionLibrary =
                DeriveCompanionLibraryNameFromPakPath(PakPath);

            if (!IsLogicalShaderLibraryOpen(
                    OpenedShaderLibraries,
                    CompanionLibrary))
            {
                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("EARLY companion mount SKIPPED | pak='%s' | logical='%s' | parent shader library not open yet."),
                    *FPaths::GetCleanFilename(PakPath),
                    *CompanionLibrary);
                return false;
            }

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("EARLY companion gate PASSED | pak='%s' | logical='%s' | parent shader library already open."),
                *FPaths::GetCleanFilename(PakPath),
                *CompanionLibrary);
        }
    }

    if (!bAlreadyMounted)
    {
        if (!PakPlatformFile)
        {
            UE_LOG(
                LogSquadCookedMount,
                Error,
                TEXT("Cooked mount failed: PakPlatformFile is null for '%s'."),
                *PakPath);
            return false;
        }

        FPakMountArgs MountArgs;
        MountArgs.PakFilename = *PakPath;
        MountArgs.PakOrder = 100;
        MountArgs.Path = nullptr;
        MountArgs.bLoadIndex = true;

        FIoStatus IoMountStatus;

        const bool bMounted =
            PakPlatformFile->Mount(MountArgs, &IoMountStatus, nullptr);

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("%s Mount result: PAK=%s | associated IoStore=%s"),
            bCookCommandletMode ? TEXT("COOK") : (bPostProcess ? TEXT("LATE") : TEXT("EARLY")),
            bMounted ? TEXT("OK") : TEXT("FAILED"),
            *IoMountStatus.ToString());

        if (!bMounted)
        {
            return false;
        }

        MountedPakPaths.AddUnique(PakPath);
        if (!LongRoot.IsEmpty())
        {
            MountedCookedLongRoots.Add(LongRoot);
        }
        if (!bCookCommandletMode && !LongRoot.IsEmpty())
        {
            SquadCookedMount::AddCookedBlueprintActionRoot(LongRoot);
        }
    }
    else
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("POST pass: container already EARLY-mounted; skipping duplicate mount | %s"),
            *PakPath);
    }

    if (bCookCommandletMode)
    {
        // Shader libraries were opened before package exposure in the EARLY
        // phase. After the IoDispatcher/PackageStore mount, commandlets still
        // skip global AssetRegistry append, PrimaryAssets and Blueprint editor
        // databases.
        return true;
    }

    if (!bPostProcess)
    {
        // This is intentionally the end of the early phase. Do NOT append the
        // cooked AssetRegistry while the editor's initial registry scan is
        // active, and do not touch editor action databases here.
        return true;
    }

    if (LongRoot.IsEmpty())
    {
        // Rootless pakchunk companions carry additional IoStore packages for
        // the same logical mod. Their primary rooted pak owns the mod
        // AssetRegistry and shader-library identity, so repeating those steps
        // here only re-reads/re-appends the same registry.
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("POST companion chunk: mount complete; skipping duplicate shader/AssetRegistry post-processing | %s"),
            *FPaths::GetCleanFilename(PakPath));
        return true;
    }

    // Reconstruct the mod's IoStore ShaderCodeLibrary/ShaderCode chunks into
    // the stock loose ShaderArchive v2 format before any later cooked materials load.
    RebuildShaderArchivesForMod(
        UtocPath,
        LongRoot);

    OpenCookedShaderLibrary(
        LongRoot,
        PreferredContentPath);

    LoadCookedAssetRegistry(
        *PakFile,
        PakPath,
        LongRoot,
        PreferredContentPath);

    return true;
}



FString FSquadCookedMountModule::ResolveBaseGamePaksDir() const
{
    if (!BaseGamePaksDir.IsEmpty() &&
        IFileManager::Get().DirectoryExists(*BaseGamePaksDir))
    {
        return SquadCookedMount::NormalizeDirectory(BaseGamePaksDir);
    }

    TArray<FString> Candidates;

    auto AddSteamCandidate =
        [&Candidates](const FString& SteamRoot)
        {
            if (SteamRoot.IsEmpty())
            {
                return;
            }

            Candidates.AddUnique(
                SquadCookedMount::NormalizeDirectory(
                    FPaths::Combine(
                        SteamRoot,
                        TEXT("steamapps/common/Squad/SquadGame/Content/Paks"))));
        };

    const FString ProgramFilesX86 =
        FPlatformMisc::GetEnvironmentVariable(TEXT("ProgramFiles(x86)"));
    const FString ProgramFiles =
        FPlatformMisc::GetEnvironmentVariable(TEXT("ProgramFiles"));

    AddSteamCandidate(
        FPaths::Combine(ProgramFilesX86, TEXT("Steam")));
    AddSteamCandidate(
        FPaths::Combine(ProgramFiles, TEXT("Steam")));

    // Steam's libraryfolders.vdf lets us discover custom D:/E:/... libraries
    // without requiring BaseGamePaksDir in the common case.
    TArray<FString> SteamRoots;
    if (!ProgramFilesX86.IsEmpty())
    {
        SteamRoots.AddUnique(
            FPaths::Combine(ProgramFilesX86, TEXT("Steam")));
    }
    if (!ProgramFiles.IsEmpty())
    {
        SteamRoots.AddUnique(
            FPaths::Combine(ProgramFiles, TEXT("Steam")));
    }

    for (const FString& SteamRoot : SteamRoots)
    {
        FString VdfText;
        const FString VdfPath =
            FPaths::Combine(
                SteamRoot,
                TEXT("steamapps/libraryfolders.vdf"));

        if (!FFileHelper::LoadFileToString(VdfText, *VdfPath))
        {
            continue;
        }

        TArray<FString> Lines;
        VdfText.ParseIntoArrayLines(Lines, false);

        for (const FString& Line : Lines)
        {
            if (!Line.Contains(TEXT("\"path\""), ESearchCase::IgnoreCase))
            {
                continue;
            }

            TArray<FString> Quoted;
            int32 SearchFrom = 0;

            while (SearchFrom < Line.Len())
            {
                const int32 OpenQuote =
                    Line.Find(
                        TEXT("\""),
                        ESearchCase::CaseSensitive,
                        ESearchDir::FromStart,
                        SearchFrom);

                if (OpenQuote == INDEX_NONE)
                {
                    break;
                }

                const int32 CloseQuote =
                    Line.Find(
                        TEXT("\""),
                        ESearchCase::CaseSensitive,
                        ESearchDir::FromStart,
                        OpenQuote + 1);

                if (CloseQuote == INDEX_NONE)
                {
                    break;
                }

                Quoted.Add(
                    Line.Mid(
                        OpenQuote + 1,
                        CloseQuote - OpenQuote - 1));

                SearchFrom = CloseQuote + 1;
            }

            if (Quoted.Num() < 2 ||
                !Quoted[0].Equals(TEXT("path"), ESearchCase::IgnoreCase))
            {
                continue;
            }

            FString LibraryRoot = Quoted[1];
            LibraryRoot.ReplaceInline(TEXT("\\\\"), TEXT("\\"));

            AddSteamCandidate(LibraryRoot);
        }
    }

    for (const FString& Candidate : Candidates)
    {
        if (IFileManager::Get().DirectoryExists(*Candidate))
        {
            return Candidate;
        }
    }

    return FString();
}

bool FSquadCookedMountModule::EnsureBaseShaderArchives()
{
    if (bBaseShaderArchivesPrepared)
    {
        return
            SquadCookedMount::IsLegacyShaderArchiveV2(
                FPaths::Combine(
                    LooseShaderDir,
                    SquadCookedMount::GetLegacyShaderArchiveFilename(
                        TEXT("Global"))));
    }

    bBaseShaderArchivesPrepared = true;

    const FString GlobalOutput =
        FPaths::Combine(
            LooseShaderDir,
            SquadCookedMount::GetLegacyShaderArchiveFilename(
                TEXT("Global")));

    const FString SquadGameOutput =
        FPaths::Combine(
            LooseShaderDir,
            SquadCookedMount::GetLegacyShaderArchiveFilename(
                TEXT("SquadGame")));

    if (SquadCookedMount::IsLegacyShaderArchiveV2(GlobalOutput) &&
        SquadCookedMount::IsLegacyShaderArchiveV2(SquadGameOutput))
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Base shader cache already ready | Global='%s' | SquadGame='%s'"),
            *GlobalOutput,
            *SquadGameOutput
        );
        return true;
    }

    const FString ResolvedBasePaksDir =
        ResolveBaseGamePaksDir();

    if (ResolvedBasePaksDir.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("Automatic base shader rebuild: retail Squad Content/Paks was not found. Set [SquadCookedMount] BaseGamePaksDir=.../SquadGame/Content/Paks in DefaultGame.ini.")
        );
        return false;
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Automatic base shader rebuild: scanning '%s'"),
        *ResolvedBasePaksDir
    );

    TArray<FString> UtocFiles;
    IFileManager::Get().FindFilesRecursive(
        UtocFiles,
        *ResolvedBasePaksDir,
        TEXT("*.utoc"),
        true,
        false,
        false);

    SquadCookedMount::FShaderIoStoreReaderSet ReaderSet;

    for (const FString& Utoc : UtocFiles)
    {
        ReaderSet.AddUtoc(Utoc);
    }

    const TArray<FString> DesiredNames =
    {
        TEXT("Global"),
        TEXT("SquadGame")
    };

    const int32 ReadyCount =
        SquadCookedMount::RebuildLibrariesFromReaderSet(
            ReaderSet,
            DesiredNames,
            FString(),
            LooseShaderDir);

    const bool bGlobalReady =
        SquadCookedMount::IsLegacyShaderArchiveV2(GlobalOutput);

    const bool bSquadGameReady =
        SquadCookedMount::IsLegacyShaderArchiveV2(SquadGameOutput);

    if (bGlobalReady)
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Automatic base shader rebuild finished | converted/cached=%d | Global=OK | SquadGame=%s"),
            ReadyCount,
            bSquadGameReady ? TEXT("OK") : TEXT("MISSING")
        );
    }
    else
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("Automatic base shader rebuild finished | converted/cached=%d | Global=MISSING | SquadGame=%s"),
            ReadyCount,
            bSquadGameReady ? TEXT("OK") : TEXT("MISSING")
        );
    }

    return bGlobalReady;
}

int32 FSquadCookedMountModule::RebuildShaderArchivesForMod(
    const FString& UtocPath,
    const FString& LongRoot)
{
    FString RootName = LongRoot;
    RootName.RemoveFromStart(TEXT("/"));
    RootName.RemoveFromEnd(TEXT("/"));

    if (RootName.IsEmpty())
    {
        return 0;
    }

    const FString UtocDir =
        FPaths::GetPath(UtocPath);

    TArray<FString> SiblingUtocs;
    IFileManager::Get().FindFilesRecursive(
        SiblingUtocs,
        *UtocDir,
        TEXT("*.utoc"),
        true,
        false,
        false);

    SquadCookedMount::FShaderIoStoreReaderSet ReaderSet;

    // Add the current container first, then same-mod sibling chunk containers.
    ReaderSet.AddUtoc(UtocPath);

    for (const FString& Sibling : SiblingUtocs)
    {
        if (FPaths::IsSamePath(Sibling, UtocPath))
        {
            continue;
        }

        const FString Clean =
            FPaths::GetCleanFilename(Sibling);

        if (!Clean.StartsWith(
                RootName,
                ESearchCase::IgnoreCase))
        {
            continue;
        }

        ReaderSet.AddUtoc(Sibling);
    }

    const TArray<FString> DesiredNames =
    {
        RootName
    };

    const int32 Count =
        SquadCookedMount::RebuildLibrariesFromReaderSet(
            ReaderSet,
            DesiredNames,
            RootName,
            LooseShaderDir);

    if (Count > 0)
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Automatic mod shader rebuild | root='%s' | converted/cached=%d"),
            *RootName,
            Count
        );
    }

    return Count;
}

bool FSquadCookedMountModule::StageLooseGlobalShaderLibrary()
{
    if (LooseShaderDir.IsEmpty())
    {
        return false;
    }

    TArray<FString> GlobalArchives;
    IFileManager::Get().FindFilesRecursive(
        GlobalArchives,
        *LooseShaderDir,
        TEXT("ShaderArchive-Global-*.ushaderbytecode"),
        true,
        false,
        false);

    if (GlobalArchives.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("Loose shader bootstrap: no ShaderArchive-Global-*.ushaderbytecode under '%s'."),
            *LooseShaderDir
        );
        return false;
    }

    const FString ProjectContentDir =
        SquadCookedMount::NormalizeDirectory(
            FPaths::ConvertRelativePathToFull(FPaths::ProjectContentDir()));

    IFileManager::Get().MakeDirectory(*ProjectContentDir, true);

    int32 Copied = 0;

    for (const FString& SourcePath : GlobalArchives)
    {
        const FString SourceFull =
            FPaths::ConvertRelativePathToFull(SourcePath);

        if (!SquadCookedMount::IsLegacyShaderArchiveV2(SourceFull))
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Loose shader bootstrap: ignoring non-v2 Global archive '%s'."),
                *SourceFull
            );
            continue;
        }

        const FString DestPath =
            FPaths::Combine(
                ProjectContentDir,
                FPaths::GetCleanFilename(SourceFull));

        if (FPaths::IsSamePath(SourceFull, DestPath))
        {
            ++Copied;
            continue;
        }

        TArray<uint8> Bytes;
        if (!FFileHelper::LoadFileToArray(Bytes, *SourceFull))
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Loose shader bootstrap: failed to read '%s'."),
                *SourceFull
            );
            continue;
        }

        if (!FFileHelper::SaveArrayToFile(Bytes, *DestPath))
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Loose shader bootstrap: failed to stage '%s' -> '%s'."),
                *SourceFull,
                *DestPath
            );
            continue;
        }

        ++Copied;

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Loose shader bootstrap: staged Global archive '%s'."),
            *DestPath
        );
    }

    return Copied > 0;
}

int32 FSquadCookedMountModule::OpenLooseShaderLibrariesForRoot(
    const FString& LibraryRootName)
{
    if (LooseShaderDir.IsEmpty() ||
        !FShaderCodeLibrary::IsEnabled())
    {
        return 0;
    }

    TArray<FString> CandidateArchives;
    IFileManager::Get().FindFilesRecursive(
        CandidateArchives,
        *LooseShaderDir,
        TEXT("ShaderArchive-*.ushaderbytecode"),
        true,
        false,
        false);

    const FString ExpectedSuffix =
        FString::Printf(
            TEXT("-%s.ushaderbytecode"),
            *SquadCookedMount::GetShaderFormatAndPlatform());

    int32 Opened = 0;

    for (const FString& ArchivePath : CandidateArchives)
    {
        const FString Filename =
            FPaths::GetCleanFilename(ArchivePath);

        if (!Filename.StartsWith(TEXT("ShaderArchive-")) ||
            !Filename.EndsWith(ExpectedSuffix))
        {
            continue;
        }

        FString LogicalName =
            Filename.Mid(FCString::Strlen(TEXT("ShaderArchive-")));

        LogicalName.LeftChopInline(ExpectedSuffix.Len(), EAllowShrinking::No);

        // Global is only a bootstrap archive. Per-mod calls should open the
        // library/libraries belonging to that mod root, including ChunkN names.
        if (!LogicalName.Contains(
                LibraryRootName,
                ESearchCase::IgnoreCase))
        {
            continue;
        }

        if (OpenedShaderLibraries.Contains(LogicalName))
        {
            continue;
        }

        const FString Directory =
            SquadCookedMount::NormalizeDirectory(
                FPaths::GetPath(
                    FPaths::ConvertRelativePathToFull(ArchivePath)));

        const bool bOpened =
            FShaderCodeLibrary::OpenLibrary(
                LogicalName,
                Directory,
                false);

        if (bOpened)
        {
            OpenedShaderLibraries.Add(LogicalName);
            ++Opened;

            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("Opened loose cooked shader library | logical='%s' | file='%s' | shaders=%u"),
                *LogicalName,
                *ArchivePath,
                FShaderCodeLibrary::GetShaderCount()
            );
        }
        else
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Failed to open loose cooked shader library | logical='%s' | file='%s'"),
                *LogicalName,
                *ArchivePath
            );
        }
    }

    return Opened;
}

bool FSquadCookedMountModule::OpenCookedShaderLibrary(
    const FString& LongRoot,
    const FString& PreferredContentPath)
{
    FString LibraryName = LongRoot;
    LibraryName.RemoveFromStart(TEXT("/"));
    LibraryName.RemoveFromEnd(TEXT("/"));

    if (LibraryName.IsEmpty())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("Shader library: could not derive library name from root '%s'."),
            *LongRoot
        );
        return false;
    }

    if (!FShaderCodeLibrary::IsEnabled())
    {
        // Build Global/SquadGame directly from retail Squad IoStore if needed.
        // This removes the external retoc/manual to-legacy step.
        EnsureBaseShaderArchives();
        StageLooseGlobalShaderLibrary();

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("ShaderCodeLibrary disabled; calling InitForRuntime after staging loose Global archive(s). platform=%d"),
            static_cast<int32>(GMaxRHIShaderPlatform)
        );

        FShaderCodeLibrary::InitForRuntime(GMaxRHIShaderPlatform);

        if (FShaderCodeLibrary::IsEnabled())
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("Late FShaderCodeLibrary::InitForRuntime finished | enabled=YES | shaderPlatform=%d"),
                static_cast<int32>(GMaxRHIShaderPlatform)
            );
        }
        else
        {
            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Late FShaderCodeLibrary::InitForRuntime finished | enabled=NO | shaderPlatform=%d"),
                static_cast<int32>(GMaxRHIShaderPlatform)
            );
        }
    }

    if (!FShaderCodeLibrary::IsEnabled())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("Shader library '%s': runtime ShaderCodeLibrary remains disabled. A valid same-build Global shader archive could not be reconstructed/opened. Cache='%s'"),
            *LibraryName,
            *LooseShaderDir
        );
        return false;
    }

    // The project shader library is separate from Global and can contain
    // shared shaders referenced by cooked mod materials.
    OpenLooseShaderLibrariesForRoot(TEXT("SquadGame"));

    // First preference: archives reconstructed from IoStore into legacy
    // .ushaderbytecode files. This bypasses the engine's cached early
    // IsRunningWithIoStore=false without changing RenderCore.
    const int32 LooseOpened =
        OpenLooseShaderLibrariesForRoot(LibraryName);

    if (LooseOpened > 0)
    {
        return true;
    }

    // Fallback for projects that already have a normal loose/pak library in
    // the plugin Content directory. Use the actual editor mount path where
    // possible rather than the cooked PAK's relative UFS fallback path.
    FString EditorContentPath = PreferredContentPath;

    if (FPackageName::MountPointExists(LongRoot))
    {
        const FString Resolved =
            FPackageName::LongPackageNameToFilename(LongRoot);

        if (!Resolved.IsEmpty())
        {
            EditorContentPath =
                SquadCookedMount::NormalizeDirectory(
                    FPaths::ConvertRelativePathToFull(Resolved));
        }
    }

    if (OpenedShaderLibraries.Contains(LibraryName))
    {
        return true;
    }

    const bool bOpened =
        FShaderCodeLibrary::OpenLibrary(
            LibraryName,
            EditorContentPath,
            false);

    if (bOpened)
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Cooked shader library open | name='%s' | dir='%s' | result=OK | total open shaders=%u"),
            *LibraryName,
            *EditorContentPath,
            FShaderCodeLibrary::GetShaderCount()
        );

        OpenedShaderLibraries.Add(LibraryName);
    }
    else
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("Cooked shader library open | name='%s' | dir='%s' | result=FAILED | loose dir='%s'"),
            *LibraryName,
            *EditorContentPath,
            *LooseShaderDir
        );
    }

    return bOpened;
}

bool FSquadCookedMountModule::RegisterCookedMountPointFromPak(
    FPakFile& PakFile,
    FString& OutLongRoot,
    FString& OutContentPath)
{
    const FString PakMount =
        SquadCookedMount::NormalizeDirectory(PakFile.GetMountPoint());

    const FString PluginName =
        SquadCookedMount::ExtractPluginNameFromPakMountPoint(PakMount);

    if (PluginName.IsEmpty())
    {
        return false;
    }

    OutLongRoot = FString::Printf(TEXT("/%s/"), *PluginName);
    OutContentPath =
        SquadCookedMount::NormalizeDirectory(
            FPaths::Combine(PakMount, TEXT("Content")));

    // If the empty editor-side shell plugin is enabled, PluginManager has
    // already registered /PluginName/ to the real SDK Content directory.
    // Keep that mapping. IoStore package loading uses PackageId/PackageStore
    // and does not require us to replace the editor's physical plugin root.
    if (FPackageName::MountPointExists(OutLongRoot))
    {
        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Keeping existing editor plugin mount root for %s; cooked UFS fallback would be %s"),
            *OutLongRoot,
            *OutContentPath
        );
    }
    else
    {
        FPackageName::RegisterMountPoint(OutLongRoot, OutContentPath);

        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("No editor plugin mount root existed; registered cooked fallback: %s -> %s"),
            *OutLongRoot,
            *OutContentPath
        );
    }

    return true;
}

bool FSquadCookedMountModule::ReadFileThroughPak(
    const FString& Filename,
    TArray<uint8>& OutBytes) const
{
    OutBytes.Reset();

    TUniquePtr<IFileHandle> Handle(
        PakPlatformFile ? PakPlatformFile->OpenRead(*Filename, false) : nullptr);

    if (!Handle)
    {
        return false;
    }

    const int64 Size = Handle->Size();
    if (Size <= 0 || Size > MAX_int32)
    {
        return false;
    }

    OutBytes.SetNumUninitialized(static_cast<int32>(Size));

    if (!Handle->Read(OutBytes.GetData(), Size))
    {
        OutBytes.Reset();
        return false;
    }

    return true;
}

bool FSquadCookedMountModule::LoadCookedAssetRegistry(
    FPakFile& PakFile,
    const FString& PakPath,
    const FString& LongRoot,
    const FString& PreferredContentPath)
{
    SquadCookedMount::FFindAssetRegistryVisitor Visitor;
    PakFile.PakVisitPrunedFilenames(Visitor);

    TArray<FString> Candidates;

    for (const FString& Match : Visitor.Matches)
    {
        SquadCookedMount::AddUniqueCandidate(Candidates, Match);

        if (FPaths::IsRelative(Match))
        {
            SquadCookedMount::AddUniqueCandidate(
                Candidates,
                FPaths::Combine(PakFile.GetMountPoint(), Match));
        }
    }

    const FString PakDir = FPaths::GetPath(PakPath);

    SquadCookedMount::AddUniqueCandidate(
        Candidates,
        FPaths::Combine(PakDir, TEXT("AssetRegistry.bin")));
    SquadCookedMount::AddUniqueCandidate(
        Candidates,
        FPaths::Combine(PakDir, TEXT("DevelopmentAssetRegistry.bin")));

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("AssetRegistry candidates found: %d"),
        Candidates.Num()
    );

    for (const FString& Candidate : Candidates)
    {
        TArray<uint8> Bytes;
        bool bRead = ReadFileThroughPak(Candidate, Bytes);

        if (!bRead && IFileManager::Get().FileExists(*Candidate))
        {
            TUniquePtr<FArchive> LooseReader(
                IFileManager::Get().CreateFileReader(*Candidate));

            if (LooseReader)
            {
                const int64 Size = LooseReader->TotalSize();

                if (Size > 0 && Size <= MAX_int32)
                {
                    Bytes.SetNumUninitialized(static_cast<int32>(Size));
                    LooseReader->Serialize(Bytes.GetData(), Size);
                    bRead = !LooseReader->IsError();
                }
            }
        }

        if (!bRead)
        {
            continue;
        }

        FMemoryReader Reader(Bytes, true);

        FAssetRegistryState State;
        FAssetRegistryLoadOptions LoadOptions;
        FAssetRegistryVersion::Type Version = FAssetRegistryVersion::LatestVersion;

        if (!State.Load(Reader, LoadOptions, &Version))
        {
            continue;
        }

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Loaded cooked AssetRegistry: %s | Assets=%d | Packages=%d | Version=%d"),
            *Candidate,
            State.GetNumAssets(),
            State.GetNumPackages(),
            static_cast<int32>(Version)
        );

        RegisterRootsFromState(State, PreferredContentPath);

        FAssetRegistryModule& AssetRegistryModule =
            FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));

        AssetRegistryModule.Get().AppendState(
            State,
            FAssetRegistryState::EInitializationMode::OnlyUpdateNew);

        UE_LOG(LogSquadCookedMount, Display, TEXT("Cooked AssetRegistry appended."));

        const int32 RegisteredPrimaryAssets =
            RegisterCookedPrimaryAssets(State, LongRoot);

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Late cooked PrimaryAsset registration finished for root '%s' | newly registered=%d"),
            *LongRoot,
            RegisteredPrimaryAssets
        );

        FString ContainerBasePath = FPaths::ChangeExtension(PakPath, TEXT(""));
        if (ContainerBasePath.EndsWith(TEXT(".")))
        {
            ContainerBasePath.LeftChopInline(1);
        }

        DiagnoseDirectUtoc(ContainerBasePath, State, LongRoot);
        DiagnoseMountedIoStoreNames(LongRoot);
        DiagnoseGlobalIoChunks(State, LongRoot);

        return true;
    }

    return false;
}


int32 FSquadCookedMountModule::RegisterCookedPrimaryAssets(
    const FAssetRegistryState& State,
    const FString& LongRoot)
{
    if (!UAssetManager::IsInitialized())
    {
        UE_LOG(
            LogSquadCookedMount,
            Warning,
            TEXT("UAssetManager is not initialized yet; cooked PrimaryAssets for '%s' were not registered."),
            *LongRoot
        );
        return 0;
    }

    UAssetManager& AssetManager = UAssetManager::Get();

    int32 AssetsInRoot = 0;
    int32 PrimaryAssetCandidates = 0;
    int32 AlreadyRegistered = 0;
    int32 NewlyRegistered = 0;
    int32 Failed = 0;
    int32 Logged = 0;

    State.EnumerateAllAssets(
        [&](const FAssetData& AssetData)
        {
            const FString PackageName = AssetData.PackageName.ToString();

            // A cooked mod registry can contain reference/dependency data from
            // other roots. Only register PrimaryAssets physically owned by the
            // mounted mod root so /Game assets cannot be silently replaced.
            if (!LongRoot.IsEmpty() &&
                !PackageName.StartsWith(LongRoot, ESearchCase::IgnoreCase))
            {
                return;
            }

            ++AssetsInRoot;

            // Cooked AssetRegistry data normally stores PrimaryAssetType and
            // PrimaryAssetName tags. GetPrimaryAssetId reads those tags.
            FPrimaryAssetId PrimaryAssetId = AssetData.GetPrimaryAssetId();

            if (!PrimaryAssetId.IsValid())
            {
                // Let the project's AssetManager apply its own extraction
                // rules as a fallback.
                PrimaryAssetId =
                    AssetManager.ExtractPrimaryAssetIdFromData(
                        AssetData,
                        FPrimaryAssetType());
            }

            if (!PrimaryAssetId.IsValid())
            {
                return;
            }

            ++PrimaryAssetCandidates;

            FAssetData ExistingAssetData;
            if (AssetManager.GetPrimaryAssetData(
                    PrimaryAssetId,
                    ExistingAssetData))
            {
                ++AlreadyRegistered;
                return;
            }

            if (!AssetManager.RegisterSpecificPrimaryAsset(
                    PrimaryAssetId,
                    AssetData))
            {
                ++Failed;

                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("PrimaryAsset registration FAILED | id='%s' | object='%s'"),
                    *PrimaryAssetId.ToString(),
                    *AssetData.GetObjectPathString()
                );
                return;
            }

            // Verify that the same public lookup that previously reported
            // missing NameData can now resolve this id.
            FAssetData VerifyAssetData;
            if (!AssetManager.GetPrimaryAssetData(
                    PrimaryAssetId,
                    VerifyAssetData))
            {
                ++Failed;

                UE_LOG(
                    LogSquadCookedMount,
                    Warning,
                    TEXT("PrimaryAsset registered but verification FAILED | id='%s' | object='%s'"),
                    *PrimaryAssetId.ToString(),
                    *AssetData.GetObjectPathString()
                );
                return;
            }

            ++NewlyRegistered;

            const FString IdString = PrimaryAssetId.ToString();
            const bool bImportantSquadType =
                IdString.Contains(TEXT("Faction"), ESearchCase::IgnoreCase) ||
                IdString.Contains(TEXT("Layer"), ESearchCase::IgnoreCase);

            if (Logged < 16 || bImportantSquadType)
            {
                ++Logged;

                UE_LOG(
                    LogSquadCookedMount,
                    Display,
                    TEXT("Registered cooked PrimaryAsset | id='%s' | object='%s' | bundles=%d"),
                    *IdString,
                    *VerifyAssetData.GetObjectPathString(),
                    VerifyAssetData.TaggedAssetBundles.IsValid()
                        ? VerifyAssetData.TaggedAssetBundles->Bundles.Num()
                        : 0
                );
            }
        },
        UE::AssetRegistry::EEnumerateAssetsFlags::AllowAll);

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Cooked PrimaryAsset summary | root='%s' | assets=%d | candidates=%d | registered=%d | already=%d | failed=%d | AssetManager initial scan=%s"),
        *LongRoot,
        AssetsInRoot,
        PrimaryAssetCandidates,
        NewlyRegistered,
        AlreadyRegistered,
        Failed,
        AssetManager.HasInitialScanCompleted() ? TEXT("DONE") : TEXT("NOT_DONE")
    );

    return NewlyRegistered;
}

void FSquadCookedMountModule::RegisterRootsFromState(
    const FAssetRegistryState& State,
    const FString& PreferredContentPath)
{
    TArray<FName> PackageNames;
    State.GetPackageNames(PackageNames);

    TSet<FString> Roots;

    for (const FName PackageName : PackageNames)
    {
        const FString Package = PackageName.ToString();

        if (!Package.StartsWith(TEXT("/")))
        {
            continue;
        }

        const int32 Slash =
            Package.Find(TEXT("/"), ESearchCase::CaseSensitive, ESearchDir::FromStart, 1);

        if (Slash == INDEX_NONE)
        {
            continue;
        }

        const FString Root = Package.Left(Slash + 1);

        if (Root.Equals(TEXT("/Game/"), ESearchCase::IgnoreCase) ||
            Root.Equals(TEXT("/Engine/"), ESearchCase::IgnoreCase) ||
            Root.Equals(TEXT("/Script/"), ESearchCase::IgnoreCase))
        {
            continue;
        }

        Roots.Add(Root);
    }

    FAssetRegistryModule& AssetRegistryModule =
        FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));

    for (const FString& Root : Roots)
    {
        if (!FPackageName::MountPointExists(Root) &&
            !PreferredContentPath.IsEmpty())
        {
            FPackageName::RegisterMountPoint(Root, PreferredContentPath);

            UE_LOG(
                LogSquadCookedMount,
                Warning,
                TEXT("Registry root had no existing editor mount; using cooked fallback: %s -> %s"),
                *Root,
                *PreferredContentPath
            );
        }
        else
        {
            UE_LOG(
                LogSquadCookedMount,
                VeryVerbose,
                TEXT("Registry root already has an editor mount; leaving it unchanged: %s"),
                *Root
            );
        }

        AssetRegistryModule.Get().AddPath(Root);
    }
}

void FSquadCookedMountModule::DiagnoseDirectUtoc(
    const FString& ContainerBasePath,
    const FAssetRegistryState& State,
    const FString& LongRoot) const
{
    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Direct UTOC diagnostic BEGIN | base='%s'"),
        *ContainerBasePath
    );

    FIoStoreReader Reader;
    TMap<FGuid, FAES::FAESKey> DecryptionKeys;

    const FIoStatus InitStatus =
        Reader.Initialize(ContainerBasePath, DecryptionKeys);

    if (!InitStatus.IsOk())
    {
        UE_LOG(
            LogSquadCookedMount,
            Error,
            TEXT("Direct UTOC reader FAILED: %s"),
            *InitStatus.ToString()
        );
        return;
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Direct UTOC reader OK | container='%s' | chunks=%d | version=%u | flags=0x%X"),
        *Reader.GetContainerName(),
        Reader.GetChunkCount(),
        Reader.GetVersion(),
        static_cast<uint32>(Reader.GetContainerFlags())
    );

    TMap<EIoChunkType, int32> TypeCounts;

    Reader.EnumerateChunks(
        [&TypeCounts](FIoStoreTocChunkInfo&& Info)
        {
            TypeCounts.FindOrAdd(Info.ChunkType)++;
            return true;
        });

    for (const TPair<EIoChunkType, int32>& Pair : TypeCounts)
    {
        const FString ChunkTypeString = LexToString(Pair.Key);

        UE_LOG(
            LogSquadCookedMount,
            Display,
            TEXT("Direct UTOC chunk type: %s | count=%d"),
            *ChunkTypeString,
            Pair.Value
        );
    }

    TArray<FName> PackageNames;
    State.GetPackageNames(PackageNames);

    int32 Matching = 0;
    int32 DirectFound = 0;
    int32 DirectMissing = 0;
    int32 Details = 0;

    for (const FName PackageName : PackageNames)
    {
        const FString PackageString = PackageName.ToString();

        if (!LongRoot.IsEmpty() &&
            !PackageString.StartsWith(LongRoot, ESearchCase::IgnoreCase))
        {
            continue;
        }

        ++Matching;

        const FPackageId PackageId = FPackageId::FromName(PackageName);
        const FIoChunkId ExpectedChunk = CreatePackageDataChunkId(PackageId);

        TIoStatusOr<FIoStoreTocChunkInfo> Info =
            Reader.GetChunkInfo(ExpectedChunk);

        const bool bFound = Info.IsOk();

        if (bFound)
        {
            ++DirectFound;
        }
        else
        {
            ++DirectMissing;
        }

        if (Details < 12)
        {
            UE_LOG(
                LogSquadCookedMount,
                Display,
                TEXT("Direct UTOC package: %s | expected package-data chunk=%s"),
                *PackageString,
                bFound ? TEXT("FOUND") : TEXT("MISSING")
            );
            ++Details;
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Direct UTOC diagnostic END | matching=%d | FOUND=%d | MISSING=%d"),
        Matching,
        DirectFound,
        DirectMissing
    );
}

void FSquadCookedMountModule::DiagnoseMountedIoStoreNames(
    const FString& LongRoot) const
{
    int32 TotalEnumerated = 0;
    int32 Matching = 0;
    int32 Details = 0;

    FPakPlatformFile::ForeachPackageInIostoreWhile(
        [&](FName PackageName)
        {
            ++TotalEnumerated;

            const FString Name = PackageName.ToString();

            if (LongRoot.IsEmpty() ||
                Name.StartsWith(LongRoot, ESearchCase::IgnoreCase))
            {
                ++Matching;

                if (Details < 12)
                {
                    UE_LOG(
                        LogSquadCookedMount,
                        Display,
                        TEXT("Mounted IoStore package name: %s"),
                        *Name
                    );
                    ++Details;
                }
            }

            return true;
        });

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("Mounted IoStore name diagnostic | total=%d | matching root '%s'=%d"),
        TotalEnumerated,
        *LongRoot,
        Matching
    );
}

void FSquadCookedMountModule::DiagnoseGlobalIoChunks(
    const FAssetRegistryState& State,
    const FString& LongRoot) const
{
    if (!FIoDispatcher::IsInitialized())
    {
        return;
    }

    TArray<FName> PackageNames;
    State.GetPackageNames(PackageNames);

    int32 Matching = 0;
    int32 Found = 0;
    int32 Missing = 0;

    FIoDispatcher& Dispatcher = FIoDispatcher::Get();

    for (const FName PackageName : PackageNames)
    {
        const FString PackageString = PackageName.ToString();

        if (!LongRoot.IsEmpty() &&
            !PackageString.StartsWith(LongRoot, ESearchCase::IgnoreCase))
        {
            continue;
        }

        ++Matching;

        const FIoChunkId ChunkId =
            CreatePackageDataChunkId(FPackageId::FromName(PackageName));

        if (Dispatcher.DoesChunkExist(ChunkId))
        {
            ++Found;
        }
        else
        {
            ++Missing;
        }
    }

    UE_LOG(
        LogSquadCookedMount,
        Display,
        TEXT("GLOBAL IoDispatcher diagnostic END | matching=%d | FOUND=%d | MISSING=%d"),
        Matching,
        Found,
        Missing
    );
}

IMPLEMENT_MODULE(FSquadCookedMountModule, SquadCookedMount)
