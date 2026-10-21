#pragma once

#include "CoreMinimal.h"
#include "Containers/Ticker.h"
#include "IO/PackageId.h"
#include "Modules/ModuleManager.h"

class FPakPlatformFile;
class FPakFile;
class FAssetRegistryState;
class IPlatformFile;
class UPackage;
struct FEndLoadPackageContext;

class FSquadCookedMountModule final : public IModuleInterface
{
public:
    virtual void StartupModule() override;
    virtual void ShutdownModule() override;

    // FPackageStore and FIoDispatcher have no public unmount path for the
    // custom backends used here. Once either backend is mounted, keep this
    // module DLL resident so no backend vtable can outlive its code.
    virtual bool SupportsDynamicReloading() override { return false; }
    virtual bool SupportsAutomaticShutdown() override
    {
        return !(bCookSelectiveZenBackendMounted || bGenericBlueprintSuperIoOverlayMounted);
    }

private:
    enum class ECookRegistryPhaseResult : uint8
    {
        Ready,
        Pending,
        Failed
    };

    enum class ECookTargetSeedResult : uint8
    {
        HasExternalDependencies,
        NoExternalDependencies,
        Pending,
        Failed
    };

    void BeginDelayedMount();
    void OnInitialAssetRegistryFilesLoaded();
    void OnCookCommandletPreMain();
    void OnCookCommandletPostMain();
    void OnCookAssetManagerInitialScanCompleted();
    ECookRegistryPhaseResult PrepareCookCommandletRegistryPhase();
    ECookTargetSeedResult PrepareCookTargetedDependencySeeds(const FAssetRegistryState& ExternalState);
    bool BuildCookEarlyTriggerFromIoStoreMetadata(const FAssetRegistryState& ExternalState);
    void ArmCookBridgeOnPostAssetManagerSyncLoad();
    void OnCookSyncLoadPackage(const FString& PackageName);
    void HandleEnginePreExit();

    // v0.3.17r-diag: targeted diagnostics for the remaining mixed
    // Zen -> LinkerLoad object-import and cooked material failures.
    void StartTargetedDiagnostics();
    void StopTargetedDiagnostics();
    void OnDiagnosticSyncLoadPackage(const FString& PackageName);
    void OnDiagnosticAsyncLoadPackage(FStringView PackageName);
    void OnDiagnosticEndLoadPackage(const FEndLoadPackageContext& Context);
    void DiagnoseProblemZenPackage(const FString& PackageName);
    void DiagnoseLoadedProblemPackage(UPackage* Package);
    void DiagnoseLoadedExternalMaterials(UPackage* Package);
    bool BuildCrossLoaderImportIndex();
    bool PrepareCookCrossLoaderCompatibilityOverlays(
        const TSet<FPackageId>& RepairPackageIds,
        const TMap<FPackageId, FString>& ExpectedSourceUtocs);
    int32 PreArmExternalUFunctionSuperOverlays();
    void RefreshLiveUFunctionScriptBindingsAfterBlueprintCompile();
    bool PrepareGenericBlueprintSuperOverlayForPackage(
        const FString& PackageName,
        bool bAllowKnownFailedStockUFunctionImports = false);
    int32 RefreshLoadedLinkerPackagesForZenImports(
        const TArray<FPackageId>* RestrictToPackageIds,
        const TCHAR* Reason,
        bool bForceSyncRefresh);
    void PrepareCrossLoaderParentsForExternalPackage(
        const FString& PackageName,
        const TCHAR* Reason);
    void OnPreBeginPIE(const bool bIsSimulating);

    void StartBlueprintActionAutoRefresh();
    void StopBlueprintActionAutoRefresh();
    bool TickBlueprintActionAutoRefresh(float DeltaTime);

    bool PreparePakPlatformFileEarly();
    bool SetupCookCommandletBridge();
    bool PrepareCookShaderLibraries();
    bool DiscoverBaseGameContainersForCook();
    bool BuildAndMountCookSelectiveZenBackend(const FAssetRegistryState& ExternalState);
    bool CollectCookedModAssetRegistries(FAssetRegistryState& OutCombinedState);
    bool CollectCookedModAssetRegistriesPassive(FAssetRegistryState& OutCombinedState);
    bool PrepareSyntheticBasedOnRelease(const FAssetRegistryState& ExternalState);
    void DiagnoseCookPackageStore(const FAssetRegistryState& ExternalState) const;
    bool PromotePakPlatformFile();
    void MountAllCookedMods(bool bPostProcess);
    bool MountTriplet(const FString& PakPath, bool bPostProcess);

    bool RegisterCookedMountPointFromPak(
        FPakFile& PakFile,
        FString& OutLongRoot,
        FString& OutContentPath);

    bool LoadCookedAssetRegistry(
        FPakFile& PakFile,
        const FString& PakPath,
        const FString& LongRoot,
        const FString& PreferredContentPath);

    bool OpenCookedShaderLibrary(
        const FString& LongRoot,
        const FString& PreferredContentPath);

    bool EnsureBaseShaderArchives();
    int32 RebuildShaderArchivesForMod(
        const FString& UtocPath,
        const FString& LongRoot);
    FString ResolveBaseGamePaksDir() const;

    bool StageLooseGlobalShaderLibrary();
    int32 OpenLooseShaderLibrariesForRoot(
        const FString& LibraryRootName);

    bool ReadFileThroughPak(
        const FString& Filename,
        TArray<uint8>& OutBytes) const;

    void RegisterRootsFromState(
        const FAssetRegistryState& State,
        const FString& PreferredContentPath);

    int32 RegisterCookedPrimaryAssets(
        const FAssetRegistryState& State,
        const FString& LongRoot);

    void DiagnoseDirectUtoc(
        const FString& ContainerBasePath,
        const FAssetRegistryState& State,
        const FString& LongRoot) const;

    void DiagnoseMountedIoStoreNames(
        const FString& LongRoot) const;

    void DiagnoseGlobalIoChunks(
        const FAssetRegistryState& State,
        const FString& LongRoot) const;

private:
    FPakPlatformFile* PakPlatformFile = nullptr;
    IPlatformFile* PreviousTopmostPlatformFile = nullptr;

    FDelegateHandle AssetRegistryFilesLoadedHandle;
    FDelegateHandle EnginePreExitHandle;
    FTSTicker::FDelegateHandle BlueprintActionAutoRefreshTickerHandle;
    FDelegateHandle CookSyncLoadPackageHandle;
    FDelegateHandle CookCommandletPreMainHandle;
    FDelegateHandle CookCommandletPostMainHandle;
    FDelegateHandle DiagnosticSyncLoadPackageHandle;
    FDelegateHandle DiagnosticAsyncLoadPackageHandle;
    FDelegateHandle DiagnosticEndLoadPackageHandle;
    FDelegateHandle PreBeginPIEHandle;
    FDelegateHandle BlueprintCompiledHandle;

    bool bAutoRefreshBlueprintActions = true;
    float BlueprintActionAutoRefreshInterval = 0.50f;

    bool bMountStarted = false;
    bool bCookCommandletMode = false;
    bool bBlueprintActionSubsystemStarted = false;
    bool bEnginePreExitCleanupDone = false;
    bool bPakPlatformFileInitialized = false;
    bool bPakPlatformFileActive = false;

    FString PakNameFilter;

    // Cached from this plugin's .uplugin descriptor at StartupModule.
    // VersionName in the descriptor is the single source of truth for runtime banners.
    FString PluginVersionName;

    TArray<FString> MountedPakPaths;
    TArray<FString> CookBasePakPaths;
    TArray<FString> MountedBasePakPaths;
    TSet<FString> MountedCookedLongRoots;
    TSet<FString> CookExternalLongRoots;
    TSet<FPackageId> CookTargetExternalSeedPackageIds;
    TSet<FName> CookEarlyTriggerPackageNames;
    TSet<FPackageId> CookSelectiveZenClosurePackageIds;
    TSet<FPackageId> CookPreloadedLinkerPackageIds;
    bool bCookBridgeReady = false;
    bool bCookRegistryPhaseReady = false;
    bool bCookExternalBridgeRequired = false;
    bool bCookInitialAssetRegistryCallbackReached = false;
    bool bCookAssetManagerCompletionHookRegistered = false;
    bool bCookAssetManagerInitialScanCompleted = false;
    bool bCookBridgeActivationInProgress = false;
    bool bCookBridgeFailedTerminal = false;
    bool bCookInsideAssetRegistryFilesLoadedCallback = false;
    bool bSyntheticBasedOnReleaseReady = false;
    FString CookDlcLongRoot;
    bool bCookSelectiveZenBackendMounted = false;

    // Editor-only generic UFunction SuperStruct bridge. It rewrites only the
    // external Zen package-data chunk in memory and binds exact stock UFunction
    // parents to real live ScriptImports before the external request is queued.
    bool bGenericBlueprintSuperIoOverlayMounted = false;

    TMap<FPackageId, TSet<uint64>> EditorSuperOverlayParentHashes;
    TMap<FPackageId, TSet<uint64>> CrossLoaderSuperParentPublicHashes;
    TMap<FPackageId, TSet<uint64>> CrossLoaderNonSuperParentPublicHashes;

    // Generic mixed-loader bridge. Built from every mounted external Zen package header
    bool bCrossLoaderImportIndexReady = false;
    bool bCrossLoaderRefreshInProgress = false;
    TSet<FPackageId> CrossLoaderParentPackageIds;
    TMap<FPackageId, FName> CrossLoaderParentPackageNames;
    TMap<FPackageId, TSet<uint64>> CrossLoaderParentPublicHashes;
    // Compact reverse index built from immutable Zen headers. It records exact
    // consumers of each stock public-export hash for diagnostics/classification;
    // no UObject pointers are retained.
    TMap<FPackageId, TMap<uint64, TMap<FPackageId, FName>>>
        CrossLoaderParentHashConsumers;
    TMap<FName, FPackageId> ExternalPackageNameToId;
    // ImportedPackageIds copied from the same immutable reconstructed package-store
    // snapshot used by BuildCrossLoaderImportIndex. Startup pre-arm must not depend
    // on the live FPackageStore having published those arrays again.
    TMap<FPackageId, TArray<FPackageId>> ExternalPackageImportedPackageIds;
    TMap<FPackageId, FString> ExternalPackageSourceUtocs;
    TMap<FPackageId, TArray<FPackageId>> ExternalPackageCrossLoaderParents;
    // Exact stock LinkerLoad parents used as UFunction::SuperStruct by each
    // external Zen package. Only these parents are first-loaded by the JIT
    // preflight; ordinary class/template imports remain under AsyncLoading2.
    TMap<FPackageId, TArray<FPackageId>> ExternalPackageStockUFunctionSuperParents;

    // Reindex is intentionally one-shot per live UPackage identity. Re-arming
    // thousands of editor packages after a PIE teardown is unsafe because PIE
    // duplication/GC may have already invalidated loader-side assumptions.
    TMap<FPackageId, TWeakObjectPtr<UPackage>> CrossLoaderRefreshAttempts;
    bool bCrossLoaderInitialEditorRefreshDone = false;

    TSet<FString> DiagnosticDumpedProblemPackages;
    TSet<FString> DiagnosticDumpedLoadedProblemPackages;
    TSet<FString> DiagnosticLoggedMaterialPackages;
    TSet<FString> DiagnosticDumpedLoadedMaterialPackages;

    // Names passed successfully to FShaderCodeLibrary::OpenLibrary.
    TSet<FString> OpenedShaderLibraries;

    // Automatically reconstructed legacy shader archives are cached here.
    // Default: <Project>/Saved/SquadCookedMount/ShaderCache.
    FString LooseShaderDir;

    // Optional retail Squad Content/Paks directory used to reconstruct the
    // same-build Global and SquadGame shader libraries automatically.
    FString BaseGamePaksDir;

    bool bBaseShaderArchivesPrepared = false;
};
