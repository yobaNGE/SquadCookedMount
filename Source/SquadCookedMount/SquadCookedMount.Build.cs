using UnrealBuildTool;

public class SquadCookedMount : ModuleRules
{
    public SquadCookedMount(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;

        PublicDependencyModuleNames.AddRange(new string[]
        {
            "Core",
            "CoreUObject",
            "Engine"
        });

        PrivateDependencyModuleNames.AddRange(new string[]
        {
            "AssetRegistry",
            "BlueprintGraph",
            "PakFile",
            "Projects",
            "RenderCore",
            "RHI",
            "UnrealEd"
        });
    }
}
