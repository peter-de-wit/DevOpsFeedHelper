#
# Module manifest for module 'DevOpsFeedHelper'
#

@{

  # Script module or binary module file associated with this manifest.
  RootModule           = 'DevOpsFeedHelper.psm1'

  # Version number of this module.
  ModuleVersion        = '0.3.0'

  # Supported PSEditions
  CompatiblePSEditions = @("Desktop", "Core")

  # ID used to uniquely identify this module
  GUID                 = '496f969c-3a3e-462e-a2a1-52aecead0f7e'

  # Author of this module
  Author               = 'Peter de Wit'

  # Company or vendor of this module
  CompanyName          = 'Witti B.V.'

  # Copyright statement for this module
  Copyright            = '(c) 2023 Peter de Wit. All rights reserved.'

  # Description of the functionality provided by this module
  Description          = 'This module exposes functionality to easily connect and/or maintain connections to DevOps Artifacts Feeds through PowerShell.'

  # Minimum version of the Windows PowerShell engine required by this module
  PowerShellVersion    = '5.1'

  # Name of the Windows PowerShell host required by this module
  # PowerShellHostName = ''

  # Minimum version of the Windows PowerShell host required by this module
  # PowerShellHostVersion = ''

  # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
  # DotNetFrameworkVersion = ''

  # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
  # CLRVersion = ''

  # Processor architecture (None, X86, Amd64) required by this module
  # ProcessorArchitecture = ''

  # Modules that must be imported into the global environment prior to importing this module
  RequiredModules      = @()

  # Assemblies that must be loaded prior to importing this module
  # RequiredAssemblies = @()

  # Script files (.ps1) that are run in the caller's environment prior to importing this module.
  ScriptsToProcess     = @()

  # Type files (.ps1xml) to be loaded when importing this module
  # TypesToProcess = @()

  # Format files (.ps1xml) to be loaded when importing this module
  # FormatsToProcess = @()

  # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
  # NestedModules = @()

  # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
  FunctionsToExport    = @(
    "Update-PowerShellGetToLatest",
    "Set-DevOpsFeedEncryptionEntropy",
    "Get-DevOpsFeedContext",
    "Set-DevOpsFeedContext",
    "Remove-DevOpsFeedCredential",
    "Get-DevOpsFeedCredential",
    "Set-DevOpsFeedCredential",
    "Unregister-DevOpsFeed",
    "Register-DevOpsFeed",
    "Find-DevOpsFeedModule",
    "Install-DevOpsFeedModule",
    "Update-DevOpsFeedModule",
    "Find-NuGetExecutable",
    "New-NuGetPackage"
  )

  # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
  CmdletsToExport      = @()

  # Variables to export from this module
  VariablesToExport    = ''

  # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
  AliasesToExport      = @(
    "Get-DevOpsContext",
    "Set-DevOpsContext",
    "Remove-DevOpsCredential",
    "Get-DevOpsCredential",
    "Set-DevOpsCredential"
  )

  # DSC resources to export from this module
  # DscResourcesToExport = @()

  # List of all modules packaged with this module
  # ModuleList = @("")

  # List of all files packaged with this module
  # FileList = @()

  # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
  PrivateData          = @{

    PSData = @{

      # Tags applied to this module. These help with module discovery in online galleries.
      Tags       = @("Azure", "DevOps", "Artifacts", "Feed", "Credential")

      # A URL to the license for this module.
      LicenseUri = 'https://github.com/peter-de-wit/DevOpsFeedHelper/blob/master/LICENSE'

      # A URL to the main website for this project.
      ProjectUri = 'https://github.com/peter-de-wit/DevOpsFeedHelper'

      IconUri = 'https://upload.wikimedia.org/wikipedia/commons/2/2f/PowerShell_5.0_icon.png'

      # ReleaseNotes of this module
      ReleaseNotes = '
Release notes for this and previous releases are on GitHub at:
https://github.com/peter-de-wit/DevOpsFeedHelper/releases .
'

      # Prerelease string of this module
      Prerelease = ''

    } # End of PSData hashtable

  } # End of PrivateData hashtable

  # HelpInfo URI of this module
  # HelpInfoURI = ''

  # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
  # DefaultCommandPrefix = ''
}