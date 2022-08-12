<#
  .SYNOPSIS
    Powershell module to support connecting and maintaining connections to DevOps Artifacts Feeds.

  .DESCRIPTION
    This module can be used by to help connecting with or maintaining existing DevOps Artifacts Feeds
    without needing the knowledge of prerequisites.

    2021-06-12
    Peter de Wit

  .NOTES
    This script was created from the steps explained in:
    https://docs.microsoft.com/en-us/azure/devops/artifacts/tutorials/private-powershell-library?view=azure-devops

    Keep in mind that this module is created because the current
    version of PowerShellGet has some limitations with connecting to DevOps Artifacts Feeds. This should be fixed
    in a later release of PowerShellGet. See notes within function Register-DevOpsFeed.

#>

#Global variables
$Script:SourceUri_v2 = "https://pkgs.dev.azure.com/{0}/{1}/_packaging/{2}/nuget/v2"
$Script:SourceUri_v3 = "https://pkgs.dev.azure.com/{0}/{1}/_packaging/{2}/nuget/v3/index.json"
$Script:DefaultFeedEnvironmentVariableNameForUser = "DevOpsSharedFeedUser"
$Script:DefaultFeedEnvironmentVariableNameForPat = "DevOpsSharedFeedPAT"
$Script:DefaultFeedEncryptionEntropy = "6a9909f8-bbf6-48d0-b6fa-ff3543fa4c75"
$Script:FeedEncryptionEntropy = $Script:DefaultFeedEncryptionEntropy
$Script:DefaultOrganisationName = ""
$Script:DefaultProjectName = ""
$Script:DefaultFeedName = ""
$Script:DevOpsFeedContext = [PsCustomObject] @{
  OrganisationName = $Script:DefaultOrganisationName
  ProjectName = $Script:DefaultProjectName
  FeedName = $Script:DefaultFeedName
}

Function Test-IsWindowsPlatform
{
  If ($PsVersionTable.PSVersion.Major -eq 5) { Return $True }
  If ($PsVersionTable.Platform -and $PsVersionTable.StartsWith("Win")) { Return $True }
  Return $False
}

Function Set-DevOpsFeedEncryptionEntropy
{
  [CmdletBinding(SupportsShouldProcess)]
  Param(
    [Parameter(Mandatory=$True, ValueFromPipeline)]
    [String] $EncryptionEntropy
  )

  Begin
  {
    "Set-DevOpsFeedEncryptionEntropy - START" | Write-Verbose
    $Value = ""
  }

  Process
  {
    # Only select last
    $Value = $EncryptionEntropy
  }

  End
  {
    Set-Variable -Name "FeedEncryptionEntropy" -Value $Value -Scope Script
    "Set-DevOpsFeedEncryptionEntropy - END" | Write-Verbose
  }

 <#
  .SYNOPSIS
    Powershell function to change the encryption entropy used for encrypting and decrypting DevOps Artifacts Feed credentials to local environment settings.

  .DESCRIPTION
    This function can be used to change the encryption entropy so that it will be used for encrypting and decrypting DevOps Artifacts Feed credentials within the
    current session.

  .OUTPUTS
    NONE

  #>
}

Function ConvertTo-EncryptedStringWithDpApi
{
  [CmdletBinding()]
  [OutputType([String])]
  Param(
    [Parameter(Mandatory=$True, ValueFromPipeline)]
    [String] $String,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $EncryptionEntropy = ($Script:FeedEncryptionEntropy)
  )

  Begin
  {
    "ConvertTo-EncryptedStringWithDpApi - START" | Write-Verbose
    If (-not(Test-IsWindowsPlatform))
    {
      "ConvertTo-EncryptedStringWithDpApi - Using cryptography functionality is only supported on Windows. Result is NOT encrypted." | Write-Warning
    }
    Else
    {
      Add-Type -AssemblyName System.Security | Out-Null
    }
  }

  Process
  {
    If (-not(Test-IsWindowsPlatform))
    {
      $String
    }
    Else
    {
      $Bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
      If ([String]::IsNullOrEmpty($EncryptionEntropy))
      {
        $EntropyBytes = $Null
      }
      Else
      {
        $EntropyBytes = [System.Text.Encoding]::Unicode.GetBytes($EncryptionEntropy)
      }

      $SecureStr = [Security.Cryptography.ProtectedData]::Protect($bytes, $EntropyBytes, [Security.Cryptography.DataProtectionScope]::CurrentUser)
      $SecureStrBase64 = [System.Convert]::ToBase64String($SecureStr)
      $SecureStrBase64
    }
  }

  End
  {
    "ConvertTo-EncryptedStringWithDpApi - END" | Write-Verbose
  }

 <#
  .SYNOPSIS
    Powershell function to encrypt a string by using the local machine key and an optional entropy.

  .DESCRIPTION
    This function can be used to encrypt a given string by using strong encryption with the local machine key as se store DevOps Artifacts Feed credentials to the local environment setting in the user scope.
    If possible the credentials will be encrypted with a local machine key and entropy only known within this module.

  .OUTPUTS
    NONE

  #>
}

Function ConvertFrom-EncryptedStringWithDpApi
{
  [CmdletBinding()]
  [OutputType([String])]
  Param(
    [Parameter(Mandatory=$True, ValueFromPipeline)]
    [String] $String,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $EncryptionEntropy = ($Script:FeedEncryptionEntropy)
  )

  Begin
  {
    "ConvertFrom-EncryptedStringWithDpApi - START" | Write-Verbose
    If (-not(Test-IsWindowsPlatform))
    {
      "ConvertFrom-EncryptedStringWithDpApi - Using cryptography functionality is only supported on Windows. Result is NOT decrypted." | Write-Warning
    }
    Else
    {
      Add-Type -AssemblyName System.Security | Out-Null
    }
  }

  Process
  {
    If (-not(Test-IsWindowsPlatform))
    {
      $String
    }
    Else
    {
      $SecureStr = [System.Convert]::FromBase64String($String)
      $EntropyBytes = [System.Text.Encoding]::Unicode.GetBytes($EncryptionEntropy)
      $Bytes = [Security.Cryptography.ProtectedData]::Unprotect($SecureStr, $EntropyBytes, [Security.Cryptography.DataProtectionScope]::LocalMachine)
      $UnEncryptedString = [System.Text.Encoding]::Unicode.GetString($Bytes)
      $UnEncryptedString
    }
  }

  End
  {
    "ConvertFrom-EncryptedStringWithDpApi - END" | Write-Verbose
  }

 <#
  .SYNOPSIS
    Powershell function to write DevOps Artifacts Feed credentials to local environment settings.

  .DESCRIPTION
    This function can be used to store DevOps Artifacts Feed credentials to the local environment setting in the user scope.
    If possible the credentials will be encrypted with a local machine key and entropy only known within this module.

  .OUTPUTS
    NONE

  #>
}

Function Update-PowerShellGetToLatest
{
  [CmdletBinding(SupportsShouldProcess)]
  Param()

  $PackageProviders = Get-PackageProvider
  $NuGetPackageProvider = $PackageProviders | Where-Object { $_.Name -eq "NuGet" }
  $PsGetPackageProvider = $PackageProviders | Where-Object { $_.Name -eq "PowerShellGet" }

  If ($Null -ne $PsGetPackageProvider -and $PsGetPackageProvider.Version.Major -ge 2 -and $PsGetPackageProvider.Version.Minor -ge 2)
  {
    "PowerShellGet package provider version {0} was found. No action needed." -f $PsGetPackageProvider.Version.ToString() | Write-Host
    Return;
  }

  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  # If we have NuGet >= 3 installed we are good to go.
  If ($Null -eq $NuGetPackageProvider -or $NuGetPackageProvider.Version.Major -lt 3)
  {
    If ($Null -eq $NuGetPackageProvider)
    {
      "Update-PowerShellGetToLatest - NuGet package provider was not found. Installing..." | Write-Verbose
    }
    Else
    {
      "Update-PowerShellGetToLatest - NuGet package provider version {0} was found. Version >= 3 required. Installing..." -f $NuGetPackageProvider.Version.ToString() | Write-Verbose
    }

    If (Test-IsWindowsPlatform -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
      Throw "To install package providers you need to run this script as administrator. Operation canceled."
      Return;
    }

    Install-PackageProvider -Name "NuGet" -Force | Out-Null
  }
  Else
  {
    "Found package provider 'NuGet' version '{0}'. No action required." -f $NuGetPackageProvider.Version.ToString() | Write-Verbose
  }

  Try
  {
    Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted" -ErrorAction Stop
  }
  Catch
  {
    Register-PSRepository -Default
  }

  "Update-PowerShellGetToLatest - Installing latest version of PowerShellGet..." | Write-Verbose
  Try
  {
    Install-Module -Name PowerShellGet -MinimumVersion 2.2.5 -Force -ErrorAction Stop | Out-Null
    $Installed = Get-Module -Name "PowerShellGet" -ListAvailable -Refresh | Sort-Object -Property Version -Descending | Select-Object -First 1
    "Update-PowerShellGetToLatest - PowerShellGet version '{0}' is installed." -f $Installed.Version.ToString() | Write-Verbose
    "PowerShellGet installation is completed." | Write-Host
  }
  Catch
  {
    "Something went wrong when installing latest version of PowerShellGet. Message: {0}" -f $_.ErrorDetails.Message | Write-Error
  }

  <#
  .SYNOPSIS
    Powershell function to support with upgrading the current PowerShellGet module towards the latest version.

  .DESCRIPTION
    This function can be used to install the latest PowerShellGet module with their depencendies.

  .OUTPUTS
    NONE

  #>
}

Function Remove-DevOpsFeedCredential
{
  [CmdletBinding()]
  [Alias("Remove-DevOpsCredential")]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Scope='Function')]
  Param(
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $FeedEnvironmentVariableNameForUser = $($Script:DefaultFeedEnvironmentVariableNameForUser),

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $FeedEnvironmentVariableNameForPat = $($Script:DefaultFeedEnvironmentVariableNameForPat)
  )

  "Remove-DevOpsFeedCredential - Removing local credentials stored within environment settings..." | Write-Verbose
  [System.Environment]::SetEnvironmentVariable($FeedEnvironmentVariableNameForUser, $Null, [System.EnvironmentVariableTarget]::User)
  [System.Environment]::SetEnvironmentVariable($FeedEnvironmentVariableNameForPat, $Null, [System.EnvironmentVariableTarget]::User)
  "All credentials removed from environment settings." | Write-Host
  "Remove-DevOpsFeedCredential - Done." | Write-Verbose

  <#
  .SYNOPSIS
    Powershell function to remove DevOps Artifacts Feed credentials from local environment settings.

  .DESCRIPTION
    This function can be used to remove DevOps Artifacts Feed credentials from the local environment setting in the user scope.

  .OUTPUTS
    NONE

  #>
}

Function Get-DevOpsFeedCredential
{
  [CmdletBinding()]
  [Alias("Get-DevOpsCredential")]
  [OutputType([System.Management.Automation.PSCredential])]
  Param(
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $FeedEnvironmentVariableNameForUser = $($Script:DefaultFeedEnvironmentVariableNameForUser),

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $FeedEnvironmentVariableNameForPat = $($Script:DefaultFeedEnvironmentVariableNameForPat),

    [Parameter(Mandatory=$False)]
    [Switch] $NoEncryption
  )

  $EnvValueUser = [System.Environment]::GetEnvironmentVariable($FeedEnvironmentVariableNameForUser, [System.EnvironmentVariableTarget]::User)
  $EnvValuePat = [System.Environment]::GetEnvironmentVariable($FeedEnvironmentVariableNameForPat, [System.EnvironmentVariableTarget]::User)

  If (-not [String]::IsNullOrEmpty($EnvValueUser) -and -not [String]::IsNullOrEmpty(($EnvValuePat)))
  {
    If (($NoEncryption.IsPresent -and $True -eq $NoEncryption) -or -not $EnvValuePat.EndsWith("="))
    {
      # Seems like encryption was not used.
      "Get-DevOpsFeedCredential - PAT token is unencrypted or NoEncryption switch is set." | Write-Verbose
    }
    Else
    {
      "Get-DevOpsFeedCredential - Looks like the PAT token is encrypted with a local machine key. Decrypting..." | Write-Verbose
      $EnvValuePat = $EnvValuePat | ConvertFrom-EncryptedStringWithDpApi
    }

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', 'No other option available')]
    $PatTokenS = ConvertTo-SecureString -String $EnvValuePat -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential($EnvValueUser, $PatTokenS)
    $Cred
  }
  Else
  {
    "Get-DevOpsFeedCredential - No DevOps credentials found within environment variables." | Write-Verbose
  }

  <#
  .SYNOPSIS
    Powershell function to retrieve DevOps Artifacts Feed credentials from local environment settings.

  .DESCRIPTION
    This function can be used to retrieve DevOps Artifacts Feed credentials from the local environment setting in the user scope.
    If possible the credentials will be decrypted with a local machine key and entropy only known within this module.

  .OUTPUTS
    The credentials found, otherwise $null.

  #>
}

Function Set-DevOpsFeedCredential
{
  [CmdletBinding()]
  [Alias("Set-DevOpsCredential")]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Scope='Function')]
  Param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String] $Username,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String] $PatToken,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $FeedEnvironmentVariableNameForUser = $($Script:DefaultFeedEnvironmentVariableNameForUser),

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $FeedEnvironmentVariableNameForPat = $($Script:DefaultFeedEnvironmentVariableNameForPat),

    [Parameter(Mandatory=$False)]
    [Switch] $NoEncryption
  )

  If ($NoEncryption.IsPresent -and $True -eq $NoEncryption)
  {
    "Set-DevOpsFeedCredential - NoEncryption switch was set so PAT token will be stored within environment variable in PLAIN TEXT." | Write-Warning
  }
  Else
  {
    "Set-DevOpsFeedCredential - Encrypting PAT token with a local machine key..." | Write-Verbose
    $PatToken = $PatToken | ConvertTo-EncryptedStringWithDpApi
  }

  "Set-DevOpsFeedCredential - Writing DevOps credentials to environment variables..." | Write-Verbose
  [System.Environment]::SetEnvironmentVariable($FeedEnvironmentVariableNameForUser, $Username, [System.EnvironmentVariableTarget]::User)
  [System.Environment]::SetEnvironmentVariable($FeedEnvironmentVariableNameForPat, $PatToken, [System.EnvironmentVariableTarget]::User)
  "DevOps Artifacts Feed Credentials saved in local environment settings." | Write-Host
  "Set-DevOpsFeedCredential - Done." | Write-Verbose

 <#
  .SYNOPSIS
    Powershell function to write DevOps Artifacts Feed credentials to local environment settings.

  .DESCRIPTION
    This function can be used to store DevOps Artifacts Feed credentials to the local environment setting in the user scope.
    If possible the credentials will be encrypted with a local machine key and entropy only known within this module.

  .OUTPUTS
    NONE

  #>
}

Function Set-DevOpsFeedContext
{
  [CmdletBinding(SupportsShouldProcess)]
  [Alias("Set-DevOpsContext")]
  Param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String] $OrganisationName,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String] $ProjectName,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $FeedName
  )


  "Set-DevOpsFeedContext- Saving DevOps Feed context within current session..." | Write-Verbose
  $NewContext = [PsCustomObject] @{
    OrganisationName = $OrganisationName
    ProjectName = $ProjectName
    FeedName = $FeedName
  }

  Set-Variable -Name "DevOpsFeedContext" -Value $NewContext -Scope Script

  "DevOps Feed context set." | Write-Host
  "Set-DevOpsFeedContext - Done." | Write-Verbose

 <#
  .SYNOPSIS
    Powershell function to setup DevOps Artifacts Feed connection context into the current user session.

  .DESCRIPTION
    This function can be used to setup the default DevOps Artifacts Feed connection context that can be used within
    other functions within this module.

  .OUTPUTS
    NONE

  #>
}

Function Get-DevOpsFeedContext
{
  [CmdletBinding()]
  [OutputType([PsCustomObject])]
  Param()

  $Script:DevOpsFeedContext

 <#
  .SYNOPSIS
    Powershell function to retrieve default DevOps Artifacts Feed connection context from the current user session.

  .DESCRIPTION
    This function can be used to retrieve the default DevOps Artifacts Feed connection context that will be used
    in other functions within this module.

  .OUTPUTS
    NONE

  #>
}

Function Register-DevOpsFeed
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$False)]
    [String] $OrganisationName = $($Script:DevOpsFeedContext.OrganisationName),

    [Parameter(Mandatory=$False)]
    [String] $ProjectName = $($Script:DevOpsFeedContext.ProjectName),

    [Parameter(Mandatory=$False)]
    [String] $FeedName = $($Script:DevOpsFeedContext.FeedName),

    [Parameter(Mandatory=$False)]
    [Switch] $NonInteractive,

    [Parameter(Mandatory=$False)]
    [String] $FeedEnvironmentVariableNameForUser = $($Script:DefaultFeedEnvironmentVariableNameForUser),

    [Parameter(Mandatory=$False)]
    [String] $FeedEnvironmentVariableNameForPat = $($Script:DefaultFeedEnvironmentVariableNameForPat),

    [Parameter(Mandatory=$False)]
    [Switch] $SkipStoreCredentials
  )

  # If one of the required connection info properties is not found, we cannot proceed.
  If ([String]::IsNullOrEmpty($OrganisationName) -or [String]::IsNullOrEmpty($ProjectName) -or [String]::IsNullOrEmpty($FeedName))
  {
    Throw "Not all connection fields have a value. Consider using function Set-DevOpsFeedContext first."
    Return;
  }

  # TODO: More encoding needed, only spacing is implemented for now.
  $ProjectNameEncoded = $ProjectName.Replace(" ", "%20")

  $FeedCredentialParams = @{
    FeedEnvironmentVariableNameForUser = $FeedEnvironmentVariableNameForUser
    FeedEnvironmentVariableNameForPat = $FeedEnvironmentVariableNameForPat
  }

  # I advise to store the PAT (with only read access to feeds) in an user environment variable.
  $Creds = Get-DevOpsFeedCredential @FeedCredentialParams
  If ($Null -eq $Creds)
  {
    If ($NonInteractive.IsPresent)
    {
      Throw "Cannot request credentials in non-interactive mode. Operation canceled."
      Return;
    }

    $Creds = Get-Credential -Message ("Enter your username and PAT token to connect to '{0}' feed within '{1}' organisation." -f $FeedName, $OrganisationName)
    If (-not($Creds))
    {
      Throw "Cannot proceed without credential info".
      Return;
    }

    $Username = $Creds.GetNetworkCredential().UserName
    $PatToken = $Creds.GetNetworkCredential().Password

    If (-not $SkipStoreCredentials.IsPresent -or -not $SkipStoreCredentials)
    {
      If (-not([String]::IsNullOrEmpty($Username)) -and -not([String]::IsNullOrEmpty($PatToken)))
      {
        "Writing feed credentials to environment settings..." | Write-Host
        Set-DevOpsCredential -Username $Username -PatToken $PatToken @FeedCredentialParams
      }
      Else
      {
        "Cannot write empty values in environment settings." | Write-Warning
      }
    }
  }

  # Maybe look at SourceLocation instead of feedname?
  $Repo = Get-PsRepository -Name $FeedName -ErrorAction SilentlyContinue
  If ($Null -ne $Repo)
  {
    "Register-DevOpsFeed - Found repository '{0}'. Unregistering..." -f $Repo.Name | Write-Verbose
    $Repo | Unregister-PSRepository | Out-Null
  }
  Else
  {
    "Register-DevOpsFeed - No repository found for feed '{0}'." -f $FeedName | Write-Verbose
  }

  $Uri_v2 = $Script:SourceUri_v2 -f $OrganisationName, $ProjectNameEncoded, $FeedName
  $Uri_v3 = $Script:SourceUri_v3 -f $OrganisationName, $ProjectNameEncoded, $FeedName
  "Register-DevOpsFeed - Registering PS repository for feed '{0}' and location '{1}'..." -f $FeedName, $Uri_v2 | Write-Verbose
  Register-PSRepository -Name $FeedName -InstallationPolicy "Trusted" -SourceLocation $Uri_v2 -PublishLocation $Uri_v2 -Credential $Creds | Out-Null
  "Register-DevOpsFeed - PS repository for feed '{0}' registered." -f $FeedName | Write-Verbose

  # Register a source for NuGet and for PowershellGet
  $PackageSources = Get-PackageSource -Name $FeedName -ErrorAction SilentlyContinue
  If ($Null -ne $PackageSources)
  {
    "Register-DevOpsFeed - Found {0} package sources for feed '{1}'. Unregistering..." -f $PackageSources.Count, $FeedName | Write-Verbose
    $PackageSources | Unregister-PackageSource | Out-Null
  }
  Else
  {
    "Register-DevOpsFeed - No package source found for feed '{0}'." -f $FeedName | Write-Verbose
  }

  "Register-DevOpsFeed - Registering package source for feed '{0}', provider '{1}', location '{2}'..." -f $FeedName, "NuGet", $Uri_v3 | Write-Verbose
  Register-PackageSource -Name $FeedName -Location $Uri_v3 -ProviderName "NuGet" -Trusted -SkipValidate -Credential $Creds | Out-Null
  "Register-DevOpsFeed - package source for feed '{0}' and provider '{1}' registered." -f $FeedName, "NuGet" | Write-Verbose

  "Register-DevOpsFeed - Registering package source for feed '{0}', provider '{1}', location '{2}'..." -f $FeedName, "PowershellGet", $Uri_v2 | Write-Verbose
  Register-PackageSource -Name $FeedName -Location $Uri_v2 -ProviderName "PowerShellGet" -PackageManagementProvider "NuGet" -Trusted -Credential $Creds | Out-Null
  "Register-DevOpsFeed - package source for feed '{0}' and provider '{1}' registered." -f $FeedName, "PowershellGet" | Write-Verbose

  "Connected with DevOps feed '{0}'" -f $FeedName | Write-Host

  <#
  .SYNOPSIS
    Powershell function to register a connection to a DevOps artifacts feed.

  .DESCRIPTION
    This function can be used to register a new connection to a DevOps artifacts feed.
    If particular components are not present they will be installed.

    To make sure the settings can be configured (and in particular credentials) this function uses
    environment settings. See NOTES for more information.

  .OUTPUTS
    NONE

  .NOTES
    As with PowerShellGet version 3 the problems with authentication on the *-Module Cmdlets is solved.
    At this moment (11-8-2022) this version is still in preview and all cmdlets are rewritten.
    https://github.com/PowerShell/PowerShellGet/issues/64#issuecomment-1204498111

    Another way to keep credentials persistent is by using the Azure Artifacts Credential Provider and env variable VSS_NUGET_EXTERNAL_FEED_ENDPOINTS
    more info: https://github.com/Microsoft/artifacts-credprovider.
    I could not get this to work, so I created this module.

  .EXAMPLE
    PS> Register-DevOpsFeed OrganisationName "Contoso" -ProjectName "myproject" -FeedName "Feed1" -NonInteractive

  #>
}

Function Find-DevOpsFeedModule
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $Name,

    [Parameter(Mandatory=$False)]
    [String] $FeedName = $($Script:DevOpsFeedContext.DefaultFeedName),

    [Parameter(Mandatory=$False)]
    [String] $FeedEnvironmentVariableNameForUser = $($Script:DefaultFeedEnvironmentVariableNameForUser),

    [Parameter(Mandatory=$False)]
    [String] $FeedEnvironmentVariableNameForPat = $($Script:DefaultFeedEnvironmentVariableNameForPat)
  )

  If ([String]::IsNullOrEmpty($FeedName))
  {
    Throw "FeedName cannot be null. Please provide a FeedName or set DevOps context first through function Set-DevOpsFeedContext."
    Return;
  }

  If ($Null -eq (Get-PSRepository -name $FeedName -ErrorAction SilentlyContinue))
  {
    Throw ("Repository for feed '{0}' is not registered. Please connect with feed first through function Register-DevOpsFeed. Operation canceled." -f $FeedName)
    Return;
  }

  $FeedCredentialParams = @{
    FeedEnvironmentVariableNameForUser = $FeedEnvironmentVariableNameForUser
    FeedEnvironmentVariableNameForPat = $FeedEnvironmentVariableNameForPat
  }

  $Creds = Get-DevOpsFeedCredential @FeedCredentialParams
  If ($Null -eq $Creds)
  {
    Throw "No credentials found. Please save credentials first through function Set-DevOpsFeedCredential. Operation canceled."
    Return;
  }

  $FindParameters = @{
    Repository = $FeedName
    Credential = $Creds
  }

  If (-not([String]::IsNullOrEmpty($Name)))
  {
    $FindParameters.Add("Name", $Name)
  }

  Find-Module @FindParameters

  <#
  .SYNOPSIS
    Powershell function that works as a wrapper around Find-Module to find modules from within a DevOps Artifacts feed.

  .DESCRIPTION
    This function can be used to find modules within a previous registered DevOps artifacts feed.

  .OUTPUTS
    If found, a list of modules.

  .EXAMPLE
    PS> Find-DevOpsFeedModule -Name "My.ModuleName"

  #>
}

Function Install-DevOpsFeedModule
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String] $Name,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $MinimumVersion,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $MaximumVersion,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $RequiredVersion,

    [Parameter(Mandatory=$False)]
    [ValidateSet("AllUsers", "CurrentUser")]
    [String] $Scope = "CurrentUser",

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String] $FeedName = $($Script:DevOpsFeedContext.FeedName),

    [Parameter(Mandatory=$False)]
    [String] $FeedEnvironmentVariableNameForUser = $($Script:DefaultFeedEnvironmentVariableNameForUser),

    [Parameter(Mandatory=$False)]
    [String] $FeedEnvironmentVariableNameForPat = $($Script:DefaultFeedEnvironmentVariableNameForPat)
  )

  If ([String]::IsNullOrEmpty($FeedName))
  {
    Throw "FeedName cannot be null. Please provide a FeedName or set DevOps context first through function Set-DevOpsFeedContext."
    Return;
  }

  If ($Null -eq (Get-PSRepository -name $FeedName -ErrorAction SilentlyContinue))
  {
    Throw ("Repository for feed '{0}' is not registered. Please connect with feed first through function Register-DevOpsFeed. Operation canceled." -f $FeedName)
    Return;
  }

  $FeedCredentialParams = @{
    FeedEnvironmentVariableNameForUser = $FeedEnvironmentVariableNameForUser
    FeedEnvironmentVariableNameForPat = $FeedEnvironmentVariableNameForPat
  }

  $Creds = Get-DevOpsFeedCredential @FeedCredentialParams
  If ($Null -eq $Creds)
  {
    Throw "No credentials found. Please save credentials first through function Set-DevOpsFeedCredential. Operation canceled."
    Return;
  }

  $Module = Find-DevOpsFeedModule -Name $Name -FeedName $FeedName
  If ($Null -eq $Module)
  {
    Throw ("Module '{0}' was not found within feed '{1}'. Operation canceled." -f $Name, $FeedName)
    Return;
  }

  $InstallParameters = @{
    Repository = $FeedName
    Name = $Name
    Scope = $Scope
    AllowClobber = $True
    Credential = $Creds
  }

  If (-not([String]::IsNullOrEmpty($MinimumVersion)))
  {
    $InstallParameters.Add("MinimumVersion", $MinimumVersion)
  }

  If (-not([String]::IsNullOrEmpty($MaximumVersion)))
  {
    $InstallParameters.Add("MaximumVersion", $MaximumVersion)
  }

  If (-not([String]::IsNullOrEmpty($RequiredVersion)))
  {
    $InstallParameters.Add("RequiredVersion", $RequiredVersion)
  }

  Install-Module @InstallParameters

  <#
  .SYNOPSIS
    Powershell function that works as a wrapper around Install-Module to install modules from a DevOps Artifacts feed.

  .DESCRIPTION
    This function can be used to install modules within a previous registered DevOps artifacts feed.

  .OUTPUTS
    NONE

  .EXAMPLE
    PS> Install-DevOpsFeedModule -Name "My.PrivateModule" -MinimumVersion "1.2.2"

  #>
}

# Exports
Export-ModuleMember -Function "Update-PowerShellGetToLatest"
Export-ModuleMember -Function "Set-DevOpsFeedEncryptionEntropy"
Export-ModuleMember -Function "Set-DevOpsFeedContext" -Alias "Set-DevOpsContext"
Export-ModuleMember -Function "Get-DevOpsFeedContext" -Alias "Get-DevOpsContext"
Export-ModuleMember -Function "Remove-DevOpsFeedCredential" -Alias "Remove-DevOpsCredential"
Export-ModuleMember -Function "Get-DevOpsFeedCredential" -Alias "Get-DevOpsCredential"
Export-ModuleMember -Function "Set-DevOpsFeedCredential" -Alias "Set-DevOpsCredential"
Export-ModuleMember -Function "Register-DevOpsFeed"
Export-ModuleMember -Function "Find-DevOpsFeedModule"
Export-ModuleMember -Function "Install-DevOpsFeedModule"