[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True)]
  [ValidateNotNullOrEmpty()]
  [String] $ApiKey
)

if($Verbose)
{
  $VerbosePreference = "Continue"
}

$ErrorActionPreference = "Stop"
$WarningPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$RootPath = Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath "..\..\")
$ModulePath = Join-Path -Path $RootPath -ChildPath "src"

<# Publish To PowerShell Gallery (www.powershellgallery.com) #>
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Publish-Module -Path $ModulePath -NuGetApiKey $ApiKey -Repository PSGallery
