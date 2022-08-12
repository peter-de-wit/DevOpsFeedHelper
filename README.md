[![GitHub release](https://img.shields.io/github/release/peter-de-wit/DevOpsFeedHelper)](https://github.com/peter-de-wit/DevOpsFeedHelper/releases/)
[![Github all releases](https://img.shields.io/github/downloads/peter-de-wit/DevOpsFeedHelper/total.svg)](https://gitHub.com/peter-de-wit/DevOpsFeedHelper/releases/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://peter-de-wit/DevOpsFeedHelper/graphs/commit-activity)

# DevOpsFeedHelper

This repository contains of a Powershell module that can help with connecting to and maintaining DevOps Artifacts Feed connections.

# Installation and Update

This module is available on the [PowerShell Gallery](https://www.powershellgallery.com/packages/DevOpsFeedHelper)
and can be installed like so:

```PowerShell
PS> Install-Module -Name DevOpsFeedHelper -Scope CurrentUser
```

If the module was installed via `Install-Module` it can be conveniently updated
from an elevated PowerShell:

```PowerShell
PS> Update-Module -Name DevOpsFeedHelper
```

# Getting Started

...

# Documentation

The module is documented through PS help. This is resonably readable with the
PowerShell command `Get-Help`.

For example:

~~~ PowerShell
PS> Get-Help about_DevOpsFeedHelper
~~~

~~~ PowerShell
PS> Get-Help Register-DevOpsFeed -Online
~~~

# Support

If you found an issue with the module or want to suggest and enhancement, head over to
the [Issues](https://github.com/peter-de-wit/DevOpsFeedHelper/issues) page on GitHub and
submit a bug report or enhancement request. Make sure
to also check the
[wiki](https://github.com/peter-de-wit/DevOpsFeedHelper/wiki) for
tips and the FAQ first.

# See Also
* [Install-Module](https://docs.microsoft.com/en-us/powershell/module/powershellget/Install-Module?view=powershell-5.1) -
  Download one or more modules from an online gallery, and installs them on the local computer.
* [Update-Module](https://docs.microsoft.com/en-us/powershell/module/powershellget/update-module?view=powershell-5.1) -
  Downloads and installs the newest version of specified modules from an online gallery to the local computer. 
* [PowerShellGet](https://docs.microsoft.com/en-us/powershell/module/powershellget/?view=powershell-5.1#powershellget) -
  a package manager for Windows PowerShell.
* `DevOpsFeedHelper` on the [Powershell Gallery](https://www.powershellgallery.com/packages/DevOpsFeedHelper).


