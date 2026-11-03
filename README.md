# RenameComputer
Sample app for renaming a Hybrid Azure AD joined (AD-joined) device after an Autopilot deployment.  Note that you will probably want to customize the RenameComputer.ps1 script to add your own naming logic, then build a new RenameComputer.intunewin package by running the "makeapp.cmd" file (it can be run from any directory; it always packages the RenameComputer folder next to it).

The included IntuneWinAppUtil.exe may be out of date. If the app fails to install with an error such as 0x80070001, download the latest version from https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool, replace IntuneWinAppUtil.exe, and rebuild the package.

To set up the RenameComputer app in Intune, perform the following steps.

Add the RenameComputer.intunewin app to Intune and specify the following command line:

powershell.exe -noprofile -executionpolicy bypass -file .\RenameComputer.ps1

To only rename devices whose current name starts with a specific prefix, add the -Prefix parameter, e.g.:

powershell.exe -noprofile -executionpolicy bypass -file .\RenameComputer.ps1 -Prefix DESKTOP-

Set the install behavior to "System". On AD-joined devices the computer account renames itself, so the script must run as SYSTEM (when run interactively, the logged-on user needs rights to rename the computer object in AD instead, otherwise you'll see "Access is denied").

To "uninstall" the app, the following can be used (for example, to get the app to re-install):

cmd.exe /c del %ProgramData%\Microsoft\RenameComputer\RenameComputer.ps1.tag

Specify the platforms and minimum OS version that you want to support.

For a detection rule, specify the path and file and "File or folder exists" detection method:

%ProgramData%\Microsoft\RenameComputer RenameComputer.ps1.tag

Deploy the app as a required app to an appropriate set of devices.

If the rename can't happen right away (no domain connectivity, or the rename fails), the script registers a "RenameComputer" scheduled task that retries at startup, at logon, and daily at 9am. Details are logged to %ProgramData%\Microsoft\RenameComputer\RenameComputer.log.
