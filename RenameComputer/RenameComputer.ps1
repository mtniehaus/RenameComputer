
<#PSScriptInfo

.VERSION 1.4

.GUID 3b42d8c8-cda5-4411-a623-90d812a8e29e

.AUTHOR Michael Niehaus

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
Version 1.4: Fixed 64-bit relaunch failing when no prefix was specified, pass the prefix to the scheduled task,
             fixed the scheduled task startup/logon delay, retry via the scheduled task (instead of rebooting) when
             the rename fails, strip invalid characters from the new name, removed leftover debug output.
Version 1.3: Only rename if the current name's prefix matches
Version 1.2: Fixed PowerShell 5.1 bug (BiosSeralNumber)
Version 1.1: Updated for AAD scenarios too.
Version 1.0: Initial version.

.PRIVATEDATA

#>

<#

.DESCRIPTION
Rename the computer using the logic contained in this script.  This will work for AD or AAD-joined devices, or even workgroup machines.
Note that if the device is joined to AD, there must be connectivity to the domain and the computer must have the rights to rename itself.
This means the script must run as SYSTEM (e.g. Intune install behavior "System"); when run interactively, the logged-on user needs the rights instead.

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $False)] [string] $Prefix = ""
)

# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64")
{
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        # Only pass -Prefix when it has a value: PowerShell 5.1 drops empty arguments to native commands,
        # which would leave a dangling -Prefix and make the 64-bit process fail before doing anything.
        $relaunchArgs = @("-NoProfile", "-ExecutionPolicy", "bypass", "-File", "$PSCommandPath")
        if ($Prefix -ne "") {
            $relaunchArgs += @("-Prefix", $Prefix)
        }
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" @relaunchArgs
        Exit $lastexitcode
    }
}

# Initialization
$dest = "$($env:ProgramData)\Microsoft\RenameComputer"
if (-not (Test-Path $dest))
{
    New-Item -Path $dest -ItemType Directory -Force | Out-Null
}

# Create a tag file just so Intune knows this was installed
Set-Content -Path "$dest\RenameComputer.ps1.tag" -Value "Installed"

Start-Transcript "$dest\RenameComputer.log" -Append
Write-Host "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "Prefix: $Prefix"

# Schedule this script to run again later (used when we can't rename right now)
function Register-RenameTask
{
    # Check to see if already scheduled
    $existingTask = Get-ScheduledTask -TaskName "RenameComputer" -ErrorAction SilentlyContinue
    if ($null -ne $existingTask)
    {
        Write-Host "Scheduled task already exists."
        return
    }

    # Copy myself to a safe place (always refresh so the task runs the latest version)
    $scriptCopy = "$dest\RenameComputer.ps1"
    if ($PSCommandPath -ne $scriptCopy)
    {
        Copy-Item $PSCommandPath $scriptCopy -Force
    }

    # Create the scheduled task action, passing along the prefix so the scheduled run honors it too
    $taskArgs = "-NoProfile -ExecutionPolicy bypass -WindowStyle Hidden -File `"$scriptCopy`""
    if ($Prefix -ne "") {
        $taskArgs += " -Prefix `"$Prefix`""
    }
    $action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument $taskArgs

    # Create the scheduled task triggers.  Startup and logon triggers ignore -RandomDelay, so set their Delay instead.
    $delay = "PT5M"
    $logonTrigger = New-ScheduledTaskTrigger -AtLogOn
    $logonTrigger.Delay = $delay
    $startupTrigger = New-ScheduledTaskTrigger -AtStartup
    $startupTrigger.Delay = $delay
    $triggers = @(
        (New-ScheduledTaskTrigger -Daily -At 9am),
        $logonTrigger,
        $startupTrigger
    )

    # Register the scheduled task
    Register-ScheduledTask -User SYSTEM -Action $action -Trigger $triggers -TaskName "RenameComputer" -Description "RenameComputer" -Force | Out-Null
    Write-Host "Scheduled task created."
}

# Bail out if the prefix doesn't match (if specified)
$details = Get-ComputerInfo
if (($Prefix -ne "") -and (-not $details.CsName.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase))) {
    Write-Host "Device name doesn't match specified prefix, bailing out. Prefix=$Prefix ComputerName=$($details.CsName)"
    Stop-Transcript
    Exit 0
}

# See if we are AD or AAD joined
$isAD = $false
$isAAD = $false
$tenantID = $null
if ($details.CsPartOfDomain) {
    Write-Host "Device is joined to AD domain: $($details.CsDomain)"
    $isAD = $true
} else {
    if (Test-Path "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo") {
        $subKey = Get-Item "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo"
        $guids = $subKey.GetSubKeyNames()
        foreach($guid in $guids) {
            $guidSubKey = $subKey.OpenSubKey($guid);
            $tenantID = $guidSubKey.GetValue("TenantId");
        }
    }
    if ($null -ne $tenantID) {
        Write-Host "Device is joined to AAD tenant: $tenantID"
        $isAAD = $true
    } else {
        Write-Host "Not part of a AAD or AD, in a workgroup."
    }
}

# Make sure we have connectivity
$goodToGo = $true
if ($isAD) {
    $dcInfo = [ADSI]"LDAP://RootDSE"
    if ($null -eq $dcInfo.dnsHostName)
    {
        Write-Host "No connectivity to the domain, unable to rename at this point."
        $goodToGo = $false
    }
}

if (-not $goodToGo)
{
    Register-RenameTask
    Stop-Transcript
    Exit 0
}

# Get the new computer name: use the asset tag (maximum of 13 characters), or the
# serial number if no asset tag is available (replace this logic if you want)
$systemEnclosure = Get-CimInstance -ClassName Win32_SystemEnclosure
if (($null -eq $systemEnclosure.SMBIOSAssetTag) -or ($systemEnclosure.SMBIOSAssetTag.Trim() -eq "")) {
    # Stupid PowerShell 5.1 bug
    if ($null -ne $details.BiosSerialNumber) {
        $assetTag = $details.BiosSerialNumber
    } else {
        $assetTag = $details.BiosSeralNumber
    }
} else {
    $assetTag = $systemEnclosure.SMBIOSAssetTag
}

# Computer names can only contain letters, digits and hyphens
$assetTag = "$assetTag" -replace '[^A-Za-z0-9-]', ''
if ($assetTag -eq "") {
    Write-Host "Unable to determine an asset tag or serial number, not renaming."
    Stop-Transcript
    Exit 0
}
if ($assetTag.Length -gt 13) {
    $assetTag = $assetTag.Substring(0, 13)
}
if ($details.CsPCSystemTypeEx -eq 1) {
    $newName = "D-$assetTag"
} else {
    $newName = "L-$assetTag"
}

# Is the computer name already set?  If so, bail out
if ($newName -ieq $details.CsName) {
    Write-Host "No need to rename computer, name is already set to $newName"
    Disable-ScheduledTask -TaskName "RenameComputer" -ErrorAction Ignore | Out-Null
    Unregister-ScheduledTask -TaskName "RenameComputer" -Confirm:$false -ErrorAction Ignore
    Stop-Transcript
    Exit 0
}

# Set the computer name.  If it fails (e.g. a DC that can't service the request yet, or the name is in use),
# don't reboot: schedule a retry instead so the device isn't stuck with a failed rename.
Write-Host "Renaming computer to $($newName)"
try {
    Rename-Computer -NewName $newName -Force -ErrorAction Stop
}
catch {
    Write-Host "Rename failed: $($_.Exception.Message)"
    if ($isAD) {
        Write-Host "If the name is reported as already taken, check AD and DNS for an existing computer object or record named $newName."
    }
    Register-RenameTask
    Stop-Transcript
    Exit 0
}

# Rename succeeded, so remove the scheduled task (if it exists)
Disable-ScheduledTask -TaskName "RenameComputer" -ErrorAction Ignore | Out-Null
Unregister-ScheduledTask -TaskName "RenameComputer" -Confirm:$false -ErrorAction Ignore
Write-Host "Scheduled task unregistered."

# Make sure we reboot if still in ESP/OOBE by reporting a 1641 return code (hard reboot)
if ($details.CsUserName -match "defaultUser")
{
    Write-Host "Exiting during ESP/OOBE with return code 1641"
    Stop-Transcript
    Exit 1641
}
else {
    Write-Host "Initiating a restart in 10 minutes"
    & shutdown.exe /g /t 600 /f /c "Restarting the computer due to a computer name change.  Save your work."
    Stop-Transcript
    Exit 0
}
