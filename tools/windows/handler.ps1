# Register the portable bundle for this user. Run again after moving the bundle.
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Status')]
    [string] $Action = 'Install',
    [string] $TlsCertificate,
    [string] $TlsKey,
    [string] $Origin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$applicationFile = Get-Item -LiteralPath (Join-Path $PSScriptRoot 'firmica.exe')
if ($applicationFile.PSIsContainer -or ($applicationFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The application must be a regular file in a trusted installation directory.'
}
$application = $applicationFile.FullName
$classes = 'Software\Classes'
$providerPath = "$classes\Firmica.afirma"
$schemePath = "$classes\afirma"
$capabilityPath = 'Software\Firmica\Capabilities'
$registeredPath = 'Software\RegisteredApplications'
$ownerName = 'FirmicaExecutable'
$currentUser = [Microsoft.Win32.Registry]::CurrentUser

function Read-Value([string] $Path, [string] $Name) {
    $registryKey = $currentUser.OpenSubKey($Path)
    if ($null -eq $registryKey) { return $null }
    try { return $registryKey.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    finally { $registryKey.Dispose() }
}

function Assert-Owned([string] $Path) {
    $registryKey = $currentUser.OpenSubKey($Path)
    if ($null -ne $registryKey) {
        try {
            if ($registryKey.GetValue($ownerName) -cne $application) {
                throw "Registration at HKCU\$Path belongs to another installation; it was not changed."
            }
        } finally { $registryKey.Dispose() }
    }
}

function Write-Values([string] $Path, [hashtable] $Values) {
    $registryKey = $currentUser.CreateSubKey($Path)
    try {
        foreach ($entry in $Values.GetEnumerator()) {
            $registryKey.SetValue($entry.Key, $entry.Value, [Microsoft.Win32.RegistryValueKind]::String)
        }
    } finally { $registryKey.Dispose() }
}

function Quote-Argument([string] $Value) {
    # A registry launch command is parsed by Windows, never by cmd/PowerShell.
    # Reject shell association placeholders in static arguments.
    # Doubling trailing slashes preserves CRT argv.
    if ($Value.Contains('"') -or $Value.Contains('%') -or $Value.Contains([char]0)) { throw 'Invalid command argument.' }
    return '"' + [regex]::Replace($Value, '(\\+)$', '$1$1') + '"'
}

Assert-Owned $providerPath
Assert-Owned $capabilityPath
$registered = Read-Value $registeredPath 'Firmica'
if ($null -ne $registered -and $registered -cne $capabilityPath) {
    throw 'The Firmica application registration belongs to another application; it was not changed.'
}

if ($Action -eq 'Status') {
    if ((Read-Value $providerPath $ownerName) -cne $application) {
        Write-Output 'Firmica is not registered from this bundle.'
    } else {
        Write-Output "Registered executable: $application"
        Write-Output ('Launch command: ' + (Read-Value "$providerPath\shell\open\command" ''))
        Write-Output 'The active default is selected in Windows Settings > Apps > Default apps.'
    }
    exit 0
}

if ($Action -eq 'Install') {
    if (!$TlsCertificate -or !$TlsKey -or !$Origin) {
        throw 'Install requires -TlsCertificate, -TlsKey and -Origin.'
    }
    $browserOrigin = [uri] $Origin
    if (!$browserOrigin.IsAbsoluteUri -or $browserOrigin.Scheme -cnotin @('http', 'https') -or
        $browserOrigin.UserInfo -or $browserOrigin.Query -or $browserOrigin.Fragment -or
        $browserOrigin.GetLeftPart([UriPartial]::Authority) -cne $Origin) {
        throw 'Origin must be one exact HTTP(S) origin without a trailing slash, credentials, path, query or fragment.'
    }
    $certificateFile = Get-Item -LiteralPath $TlsCertificate
    $keyFile = Get-Item -LiteralPath $TlsKey
    foreach ($file in @($certificateFile, $keyFile)) {
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'TLS inputs must be regular files, not reparse points.'
        }
    }
    $command = (Quote-Argument $application) + ' --tls-cert ' + (Quote-Argument $certificateFile.FullName) +
        ' --tls-key ' + (Quote-Argument $keyFile.FullName) + ' --origin ' + (Quote-Argument $Origin) + ' -- "%1"'

    # Never overwrite an existing protocol owner, including a machine registration.
    $scheme = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey('afirma')
    $claimScheme = $null -eq $scheme
    if ($null -ne $scheme) {
        try {
            $claimScheme = ($scheme.GetValue($ownerName) -ceq $application) -and
                ((Read-Value "$schemePath\shell\open\command" '') -ceq (Read-Value "$providerPath\shell\open\command" ''))
        }
        finally { $scheme.Dispose() }
    }
    Write-Values $providerPath @{ '' = 'Firmica signature request'; 'URL Protocol' = ''; $ownerName = $application }
    Write-Values "$providerPath\DefaultIcon" @{ '' = ((Quote-Argument $application) + ',0') }
    Write-Values "$providerPath\shell\open\command" @{ '' = $command }
    Write-Values $capabilityPath @{ ApplicationName = 'Firmica'; ApplicationDescription = 'CAdES document signing'; $ownerName = $application }
    Write-Values "$capabilityPath\URLAssociations" @{ afirma = 'Firmica.afirma' }
    Write-Values $registeredPath @{ Firmica = $capabilityPath }
    if ($claimScheme) {
        Write-Values $schemePath @{ '' = 'Firmica signature request'; 'URL Protocol' = ''; $ownerName = $application }
        Write-Values "$schemePath\shell\open\command" @{ '' = $command }
    }
    Write-Output "Registered Firmica from $application for this user."
    Write-Output 'Select Firmica for afirma in Windows Settings > Apps > Default apps if another handler is selected.'
    Write-Output 'TLS files must remain in a private directory. No trust store was changed.'
} else {
    # Do not delete a scheme that another application has taken over since install.
    if ((Read-Value $schemePath $ownerName) -ceq $application) {
        $schemeCommand = Read-Value "$schemePath\shell\open\command" ''
        $providerCommand = Read-Value "$providerPath\shell\open\command" ''
        if ($schemeCommand -ceq $providerCommand) { $currentUser.DeleteSubKeyTree($schemePath, $false) }
    }
    $currentUser.DeleteSubKeyTree($providerPath, $false)
    $currentUser.DeleteSubKeyTree($capabilityPath, $false)
    $applications = $currentUser.OpenSubKey($registeredPath, $true)
    if ($null -ne $applications) {
        try { $applications.DeleteValue('Firmica', $false) }
        finally { $applications.Dispose() }
    }
    Write-Output 'Removed this bundle registration. Windows default choices were not changed.'
}

# Notify the shell of association changes without resetting protected UserChoice.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FirmicaAssociations {
    [DllImport("shell32.dll")]
    public static extern void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2);
}
'@
[FirmicaAssociations]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
