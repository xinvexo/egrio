# Makes sure the Windows App Runtime the app needs is installed; the Egrio
# installer (installer.nsi) runs it elevated. The app needs the runtime's x64
# framework package of its major version, at least as new as the release it
# is built with (-Version, such as 2.6.5). When no such package is registered,
# Microsoft's runtime installer for that release is downloaded, checked to
# carry a valid Microsoft signature, and run quietly; run elevated, it
# installs the runtime for all users ("Windows App SDK deployment guide for
# framework-dependent apps packaged with external location or unpackaged").
#
# Exit codes: 0 when the runtime is installed, 1 when the download fails, 2
# when the download is not signed by Microsoft, otherwise the runtime
# installer's own.
param([Parameter(Mandatory = $true)][string] $Version)

$ErrorActionPreference = 'Stop'
# Windows PowerShell's progress display slows a download to a crawl.
$ProgressPreference = 'SilentlyContinue'

$major, $minor = $Version.Split('.')[0, 1]
$minimum = [version]"$Version.0"
try {
    $installed = Get-AppxPackage -Name "Microsoft.WindowsAppRuntime.$major" |
        Where-Object { $_.Architecture -eq 'X64' -and [version]$_.Version -ge $minimum }
    if ($installed) { exit 0 }
} catch {
    # Without the Appx module nothing is known; the runtime installer leaves
    # installed packages as they are.
}

# The release's x64 installer as the Windows App SDK downloads page links it.
$url = "https://aka.ms/windowsappsdk/$major.$minor/$Version/windowsappruntimeinstall-x64.exe"
$installer = Join-Path $PSScriptRoot 'WindowsAppRuntimeInstall-x64.exe'
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
} catch {
    exit 1
}
$signature = Get-AuthenticodeSignature -FilePath $installer
if ($signature.Status -ne 'Valid' -or
    $signature.SignerCertificate.Subject -notlike 'CN=Microsoft Corporation,*') {
    exit 2
}
$process = Start-Process -FilePath $installer -ArgumentList '--quiet' -Wait -PassThru
exit $process.ExitCode
