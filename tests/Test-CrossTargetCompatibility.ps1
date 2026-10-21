param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repositoryPath = Split-Path -Parent $PSScriptRoot
$hostProject = Join-Path $repositoryPath 'src/Vespertan.Cryptography.CompatibilityHost/Vespertan.Cryptography.CompatibilityHost.csproj'
$hostOutput = Join-Path $repositoryPath "src/Vespertan.Cryptography.CompatibilityHost/bin/$Configuration"

# A nonzero native process exit must fail the integration test in both Windows PowerShell and pwsh.
function Invoke-Checked {
    param([string] $Command, [string[]] $Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}

Invoke-Checked 'dotnet' @('build', $hostProject, '--configuration', $Configuration, '--verbosity', 'minimal')
$frameworkHost = Join-Path $hostOutput 'net48/Vespertan.Cryptography.CompatibilityHost.exe'
$modernHost = Join-Path $hostOutput 'net10.0/Vespertan.Cryptography.CompatibilityHost.dll'
$exchangePath = Join-Path ([IO.Path]::GetTempPath()) ('Vespertan-Crypto-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($exchangePath)
$frameworkRecords = Join-Path $exchangePath 'net48.txt'
$modernRecords = Join-Path $exchangePath 'net10.txt'
try {
    Invoke-Checked $frameworkHost @('write', $frameworkRecords)
    Invoke-Checked 'dotnet' @($modernHost, 'write', $modernRecords)
    Invoke-Checked $frameworkHost @('verify', $modernRecords)
    Invoke-Checked 'dotnet' @($modernHost, 'verify', $frameworkRecords)
    Write-Output 'Cross-target compatibility passed in both directions.'
}
finally {
    # Only delete our two known files and the now-empty directory; no recursive deletion.
    foreach ($exchangeFile in @($frameworkRecords, $modernRecords)) {
        if (Test-Path -LiteralPath $exchangeFile) { Remove-Item -LiteralPath $exchangeFile }
    }
    [IO.Directory]::Delete($exchangePath)
}
