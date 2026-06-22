$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$File,
        [string[]]$Arguments = @()
    )

    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $RepoRoot
try {
    Invoke-Checked "cargo fmt" "cargo" @("fmt", "--all", "--check")
    Invoke-Checked "cargo test" "cargo" @("test", "--workspace")
    Invoke-Checked "fixture validate" "cargo" @("run", "-p", "rusty-manifold-fixtures", "--", "validate")
    Invoke-Checked "fixture simulate" "cargo" @("run", "-p", "rusty-manifold-fixtures", "--", "simulate", "--check")
    Invoke-Checked "fixture diff" "cargo" @("run", "-p", "rusty-manifold-fixtures", "--", "diff", "--check")
    Invoke-Checked "fixture synthetic scalar" "cargo" @("run", "-p", "rusty-manifold-fixtures", "--", "emit-synthetic-scalar", "--check", "--expected", "fixtures/synthetic/synthetic-scalar-oscillator-samples.jsonl")
    Invoke-Checked "schema export" "cargo" @("run", "-p", "rusty-manifold-schema", "--", "export", "--check")
} finally {
    Pop-Location
}
