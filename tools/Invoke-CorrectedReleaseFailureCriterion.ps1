param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("credential_rotation", "credential_revoke", "replay")]
    [string]$Criterion,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDir,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{7,127}$')]
    [string]$RunId
)

$ErrorActionPreference = "Stop"
$utf8 = [Text.UTF8Encoding]::new($false)
$repo = [IO.Path]::GetFullPath((Resolve-Path (Join-Path $PSScriptRoot "..")).Path)
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDir)
$exporter = "crates/rusty-manifold-peer/src/bin/export_corrected_release_failure.rs"
$exportSchema = "rusty.manifold.corrected_release.failure_transition_evidence.v1"
$phaseExportSchema = "rusty.manifold.corrected_release.failure_transition_phase.v1"
$fatalPattern = '(?im)^(?:.{0,512}?\s)?(?:FATAL EXCEPTION(?: IN SYSTEM PROCESS)?|Fatal signal\b|thread\s+''[^'']+''\s+panicked at\b|error:\s+test failed\b|test result:\s+FAILED\b|FAILED(?:\s|$))'
New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null

$revision = (& git -C $repo rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $revision -cnotmatch '^[0-9a-f]{40}$') {
    throw "Could not bind the Manifold source revision."
}
$sourcePath = Join-Path $repo $exporter
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Corrected-release Rust transition exporter is missing: $exporter"
}

function Bound-File([string]$Path) {
    return [ordered]@{
        path = [IO.Path]::GetFullPath($Path)
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Write-Raw([string]$Name, [string]$Text) {
    $path = Join-Path $evidenceRoot "$Name.raw.txt"
    [IO.File]::WriteAllText($path, ($Text.TrimEnd() + [Environment]::NewLine), $utf8)
    return Bound-File $path
}

function Write-Artifact([string]$Name, [object]$Value) {
    $path = Join-Path $evidenceRoot "$Name.json"
    [IO.File]::WriteAllText(
        $path,
        (($Value | ConvertTo-Json -Depth 64) + [Environment]::NewLine),
        $utf8
    )
    return Bound-File $path
}

$transitionPath = Join-Path $evidenceRoot "$Criterion-rust-transition.raw.json"
$previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
Push-Location $repo
try {
    $exportOutput = @(& cargo run --quiet -p rusty-manifold-peer `
        --bin export_corrected_release_failure -- `
        --criterion $Criterion --output $transitionPath 2>&1)
    $exportExit = $LASTEXITCODE
} finally {
    Pop-Location
    $ErrorActionPreference = $previous
}
$exportText = (($exportOutput | ForEach-Object { [string]$_ }) -join [Environment]::NewLine)
if ($exportText) { Write-Output $exportText }
if ($exportExit -ne 0) {
    throw "$Criterion current-source Rust transition exporter failed with exit code $exportExit."
}
if (-not (Test-Path -LiteralPath $transitionPath -PathType Leaf)) {
    throw "$Criterion Rust transition exporter emitted no evidence."
}
try {
    $transition = Get-Content -LiteralPath $transitionPath -Raw | ConvertFrom-Json
} catch {
    throw "$Criterion Rust transition evidence is invalid JSON: $($_.Exception.Message)"
}
$testId = "rusty.manifold.corrected_release.$Criterion"
if ([string]$transition.'$schema' -cne $exportSchema -or
    [string]$transition.criterion_id -cne $Criterion -or
    [string]$transition.test_id -cne $testId -or
    [string]$transition.facts.kind -cne $Criterion) {
    throw "$Criterion Rust transition evidence has the wrong schema/identity."
}
foreach ($phaseName in @("before", "failure", "recovery")) {
    $phaseValue = $transition.$phaseName
    if ([string]$phaseValue.'$schema' -cne $phaseExportSchema -or
        [string]$phaseValue.phase -cne $phaseName -or
        $phaseValue.transition_complete -ne $true) {
        throw "$Criterion Rust transition phase is incomplete: $phaseName"
    }
}
if ([long]$transition.failure.authority_revision -lt [long]$transition.before.authority_revision -or
    [long]$transition.recovery.authority_revision -lt [long]$transition.failure.authority_revision) {
    throw "$Criterion Rust transition authority revision regressed."
}

$facts = $transition.facts
$observations = switch ($Criterion) {
    "credential_rotation" {
        [ordered]@{
            old_generation = [long]$facts.old_generation
            new_generation = [long]$facts.new_generation
            old_rejected = ([string]$facts.old_rejection -ceq "credential_not_current")
            new_accepted = [bool]$facts.new_accepted
        }
    }
    "credential_revoke" {
        [ordered]@{
            revoked_generation = [long]$facts.revoked_generation
            revoked_rejected = ([string]$facts.revoked_rejection -ceq "credential_not_current")
            active_grant_count = [long]$facts.revoked_peer_active_credential_count
        }
    }
    "replay" {
        [ordered]@{
            nonce = [string]$transition.failure.rendezvous_receipt.nonce_sha256
            first_accepted = [bool]$facts.first_accepted
            replay_rejected = ([string]$facts.replay_rejection -ceq "replay") -and
                [bool]$facts.state_unchanged_after_replay
        }
    }
}

$failureState = switch ($Criterion) {
    "credential_rotation" { "credential_rotated" }
    "credential_revoke" { "credential_revoked" }
    "replay" { "replay_attempted" }
}
$recoveryState = switch ($Criterion) {
    "credential_rotation" { "recovered" }
    "credential_revoke" { "rejected" }
    "replay" { "rejected" }
}
$transitionRaw = Bound-File $transitionPath
$observedAt = [DateTimeOffset]::UtcNow.ToString('o')
$injection = Write-Artifact "$Criterion-damaged-input" ([ordered]@{
    schema = "rusty.morphospace.failure_test_injection.v1"
    criterion_id = $Criterion
    test_id = $testId
    injection_kind = $Criterion
    target = "$exporter::$Criterion"
    triggered = $true
    repository_revision = $revision
    run_id = $RunId
    observed_at = $observedAt
    raw_evidence = $transitionRaw
})

$phaseBindings = [ordered]@{}
foreach ($phaseName in @("before", "failure", "recovery")) {
    $phaseValue = $transition.$phaseName
    $rawText = $phaseValue | ConvertTo-Json -Depth 64
    $raw = Write-Raw "$Criterion-$phaseName" $rawText
    $state = if ($phaseName -ceq "before") {
        "ready"
    } elseif ($phaseName -ceq "failure") {
        $failureState
    } else {
        $recoveryState
    }
    $cleanup = $phaseName -cne "failure"
    $phaseObservations = if ($phaseName -ceq "recovery") { $observations } else { [ordered]@{} }
    $phaseBindings[$phaseName] = Write-Artifact "$Criterion-$phaseName" ([ordered]@{
        schema = "rusty.morphospace.failure_test_phase_receipt.v1"
        criterion_id = $Criterion
        test_id = $testId
        phase = $phaseName
        repository_revision = $revision
        injection_sha256 = $injection.sha256
        observed_state = $state
        cleanup_complete = $cleanup
        fatal_count = [long]([regex]::Matches($rawText, $fatalPattern).Count)
        authority_revision = [long]$phaseValue.authority_revision
        provider_epoch = 1L
        run_id = $RunId
        observed_at = [DateTimeOffset]::UtcNow.ToString('o')
        raw_evidence = $raw
        observations = $phaseObservations
    })
}

$marker = [ordered]@{
    schema = "rusty.morphospace.failure_test_result.v2"
    criterion_id = $Criterion
    test_id = $testId
    run_id = $RunId
    artifacts = [ordered]@{
        damaged_input = $injection
        before = $phaseBindings.before
        failure = $phaseBindings.failure
        recovery = $phaseBindings.recovery
    }
}
Write-Output ("MORPHOSPACE_FAILURE_TEST_V2 " + ($marker | ConvertTo-Json -Depth 32 -Compress))
