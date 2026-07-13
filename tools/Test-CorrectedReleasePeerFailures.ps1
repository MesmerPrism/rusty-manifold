param(
    [Parameter(Mandatory = $true)]
    [Alias("Criterion")]
    [ValidateSet("credential_rotation", "credential_revoke", "replay")]
    [string]$MorphospaceFailureCriterion
)

$ErrorActionPreference = "Stop"
$markerPrefix = "MORPHOSPACE_FAILURE_TEST_V1 "
$markerSchema = "rusty.morphospace.failure_test_result.v1"
$fatalPattern = '(?m)^\s*(?:FATAL EXCEPTION(?: IN SYSTEM PROCESS)?|Fatal signal\b|thread\s+''[^'']+''\s+panicked at\b|error:\s+test failed\b|test result:\s+FAILED\b|FAILED(?:\s|$))'
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

# This marker is a private release-harness protocol, not a Manifold contract or
# schema authority. The adapter derives it from tracked Manifold tests and does
# not add a rusty.morphospace.* schema to the crate/catalog surface.
$cases = [ordered]@{
    credential_rotation = [ordered]@{
        source = "crates/rusty-manifold-peer/src/enrollment.rs"
        test = "enrollment::tests::key_rotation_and_revocation_fail_closed_for_signed_evidence"
        test_id = "rusty-manifold-peer.enrollment.key-rotation"
        outcome = "recovered"
        witnesses = @(
            "assert!(rotation.applied);",
            "Some(ManifoldRendezvousRejectionReason::CredentialNotCurrent)",
            "assert!(current_receipt.accepted);"
        )
    }
    credential_revoke = [ordered]@{
        source = "crates/rusty-manifold-peer/src/enrollment.rs"
        test = "enrollment::tests::key_rotation_and_revocation_fail_closed_for_signed_evidence"
        test_id = "rusty-manifold-peer.enrollment.key-revoke"
        outcome = "rejected"
        witnesses = @(
            "assert!(revocation.applied);",
            "current_request.expected_enrollment_authority_revision = revoked.authority_revision;",
            "Some(ManifoldRendezvousRejectionReason::CredentialNotCurrent)"
        )
    }
    replay = [ordered]@{
        source = "crates/rusty-manifold-peer/src/direct_lane_lease.rs"
        test = "direct_lane_lease::tests::replay_duplicate_revoke_and_expiry_are_stateful"
        test_id = "rusty-manifold-peer.direct-lane.replay-revoke-expiry"
        outcome = "rejected"
        witnesses = @(
            "assert_eq!(unchanged, issued);",
            "Some(ManifoldDirectLaneLeaseRejectionReason::ReplayedRequest)",
            'replayed_revocation.expect_err("revocation replay must reject")',
            "assert!(expired.leases.iter().all(|lease| lease.revoked));"
        )
    }
}

$case = $cases[$MorphospaceFailureCriterion]
$sourcePath = Join-Path $repo ([string]$case.source)
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Peer failure source is missing: $($case.source)"
}
& git -C $repo ls-files --error-unmatch -- ([string]$case.source) 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Peer failure source is not tracked: $($case.source)" }
$sourceText = Get-Content -LiteralPath $sourcePath -Raw
$sourceWitnessCount = 0
foreach ($witness in @($case.witnesses)) {
    if ($sourceText.IndexOf([string]$witness, [StringComparison]::Ordinal) -lt 0) {
        throw "$MorphospaceFailureCriterion source assertion witness drifted: $witness"
    }
    $sourceWitnessCount += 1
}

$previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
Push-Location $repo
try {
    $output = @(& cargo test -p rusty-manifold-peer ([string]$case.test) -- --exact --nocapture 2>&1)
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
    $ErrorActionPreference = $previous
}
$text = (($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine)
Write-Output $text
if ($exitCode -ne 0) {
    throw "$MorphospaceFailureCriterion cargo test failed with exit code $exitCode."
}

$testPattern = '(?m)^test\s+' + [regex]::Escape([string]$case.test) + '\s+\.\.\.\s+ok\s*$'
$matchedTests = ([regex]::Matches($text, $testPattern)).Count
if ($matchedTests -ne 1) {
    throw "$MorphospaceFailureCriterion expected exactly one passing targeted test, got $matchedTests."
}
$fatalCount = ([regex]::Matches($text, $fatalPattern)).Count
if ($fatalCount -ne 0) {
    throw "$MorphospaceFailureCriterion test output contains $fatalCount fatal marker(s)."
}
$cleanupComplete = (
    $exitCode -eq 0 -and
    $matchedTests -eq 1 -and
    $sourceWitnessCount -eq @($case.witnesses).Count -and
    $fatalCount -eq 0
)
if (-not $cleanupComplete) {
    throw "$MorphospaceFailureCriterion did not derive complete CPU-only authority cleanup."
}

$result = [ordered]@{
    schema = $markerSchema
    criterion_id = $MorphospaceFailureCriterion
    test_id = [string]$case.test_id
    status = "pass"
    observed_outcome = [string]$case.outcome
    cleanup_complete = $cleanupComplete
    fatal_count = $fatalCount
}
Write-Output ($markerPrefix + ($result | ConvertTo-Json -Compress))
