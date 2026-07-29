[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$fixtureRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $fixtureRoot '..\..')).Path

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)

    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message (expected '$Expected', got '$Actual')"
    }
}

$contractMap = Read-Json (Join-Path $fixtureRoot 'contract-map.json')
$valid = Read-Json (Join-Path $fixtureRoot 'valid-flow.json')
$damaged = Read-Json (Join-Path $fixtureRoot 'damaged-mappings.json')
$localPolicy = Read-Json (Join-Path $fixtureRoot 'local-control-policy.json')
$pairingEvidence = Read-Json (Join-Path $fixtureRoot 'controller-evidence.json')
$commandRequest = Read-Json (Join-Path $fixtureRoot 'command-request.json')
$safeStatusPath = Join-Path $fixtureRoot 'safe-status.json'
$safeStatusRaw = Get-Content -LiteralPath $safeStatusPath -Raw
$safeStatus = $safeStatusRaw | ConvertFrom-Json

Assert-Equal $contractMap.profile_id 'trusted_local_http_v1' 'contract map profile id must be exact'
Assert-Equal $contractMap.authority_owner 'rusty.manifold' 'Manifold must remain authority owner'
Assert-Equal $contractMap.effect_owner 'rusty.quest.player' 'Quest player must remain effect owner'
Assert-True (-not [bool]$contractMap.default_enabled) 'trusted local HTTP must be disabled by default'
Assert-Equal $contractMap.transport_security.confidentiality 'none' 'trusted local HTTP must not claim confidentiality'
Assert-Equal $localPolicy.'$schema' 'rusty.manifold.local_control.policy.v1' 'local-control policy schema must be exact'
Assert-Equal $localPolicy.trusted_adapter_id $localPolicy.adapter_identity.client_id 'admission identity must be the exact trusted Quest adapter'
Assert-True ($localPolicy.controller_id -ne $localPolicy.adapter_identity.client_id) 'logical browser controller id must remain distinct from signed adapter identity'
Assert-Equal $pairingEvidence.'$schema' 'rusty.manifold.local_control.controller_evidence.v1' 'pairing evidence schema must be exact'
Assert-Equal $pairingEvidence.adapter_id $localPolicy.trusted_adapter_id 'pairing evidence must bind the trusted adapter'
Assert-Equal $pairingEvidence.controller_id $localPolicy.controller_id 'pairing evidence must bind the logical controller'
Assert-True ([bool]$pairingEvidence.pairing_code_verified) 'single-use code verification must be explicit'
Assert-Equal $commandRequest.'$schema' 'rusty.manifold.local_control.command_request.v1' 'composite command schema must be exact'
Assert-Equal $safeStatus.'$schema' 'rusty.manifold.local_control.safe_status.v1' 'safe status schema must be exact'
Assert-True (-not $safeStatusRaw.Contains('token.session')) 'safe status must not expose the session token'
Assert-True (-not $safeStatusRaw.Contains('signing_fingerprint')) 'safe status must not expose signing evidence'
Assert-True (-not $safeStatusRaw.Contains('pairing_code')) 'safe status must not expose pairing material'

$seenConcerns = @{}
foreach ($reference in $contractMap.references) {
    Assert-True (-not $seenConcerns.ContainsKey($reference.concern)) "duplicate contract-map concern: $($reference.concern)"
    $seenConcerns[$reference.concern] = $true

    $referencePath = Join-Path $repoRoot $reference.path
    Assert-True (Test-Path -LiteralPath $referencePath -PathType Leaf) "missing referenced fixture: $($reference.path)"
    $referenced = Read-Json $referencePath
    Assert-Equal $referenced.'$schema' $reference.expected_schema "schema mismatch for $($reference.path)"
}

$requiredConcerns = @(
    'local_control_policy',
    'pairing_evidence',
    'composite_command_request',
    'display_safe_status',
    'authority_owned_session_revocation',
    'session_token_issue',
    'one_use_capability_request',
    'one_use_replay_rejection',
    'session_revocation',
    'post_revocation_rejection',
    'single_controller_lease_request',
    'single_controller_lease_application',
    'expected_revision',
    'command_acceptance',
    'explicit_lease_expiry',
    'lease_revocation_adoption',
    'transport_to_effect_evidence',
    'transport_only_damage'
)
foreach ($concern in $requiredConcerns) {
    Assert-True $seenConcerns.ContainsKey($concern) "missing contract-map concern: $concern"
}

Assert-Equal $valid.profile_id 'trusted_local_http_v1' 'valid fixture profile id must be exact'
Assert-True (-not [bool]$valid.policy.default_enabled) 'valid policy must be disabled by default'
Assert-True ([bool]$valid.policy.wearer_enable_required) 'wearer enable must be required'
Assert-True ([bool]$valid.policy.manual_address_required) 'manual address must be required'
Assert-True ([bool]$valid.policy.single_use_pairing_code_required) 'single-use pairing code must be required'
Assert-True (-not [bool]$valid.policy.pairing_code_material_present) 'pairing code material must not be committed'
Assert-Equal $valid.policy.max_controllers 1 'exactly one controller is permitted'
Assert-True ($valid.policy.foreground_listener_window_ms -gt 0 -and $valid.policy.foreground_listener_window_ms -le 300000) 'foreground listener window must be positive and bounded to five minutes'
Assert-True ($valid.policy.idle_timeout_ms -gt 0 -and $valid.policy.idle_timeout_ms -le $valid.policy.session_ttl_ms) 'idle timeout must be positive and no longer than session TTL'
Assert-True ($valid.policy.command_rate_limit_per_second -gt 0 -and $valid.policy.command_rate_limit_per_second -le 10) 'command rate limit must be positive and bounded'
Assert-Equal $valid.policy.confidentiality 'none' 'valid policy must not claim confidentiality'

$expectedCommands = @('describe', 'get_state', 'list_videos', 'pause', 'play', 'select_video')
$actualCommands = @($valid.registry.commands)
Assert-Equal $actualCommands.Count $expectedCommands.Count 'closed registry command count mismatch'
for ($index = 0; $index -lt $expectedCommands.Count; $index++) {
    Assert-Equal $actualCommands[$index] $expectedCommands[$index] "closed registry command mismatch at index $index"
}
Assert-True ([bool]$valid.registry.closed_build_time_registry) 'command registry must be closed at build time'
Assert-Equal $valid.controller.active_controller_count 1 'valid fixture must have one active controller'
Assert-True ([bool]$valid.controller.visible_to_wearer) 'controller state must be visible to the wearer'
Assert-True ([bool]$valid.controller.on_headset_revoke_available) 'on-headset revoke must be available'

Assert-True ([bool]$valid.pairing.pair_request_id_consumed_once) 'pair request id must be consumed once'
Assert-True ([bool]$valid.pairing.manual_address_confirmed) 'manual address must be confirmed'
Assert-True ([bool]$valid.pairing.single_use_code_confirmed) 'single-use code must be confirmed'
Assert-True ($null -eq $valid.pairing.code_material) 'public fixture must contain no pairing-code material'
Assert-True (-not [bool]$valid.pairing.adapter_evidence_is_authority) 'adapter pairing evidence must not become authority'
Assert-Equal $valid.pairing.manifold_admission.receipt_contract 'rusty.manifold.admission.receipt.v2' 'pairing must end in a Manifold admission receipt'
Assert-True ([bool]$valid.pairing.manifold_admission.applied) 'Manifold admission receipt must be applied'
Assert-True (-not [bool]$valid.pairing.manifold_admission.token_material_in_fixture) 'public mapping must not contain session token material'
Assert-Equal $valid.pairing.pair_request_id $valid.pairing.manifold_admission.request_id 'pair request causality must be preserved'

Assert-Equal $valid.lease.'$schema' 'rusty.manifold.command.control_lease.v1' 'controller lease must reuse Manifold control lease'
Assert-Equal $valid.lease.holder_id $valid.controller.controller_id 'controller must hold its exact lease'
Assert-Equal $valid.lease.scope $valid.registry.lease_scope 'controller lease scope must match registry scope'
Assert-Equal $valid.lease.state 'active' 'valid controller lease must be active'

$use = $valid.command.admission_use
$request = $valid.command.runtime_request
$accepted = $valid.command.command_accepted
$acceptedReceipt = $accepted.receipt
$applied = $valid.command.command_applied

Assert-Equal $use.'$schema' 'rusty.manifold.admission.use_request.v1' 'each command must use a Manifold one-use admission request'
Assert-Equal $request.'$schema' 'rusty.manifold.runtime_host.command_request.v1' 'command must use a Runtime Host request'
Assert-Equal $acceptedReceipt.'$schema' 'rusty.manifold.runtime_host.application_receipt.v2' 'command acceptance must wrap the exact Manifold application contract'
Assert-Equal $request.expected_authority_revision $acceptedReceipt.prior_authority_revision 'expected revision must match accepted prior revision'
Assert-Equal $acceptedReceipt.resulting_authority_revision ($acceptedReceipt.prior_authority_revision + 1) 'command acceptance must advance Manifold revision once'
Assert-Equal $accepted.event_kind 'command_accepted' 'Manifold application receipt must be projected as command_accepted'
Assert-Equal $accepted.authority_owner 'rusty.manifold' 'command_accepted must remain Manifold-owned'
Assert-True (-not [bool]$valid.command.transport_ack.proves_application_effect) 'transport acknowledgement must not prove player effect'
Assert-True (-not [bool]$accepted.proves_application_effect) 'command acceptance must not prove player effect'
Assert-Equal $applied.event_kind 'command_applied' 'downstream player event must be command_applied'
Assert-Equal $applied.effect_owner 'rusty.quest.player' 'command_applied must remain Quest-player-owned'
Assert-Equal $applied.source 'androidx.media3.player.events' 'application effect must be callback-derived'
Assert-Equal $request.request_id $acceptedReceipt.request_id 'accepted request causality must match'
Assert-Equal $acceptedReceipt.request_id $applied.request_id 'applied request causality must match'
Assert-Equal $acceptedReceipt.receipt_id $applied.accepted_receipt_id 'applied event must bind the accepted receipt'
Assert-Equal $applied.resulting_player_state_revision ($applied.expected_player_state_revision + 1) 'player state revision must advance once'
Assert-True (-not [bool]$applied.effective_state.play_when_ready) 'select_video must remain separate from play'

$cases = @{}
foreach ($case in $damaged.cases) {
    Assert-True (-not $cases.ContainsKey($case.case_id)) "duplicate damaged case: $($case.case_id)"
    $cases[$case.case_id] = $case
}

$expectedDamaged = @{
    second_controller = 'busy_scope'
    pair_request_replay = 'replayed_request'
    command_use_request_replay = 'replayed_request'
    stale_expected_revision = 'stale_authority_revision'
    expired_session = 'token_expired'
    expired_controller_lease = 'expired_lease'
    revoked_session = 'token_revoked'
    transport_ack_as_authority = 'missing_authority_acceptance'
    acceptance_as_player_effect = 'missing_downstream_application_effect'
    broken_causality = 'request_causality_mismatch'
}
foreach ($entry in $expectedDamaged.GetEnumerator()) {
    Assert-True $cases.ContainsKey($entry.Key) "missing damaged case: $($entry.Key)"
    Assert-Equal $cases[$entry.Key].expected_rejection $entry.Value "damaged case rejection mismatch: $($entry.Key)"
}

Assert-True (@($cases.second_controller.active_controller_ids).Count -gt $valid.policy.max_controllers) 'second-controller case must exceed controller limit'
Assert-True (@($cases.pair_request_replay.consumed_pair_request_ids) -contains $cases.pair_request_replay.pair_request_id) 'pair replay id must already be consumed'
Assert-True (@($cases.command_use_request_replay.consumed_use_request_ids) -contains $cases.command_use_request_replay.use_request_id) 'command-use replay id must already be consumed'
Assert-True ($cases.stale_expected_revision.expected_authority_revision -ne $cases.stale_expected_revision.current_authority_revision) 'stale revision case must mismatch'
Assert-True ($cases.expired_session.reviewed_at_ms -gt $cases.expired_session.token_expires_at_ms) 'session expiry case must review after expiry'
Assert-True ($cases.expired_controller_lease.reviewed_at_ms -gt $cases.expired_controller_lease.lease_expires_at_ms) 'lease expiry case must review after expiry'
Assert-True (@($cases.revoked_session.revoked_token_refs) -contains $cases.revoked_session.token_ref) 'revoked token must be retained in revocation set'
Assert-True (-not (@($cases.transport_ack_as_authority.observed_stages) -contains 'authority_accepted')) 'transport-only case must lack authority acceptance'
Assert-True (-not [bool]$cases.acceptance_as_player_effect.media3_callback_present) 'collapsed acceptance/effect case must lack callback evidence'
Assert-True ($cases.broken_causality.command_request_id -ne $cases.broken_causality.accepted_request_id) 'broken causality case must mismatch request ids'

$forbiddenNames = @(
    'password',
    'pairing_code',
    'pairing_secret',
    'fleet_credential',
    'device_management_credential',
    'private_evidence',
    'raw_shell',
    'adb_command',
    'intent',
    'component',
    'arbitrary_url',
    'arbitrary_path',
    'mcp_command'
)
foreach ($jsonPath in @(
    (Join-Path $fixtureRoot 'contract-map.json'),
    (Join-Path $fixtureRoot 'valid-flow.json'),
    (Join-Path $fixtureRoot 'damaged-mappings.json')
)) {
    $raw = Get-Content -LiteralPath $jsonPath -Raw
    foreach ($forbidden in $forbiddenNames) {
        Assert-True ($raw -notmatch ('"' + [regex]::Escape($forbidden) + '"\s*:')) "forbidden field '$forbidden' in $(Split-Path -Leaf $jsonPath)"
    }
}

Write-Output 'trusted_local_http_v1 Manifold fixture validation: PASS'
Write-Output "references_checked=$($contractMap.references.Count)"
Write-Output "damaged_cases_checked=$($damaged.cases.Count)"
