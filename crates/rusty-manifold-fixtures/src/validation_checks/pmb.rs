use super::{fail, pass, CliError, ValidationCheckReport};
use rusty_manifold_broker_adapter::{
    generate_pmb_v3_fixture_bytes, packaged_product_lock_sha256, ManifoldBrokerAdapterConfigV3,
    ManifoldBrokerAdapterReceiptV3, ManifoldBrokerNeutralIngressV1,
};
use rusty_manifold_broker_product::pmb_v2::{
    pmb_product_spec, resolve_pmb_product_v2, validate_pmb_product_lock_v2,
    ManifoldBrokerPlacement, ManifoldBrokerProductLockV1MigrationPolicy,
    ManifoldBrokerProductLockV1MigrationReceipt, ManifoldBrokerProductLockV2,
    ManifoldBrokerProductSpecV2,
};
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn push_pmb_checks(
    repo_root: &Path,
    checks: &mut Vec<ValidationCheckReport>,
) -> Result<(), CliError> {
    let spec_bytes = std::fs::read(
        repo_root.join("fixtures/broker-product/pmb-v2-product-spec.json"),
    )
    .map_err(|source| CliError::Io {
        path: repo_root.join("fixtures/broker-product/pmb-v2-product-spec.json"),
        source,
    })?;
    let lock_path = repo_root.join("fixtures/broker-product/pmb-v2-product-lock.json");
    let lock_bytes = std::fs::read(&lock_path).map_err(|source| CliError::Io {
        path: lock_path.clone(),
        source,
    })?;
    let spec: ManifoldBrokerProductSpecV2 =
        serde_json::from_slice(&spec_bytes).map_err(|source| CliError::Json {
            path: repo_root.join("fixtures/broker-product/pmb-v2-product-spec.json"),
            source,
        })?;
    let lock: ManifoldBrokerProductLockV2 =
        serde_json::from_slice(&lock_bytes).map_err(|source| CliError::Json {
            path: lock_path.clone(),
            source,
        })?;
    let result = (|| -> Result<(), String> {
        if spec != pmb_product_spec() {
            return Err("PMB V2 product spec differs from production constructor".to_owned());
        }
        validate_pmb_product_lock_v2(&spec, &lock)
            .map_err(|error| format!("PMB lock failed production validation: {error:?}"))?;
        let generated_lock = resolve_pmb_product_v2(&spec)
            .map_err(|error| format!("PMB lock generation failed: {error:?}"))?;
        if generated_lock != lock {
            return Err(
                "committed PMB V2 lock differs from production semantic regeneration".to_owned(),
            );
        }
        let generated = generate_pmb_v3_fixture_bytes(&lock_bytes)
            .map_err(|error| format!("PMB V3 fixture generation failed: {error:?}"))?;
        for (path, actual) in [
            (
                "fixtures/broker-adapter/pmb-v3-standalone-config.json",
                generated.standalone_config,
            ),
            (
                "fixtures/broker-adapter/pmb-v3-standalone-receipt.json",
                generated.standalone_receipt,
            ),
            (
                "fixtures/broker-adapter/pmb-v3-embedded-config.json",
                generated.embedded_config,
            ),
            (
                "fixtures/broker-adapter/pmb-v3-embedded-receipt.json",
                generated.embedded_receipt,
            ),
        ] {
            let expected =
                std::fs::read(repo_root.join(path)).map_err(|error| error.to_string())?;
            if actual != expected {
                return Err(format!(
                    "committed PMB V3 fixture bytes differ from production regeneration: {path}"
                ));
            }
        }
        let expected_sha256 = packaged_product_lock_sha256(&lock_bytes);
        for (placement, config_path, receipt_path) in [
            (
                ManifoldBrokerPlacement::Standalone,
                "fixtures/broker-adapter/pmb-v3-standalone-config.json",
                "fixtures/broker-adapter/pmb-v3-standalone-receipt.json",
            ),
            (
                ManifoldBrokerPlacement::Embedded,
                "fixtures/broker-adapter/pmb-v3-embedded-config.json",
                "fixtures/broker-adapter/pmb-v3-embedded-receipt.json",
            ),
        ] {
            let config: ManifoldBrokerAdapterConfigV3 = serde_json::from_slice(
                &std::fs::read(repo_root.join(config_path)).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let receipt: ManifoldBrokerAdapterReceiptV3 = serde_json::from_slice(
                &std::fs::read(repo_root.join(receipt_path)).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            if config.selected_placement != placement
                || config.product_lock_id != lock.lock_id
                || config.product_lock_fingerprint != lock.spec_fingerprint
                || config.product_lock_sha256 != expected_sha256
                || receipt.selected_placement != placement
                || receipt.product_lock_id != lock.lock_id
                || receipt.product_lock_fingerprint != lock.spec_fingerprint
                || receipt.product_lock_sha256 != expected_sha256
                || receipt.dispatch.command_id.as_str() != "command.breath.status"
                || receipt.dispatch.request_id != receipt.application.request_id
                || receipt.dispatch.dispatch_id != receipt.application.dispatch_id
                || !receipt.application.applied
                || receipt.application.resulting_authority_revision.get()
                    != receipt.application.prior_authority_revision.get() + 1
            {
                return Err(format!(
                    "PMB config/receipt provenance or Runtime Host identity drift: {config_path}"
                ));
            }
        }
        let ingress: ManifoldBrokerNeutralIngressV1 = serde_json::from_slice(
            &std::fs::read(
                repo_root.join("fixtures/broker-adapter/pmb-neutral-vector3-ingress.json"),
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        ingress
            .validate(&lock, &BTreeSet::new())
            .map_err(|error| format!("PMB stream/source binding drift: {error:?}"))?;
        let policy: ManifoldBrokerProductLockV1MigrationPolicy = serde_json::from_slice(
            &std::fs::read(
                repo_root.join("fixtures/broker-product/v1-to-v2-migration-policy.json"),
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let receipt: ManifoldBrokerProductLockV1MigrationReceipt = serde_json::from_slice(
            &std::fs::read(
                repo_root.join("fixtures/broker-product/v1-to-v2-migration-receipt.json"),
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        if !policy.forbid_pmb_target
            || receipt.policy_id != policy.policy_id
            || receipt.policy_fingerprint != policy.policy_fingerprint
        {
            return Err("PMB migration policy/receipt identity drift".to_owned());
        }
        Ok(())
    })();
    match result {
        Ok(()) => checks.push(pass(
            "validation.check.pmb_v3_production_regeneration",
            "exact PMB V2 lock bytes and all V3 standalone/embedded config and Runtime Host receipt bytes match production regeneration",
        )),
        Err(error) => checks.push(fail(
            "validation.check.pmb_v3_production_regeneration",
            error,
            None,
        )),
    }

    for (name, expected_reason, expected_error) in [
        (
            "pmb-v3-placement-missing.json",
            "missing selected placement",
            None,
        ),
        (
            "pmb-v3-placement-duplicate.json",
            "duplicate selected placement",
            None,
        ),
        (
            "pmb-v3-placement-legacy-empty.json",
            "legacy plural selection",
            None,
        ),
        (
            "pmb-v3-placement-legacy-multiple.json",
            "legacy plural selection",
            None,
        ),
        (
            "pmb-v3-placement-singular-plus-plural.json",
            "singular plus legacy plural selection",
            None,
        ),
        (
            "pmb-v3-placement-unknown-authority.json",
            "unknown placement authority",
            Some("unknown field `placement_authority`"),
        ),
        (
            "pmb-v3-placement-unknown.json",
            "non-permitted placement",
            Some("unknown variant `sidecar`"),
        ),
    ] {
        let path = repo_root.join("fixtures/damaged").join(name);
        let raw = std::fs::read(&path).map_err(|source| CliError::Io {
            path: path.clone(),
            source,
        })?;
        let rejected = match serde_json::from_slice::<ManifoldBrokerAdapterConfigV3>(&raw) {
            Err(_) if expected_error.is_none() => true,
            Err(error) => {
                error.is_data()
                    && expected_error.is_some_and(|expected| error.to_string().contains(expected))
            }
            Ok(_) => false,
        };
        if rejected {
            checks.push(pass(
                &format!("validation.check.damaged_{name}"),
                &format!(
                    "raw PMB V3 config rejects {expected_reason} before placement normalization"
                ),
            ));
        } else {
            checks.push(fail(
                &format!("validation.check.damaged_{name}"),
                format!("damaged PMB V3 config accepted: {expected_reason}"),
                None,
            ));
        }
    }
    Ok(())
}
