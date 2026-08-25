//! Placement-neutral V2 product locks and the exact PMB instance.
#![allow(missing_docs)]

use crate::{
    validate_broker_product_lock, ManifoldBrokerPermission, ManifoldBrokerProductLock,
    ManifoldBrokerProductSpec,
};
use rusty_manifold_model::{DottedId, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const BROKER_PRODUCT_SPEC_V2_SCHEMA: &str = "rusty.manifold.broker.product_spec.v2";
pub const BROKER_FEATURE_DESCRIPTOR_V2_SCHEMA: &str = "rusty.manifold.broker.feature_descriptor.v2";
pub const BROKER_PRODUCT_LOCK_V2_SCHEMA: &str = "rusty.manifold.broker.product_lock.v2";
pub const BROKER_PRODUCT_LOCK_MIGRATION_RECEIPT_V1_SCHEMA: &str =
    "rusty.manifold.broker.product_lock_migration_receipt.v1";
pub const BROKER_PRODUCT_LOCK_MIGRATION_POLICY_V1_SCHEMA: &str =
    "rusty.manifold.broker.product_lock_migration_policy.v1";
pub const PMB_PACKAGE_REPOSITORY: &str = "MesmerPrism/rusty-manifold-packages";
pub const PMB_SOURCE_COMMIT: &str = "99024f7d1d50aeb628255c1efd357c0f57965feb";
pub const PMB_SOURCE_TREE: &str = "e7ac519547ae34ad4ec7df944dc1da02157de76b";
pub const PMB_MANIFEST_PATH: &str =
    "packages/projected-motion-breath/manifests/package.manifold.json";
pub const PMB_MANIFEST_GIT_BLOB: &str = "0be9890395ca06743cfa8c449d491d6177280c4f";
pub const PMB_MANIFEST_SHA256: &str =
    "sha256:ca426641f9ae0e0f118e7d273809eb72cf1c3f2e227f55dcdd9099aed0ad9987";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerPlacement {
    Embedded,
    Standalone,
}
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldBrokerCommandSafetyV2 {
    ReadOnly,
    BoundedMutation,
}
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerCommandBindingV2 {
    pub command_id: DottedId,
    pub target_id: DottedId,
    pub required_capability_id: Option<DottedId>,
    pub safety: ManifoldBrokerCommandSafetyV2,
    pub required_lease_scope: Option<DottedId>,
}
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerStreamBindingV2 {
    pub stream_id: DottedId,
    pub source_module_id: DottedId,
}

/// Generic public source-pinned feature descriptor. PMB is an exact factory
/// instance and does not define the V2 wire authority shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerFeatureDescriptorV2 {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub descriptor_id: DottedId,
    pub package_repository: String,
    pub source_commit: String,
    pub source_tree: String,
    pub package_manifest_path: String,
    pub package_manifest_git_blob: String,
    pub package_manifest_sha256: String,
    pub package_id: DottedId,
    pub package_version: String,
    pub module_ids: Vec<DottedId>,
    pub command_ids: Vec<DottedId>,
    pub command_bindings: Vec<ManifoldBrokerCommandBindingV2>,
    pub stream_ids: Vec<DottedId>,
    pub stream_bindings: Vec<ManifoldBrokerStreamBindingV2>,
    pub permission_ids: Vec<ManifoldBrokerPermission>,
    pub effect_ids: Vec<DottedId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerProductSpecV2 {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub product_id: DottedId,
    pub descriptors: Vec<ManifoldBrokerFeatureDescriptorV2>,
    pub permitted_placements: Vec<ManifoldBrokerPlacement>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerProductLockV2 {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub lock_id: DottedId,
    pub product_id: DottedId,
    pub permitted_placements: Vec<ManifoldBrokerPlacement>,
    pub descriptors: Vec<ManifoldBrokerFeatureDescriptorV2>,
    pub resolved_descriptor_fingerprint: String,
    pub command_ids: Vec<DottedId>,
    pub command_bindings: Vec<ManifoldBrokerCommandBindingV2>,
    pub stream_ids: Vec<DottedId>,
    pub stream_bindings: Vec<ManifoldBrokerStreamBindingV2>,
    pub module_ids: Vec<DottedId>,
    pub permission_ids: Vec<ManifoldBrokerPermission>,
    pub effect_ids: Vec<DottedId>,
    /// Domain-separated semantic lock fingerprint, distinct from packaged bytes SHA.
    pub spec_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerProductLockV1MigrationPolicy {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub policy_id: DottedId,
    pub source_schema_id: SchemaId,
    pub target_schema_id: SchemaId,
    pub forbid_pmb_target: bool,
    pub policy_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldBrokerProductLockV1MigrationReceipt {
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    pub source_schema_id: SchemaId,
    pub source_lock_sha256: String,
    pub source_lock_fingerprint: String,
    pub policy_id: DottedId,
    pub policy_fingerprint: String,
    pub target_schema_id: SchemaId,
    pub target_lock_sha256: String,
    pub target_lock_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifoldBrokerProductV2Error {
    SchemaMismatch,
    NonCanonicalClosure,
    SourceMismatch,
    StaleOrExpandedLock,
    MigrationPolicyMismatch,
    MigrationSourceBytesMismatch,
    MigrationPmbRelabelForbidden,
}

pub fn pmb_product_spec() -> ManifoldBrokerProductSpecV2 {
    ManifoldBrokerProductSpecV2 {
        schema_id: schema(BROKER_PRODUCT_SPEC_V2_SCHEMA),
        product_id: id("product.projected_motion_breath"),
        descriptors: vec![pmb_descriptor()],
        permitted_placements: vec![
            ManifoldBrokerPlacement::Embedded,
            ManifoldBrokerPlacement::Standalone,
        ],
    }
}
pub fn pmb_descriptor() -> ManifoldBrokerFeatureDescriptorV2 {
    ManifoldBrokerFeatureDescriptorV2 {
        schema_id: schema(BROKER_FEATURE_DESCRIPTOR_V2_SCHEMA),
        descriptor_id: id("feature.projected_motion_breath"),
        package_repository: PMB_PACKAGE_REPOSITORY.to_owned(),
        source_commit: PMB_SOURCE_COMMIT.to_owned(),
        source_tree: PMB_SOURCE_TREE.to_owned(),
        package_manifest_path: PMB_MANIFEST_PATH.to_owned(),
        package_manifest_git_blob: PMB_MANIFEST_GIT_BLOB.to_owned(),
        package_manifest_sha256: PMB_MANIFEST_SHA256.to_owned(),
        package_id: id("package.projected_motion_breath"),
        package_version: "0.1.0".to_owned(),
        module_ids: ids([
            "module.breath.dynamics",
            "module.breath.feedback_sink",
            "module.breath.projected_motion",
            "module.breath.state_value",
            "module.motion.object_pose_provider",
            "module.motion.vector_provider",
        ]),
        command_ids: ids([
            "command.breath.begin_calibration",
            "command.breath.configure",
            "command.breath.reset_calibration",
            "command.breath.set_profile",
            "command.breath.status",
        ]),
        command_bindings: vec![
            binding(
                "command.breath.begin_calibration",
                "module.breath.projected_motion",
                Some("capability.pmb.control"),
                ManifoldBrokerCommandSafetyV2::BoundedMutation,
                Some("module.breath.projected_motion"),
            ),
            binding(
                "command.breath.configure",
                "module.breath.projected_motion",
                Some("capability.pmb.control"),
                ManifoldBrokerCommandSafetyV2::BoundedMutation,
                Some("module.breath.projected_motion"),
            ),
            binding(
                "command.breath.reset_calibration",
                "module.breath.projected_motion",
                Some("capability.pmb.control"),
                ManifoldBrokerCommandSafetyV2::BoundedMutation,
                Some("module.breath.projected_motion"),
            ),
            binding(
                "command.breath.set_profile",
                "module.breath.projected_motion",
                Some("capability.pmb.control"),
                ManifoldBrokerCommandSafetyV2::BoundedMutation,
                Some("module.breath.projected_motion"),
            ),
            binding(
                "command.breath.status",
                "module.breath.projected_motion",
                None,
                ManifoldBrokerCommandSafetyV2::ReadOnly,
                None,
            ),
        ],
        stream_ids: ids(["stream.motion.object_pose", "stream.motion.vector3"]),
        stream_bindings: vec![
            stream_binding(
                "stream.motion.object_pose",
                "module.motion.object_pose_provider",
            ),
            stream_binding("stream.motion.vector3", "module.motion.vector_provider"),
        ],
        permission_ids: Vec::new(),
        effect_ids: Vec::new(),
    }
}

pub fn resolve_broker_product_v2(
    spec: &ManifoldBrokerProductSpecV2,
) -> Result<ManifoldBrokerProductLockV2, ManifoldBrokerProductV2Error> {
    validate_spec_shape(spec)?;
    let descriptors = spec.descriptors.clone();
    let mut lock = ManifoldBrokerProductLockV2 {
        schema_id: schema(BROKER_PRODUCT_LOCK_V2_SCHEMA),
        lock_id: id(&format!("lock.{}", spec.product_id.as_str())),
        product_id: spec.product_id.clone(),
        permitted_placements: spec.permitted_placements.clone(),
        resolved_descriptor_fingerprint: descriptor_fingerprint(&descriptors),
        command_ids: union_ids(descriptors.iter().map(|d| &d.command_ids)),
        command_bindings: union_values(descriptors.iter().map(|d| &d.command_bindings)),
        stream_ids: union_ids(descriptors.iter().map(|d| &d.stream_ids)),
        stream_bindings: union_values(descriptors.iter().map(|d| &d.stream_bindings)),
        module_ids: union_ids(descriptors.iter().map(|d| &d.module_ids)),
        permission_ids: union_values(descriptors.iter().map(|d| &d.permission_ids)),
        effect_ids: union_ids(descriptors.iter().map(|d| &d.effect_ids)),
        descriptors,
        spec_fingerprint: String::new(),
    };
    lock.spec_fingerprint = lock_fingerprint(&lock);
    Ok(lock)
}
pub fn resolve_pmb_product_v2(
    spec: &ManifoldBrokerProductSpecV2,
) -> Result<ManifoldBrokerProductLockV2, ManifoldBrokerProductV2Error> {
    if spec != &pmb_product_spec() {
        return Err(ManifoldBrokerProductV2Error::SourceMismatch);
    }
    resolve_broker_product_v2(spec)
}
pub fn validate_broker_product_lock_v2(
    spec: &ManifoldBrokerProductSpecV2,
    lock: &ManifoldBrokerProductLockV2,
) -> Result<(), ManifoldBrokerProductV2Error> {
    if lock == &resolve_broker_product_v2(spec)? {
        Ok(())
    } else {
        Err(ManifoldBrokerProductV2Error::StaleOrExpandedLock)
    }
}
pub fn validate_pmb_product_lock_v2(
    spec: &ManifoldBrokerProductSpecV2,
    lock: &ManifoldBrokerProductLockV2,
) -> Result<(), ManifoldBrokerProductV2Error> {
    if lock == &resolve_pmb_product_v2(spec)? {
        Ok(())
    } else {
        Err(ManifoldBrokerProductV2Error::StaleOrExpandedLock)
    }
}

/// Bounded V1 compatibility: decode exact source bytes, validate that decoded
/// V1 lock under its caller-bound V1 spec, resolve target V2 independently,
/// then bind every schema, SHA, semantic fingerprint and policy identity.
pub fn migrate_v1_product_lock_to_v2(
    source_v1_spec: &ManifoldBrokerProductSpec,
    source_lock_bytes: &[u8],
    target_v2_spec: &ManifoldBrokerProductSpecV2,
    policy: &ManifoldBrokerProductLockV1MigrationPolicy,
) -> Result<
    (
        ManifoldBrokerProductLockV2,
        ManifoldBrokerProductLockV1MigrationReceipt,
    ),
    ManifoldBrokerProductV2Error,
> {
    let source: ManifoldBrokerProductLock = serde_json::from_slice(source_lock_bytes)
        .map_err(|_| ManifoldBrokerProductV2Error::MigrationSourceBytesMismatch)?;
    validate_broker_product_lock(source_v1_spec, &source)
        .map_err(|_| ManifoldBrokerProductV2Error::MigrationSourceBytesMismatch)?;
    if policy.schema_id.as_str() != BROKER_PRODUCT_LOCK_MIGRATION_POLICY_V1_SCHEMA
        || policy.source_schema_id.as_str() != crate::BROKER_PRODUCT_LOCK_SCHEMA
        || policy.target_schema_id.as_str() != BROKER_PRODUCT_LOCK_V2_SCHEMA
        || !policy.forbid_pmb_target
        || policy.policy_fingerprint != migration_policy_fingerprint(policy)
    {
        return Err(ManifoldBrokerProductV2Error::MigrationPolicyMismatch);
    }
    if target_v2_spec.descriptors.iter().any(is_pmb_source) {
        return Err(ManifoldBrokerProductV2Error::MigrationPmbRelabelForbidden);
    }
    let target = resolve_broker_product_v2(target_v2_spec)?;
    let target_bytes = serde_json::to_vec(&target).expect("V2 serializes");
    Ok((
        target.clone(),
        ManifoldBrokerProductLockV1MigrationReceipt {
            schema_id: schema(BROKER_PRODUCT_LOCK_MIGRATION_RECEIPT_V1_SCHEMA),
            source_schema_id: source.schema_id,
            source_lock_sha256: sha256(source_lock_bytes),
            source_lock_fingerprint: source.spec_fingerprint,
            policy_id: policy.policy_id.clone(),
            policy_fingerprint: migration_policy_fingerprint(policy),
            target_schema_id: target.schema_id.clone(),
            target_lock_sha256: sha256(&target_bytes),
            target_lock_fingerprint: target.spec_fingerprint,
        },
    ))
}

fn validate_spec_shape(
    spec: &ManifoldBrokerProductSpecV2,
) -> Result<(), ManifoldBrokerProductV2Error> {
    if spec.schema_id.as_str() != BROKER_PRODUCT_SPEC_V2_SCHEMA {
        return Err(ManifoldBrokerProductV2Error::SchemaMismatch);
    }
    if !canonical(&spec.permitted_placements)
        || spec.permitted_placements.is_empty()
        || spec.descriptors.is_empty()
        || !canonical_by(&spec.descriptors, |d| &d.descriptor_id)
    {
        return Err(ManifoldBrokerProductV2Error::NonCanonicalClosure);
    }
    for d in &spec.descriptors {
        if d.schema_id.as_str() != BROKER_FEATURE_DESCRIPTOR_V2_SCHEMA
            || !valid_repository(&d.package_repository)
            || !hex40(&d.source_commit)
            || !hex40(&d.source_tree)
            || !hex40(&d.package_manifest_git_blob)
            || !valid_manifest_path(&d.package_manifest_path)
            || !valid_sha256(&d.package_manifest_sha256)
            || d.package_version.is_empty()
            || !canonical(&d.module_ids)
            || !canonical(&d.command_ids)
            || !canonical(&d.command_bindings)
            || !canonical(&d.stream_ids)
            || !canonical(&d.stream_bindings)
            || !canonical(&d.permission_ids)
            || !canonical(&d.effect_ids)
        {
            return Err(ManifoldBrokerProductV2Error::NonCanonicalClosure);
        }
        if d.command_ids
            != d.command_bindings
                .iter()
                .map(|b| b.command_id.clone())
                .collect::<Vec<_>>()
            || d.stream_ids
                != d.stream_bindings
                    .iter()
                    .map(|b| b.stream_id.clone())
                    .collect::<Vec<_>>()
        {
            return Err(ManifoldBrokerProductV2Error::NonCanonicalClosure);
        }
    }
    Ok(())
}
fn descriptor_fingerprint(descriptors: &[ManifoldBrokerFeatureDescriptorV2]) -> String {
    semantic_fingerprint(
        "resolved-feature-descriptors-v2",
        &[(
            "descriptors",
            &descriptors
                .iter()
                .map(descriptor_text)
                .collect::<Vec<_>>()
                .join("\u{1e}"),
        )],
    )
}
fn descriptor_text(d: &ManifoldBrokerFeatureDescriptorV2) -> String {
    [
        d.schema_id.as_str().to_owned(),
        d.descriptor_id.to_string(),
        d.package_repository.clone(),
        d.source_commit.clone(),
        d.source_tree.clone(),
        d.package_manifest_path.clone(),
        d.package_manifest_git_blob.clone(),
        d.package_manifest_sha256.clone(),
        d.package_id.to_string(),
        d.package_version.clone(),
        ids_text(&d.module_ids),
        ids_text(&d.command_ids),
        bindings_text(&d.command_bindings),
        ids_text(&d.stream_ids),
        stream_bindings_text(&d.stream_bindings),
        permission_tokens(&d.permission_ids),
        ids_text(&d.effect_ids),
    ]
    .join("\u{1f}")
}
fn lock_fingerprint(lock: &ManifoldBrokerProductLockV2) -> String {
    let placements = placement_tokens(&lock.permitted_placements);
    let commands = ids_text(&lock.command_ids);
    let streams = ids_text(&lock.stream_ids);
    let modules = ids_text(&lock.module_ids);
    let permissions = permission_tokens(&lock.permission_ids);
    let effects = ids_text(&lock.effect_ids);
    semantic_fingerprint(
        "product-lock-v2",
        &[
            ("schema", lock.schema_id.as_str()),
            ("lock_id", lock.lock_id.as_str()),
            ("product_id", lock.product_id.as_str()),
            ("placements", &placements),
            (
                "descriptor_fingerprint",
                &lock.resolved_descriptor_fingerprint,
            ),
            ("commands", &commands),
            ("command_bindings", &bindings_text(&lock.command_bindings)),
            ("streams", &streams),
            (
                "stream_bindings",
                &stream_bindings_text(&lock.stream_bindings),
            ),
            ("modules", &modules),
            ("permissions", &permissions),
            ("effects", &effects),
        ],
    )
}
fn semantic_fingerprint(domain: &str, fields: &[(&str, &str)]) -> String {
    let mut bytes = b"rusty.manifold.semantic-fingerprint.v1\0".to_vec();
    append_framed(&mut bytes, domain);
    for (label, value) in fields {
        append_framed(&mut bytes, label);
        append_framed(&mut bytes, value);
    }
    sha256(&bytes)
}
fn append_framed(target: &mut Vec<u8>, value: &str) {
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value.as_bytes());
}
fn union_ids<'a>(sets: impl Iterator<Item = &'a Vec<DottedId>>) -> Vec<DottedId> {
    sets.flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
fn union_values<'a, T: Ord + Clone + 'a>(sets: impl Iterator<Item = &'a Vec<T>>) -> Vec<T> {
    sets.flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
fn ids_text<T: std::fmt::Display>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\u{1f}")
}
fn canonical<T: Ord + Clone>(values: &[T]) -> bool {
    values.iter().cloned().collect::<BTreeSet<_>>().len() == values.len()
        && values.windows(2).all(|pair| pair[0] < pair[1])
}
fn canonical_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> &K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}
fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("static ID")
}
fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema")
}
fn ids<const N: usize>(values: [&str; N]) -> Vec<DottedId> {
    values.into_iter().map(id).collect()
}
fn binding(
    command: &str,
    target: &str,
    capability: Option<&str>,
    safety: ManifoldBrokerCommandSafetyV2,
    lease: Option<&str>,
) -> ManifoldBrokerCommandBindingV2 {
    ManifoldBrokerCommandBindingV2 {
        command_id: id(command),
        target_id: id(target),
        required_capability_id: capability.map(id),
        safety,
        required_lease_scope: lease.map(id),
    }
}
fn stream_binding(stream: &str, source: &str) -> ManifoldBrokerStreamBindingV2 {
    ManifoldBrokerStreamBindingV2 {
        stream_id: id(stream),
        source_module_id: id(source),
    }
}
fn placement_tokens(values: &[ManifoldBrokerPlacement]) -> String {
    values
        .iter()
        .map(|v| match v {
            ManifoldBrokerPlacement::Embedded => "embedded",
            ManifoldBrokerPlacement::Standalone => "standalone",
        })
        .collect::<Vec<_>>()
        .join("\u{1f}")
}
fn permission_tokens(values: &[ManifoldBrokerPermission]) -> String {
    values
        .iter()
        .map(|v| serde_json::to_string(v).expect("token"))
        .collect::<Vec<_>>()
        .join("\u{1f}")
}
fn bindings_text(values: &[ManifoldBrokerCommandBindingV2]) -> String {
    values
        .iter()
        .map(|b| {
            format!(
                "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
                b.command_id,
                b.target_id,
                b.required_capability_id
                    .as_ref()
                    .map_or("", DottedId::as_str),
                match b.safety {
                    ManifoldBrokerCommandSafetyV2::ReadOnly => "read_only",
                    ManifoldBrokerCommandSafetyV2::BoundedMutation => "bounded_mutation",
                },
                b.required_lease_scope.as_ref().map_or("", DottedId::as_str)
            )
        })
        .collect::<Vec<_>>()
        .join("\u{1e}")
}
fn stream_bindings_text(values: &[ManifoldBrokerStreamBindingV2]) -> String {
    values
        .iter()
        .map(|b| format!("{}\u{1f}{}", b.stream_id, b.source_module_id))
        .collect::<Vec<_>>()
        .join("\u{1e}")
}
fn hex40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_manifest_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
}
fn valid_repository(value: &str) -> bool {
    let mut p = value.split('/');
    matches!((p.next(),p.next(),p.next()),(Some(owner),Some(repo),None) if !owner.is_empty() && !repo.is_empty() && owner.bytes().chain(repo.bytes()).all(|b| b.is_ascii_alphanumeric() || b==b'-' || b==b'_' || b==b'.'))
}
fn is_pmb_source(d: &ManifoldBrokerFeatureDescriptorV2) -> bool {
    d.package_repository == PMB_PACKAGE_REPOSITORY
        && d.source_commit == PMB_SOURCE_COMMIT
        && d.source_tree == PMB_SOURCE_TREE
        && d.package_manifest_path == PMB_MANIFEST_PATH
        && d.package_manifest_git_blob == PMB_MANIFEST_GIT_BLOB
        && d.package_manifest_sha256 == PMB_MANIFEST_SHA256
        && d.package_id.as_str() == "package.projected_motion_breath"
}
fn migration_policy_fingerprint(policy: &ManifoldBrokerProductLockV1MigrationPolicy) -> String {
    semantic_fingerprint(
        "product-lock-v1-migration-policy",
        &[
            ("schema", policy.schema_id.as_str()),
            ("policy_id", policy.policy_id.as_str()),
            ("source_schema", policy.source_schema_id.as_str()),
            ("target_schema", policy.target_schema_id.as_str()),
            (
                "forbid_pmb_target",
                if policy.forbid_pmb_target {
                    "true"
                } else {
                    "false"
                },
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve_broker_product;
    #[test]
    fn pmb_v2_is_generic_source_pinned_and_placement_neutral() {
        let spec = pmb_product_spec();
        let lock = resolve_pmb_product_v2(&spec).unwrap();
        println!("lock={}", lock.spec_fingerprint);
        assert!(lock.permission_ids.is_empty() && lock.effect_ids.is_empty());
        assert!(!lock.resolved_descriptor_fingerprint.is_empty());
        validate_pmb_product_lock_v2(&spec, &lock).unwrap();
    }
    #[test]
    fn descriptor_damage_fails_closed() {
        let mut spec = pmb_product_spec();
        spec.descriptors[0].source_tree = "0".repeat(40);
        assert_eq!(
            resolve_pmb_product_v2(&spec),
            Err(ManifoldBrokerProductV2Error::SourceMismatch)
        );
    }
    #[test]
    fn committed_pmb_v2_fixtures_deserialize_and_match_resolution() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let spec: ManifoldBrokerProductSpecV2 = serde_json::from_str(
            &std::fs::read_to_string(root.join("fixtures/broker-product/pmb-v2-product-spec.json"))
                .unwrap(),
        )
        .unwrap();
        let lock: ManifoldBrokerProductLockV2 = serde_json::from_str(
            &std::fs::read_to_string(root.join("fixtures/broker-product/pmb-v2-product-lock.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(spec, pmb_product_spec());
        validate_pmb_product_lock_v2(&spec, &lock).unwrap();
        let _: ManifoldBrokerProductLockV1MigrationPolicy = serde_json::from_str(
            &std::fs::read_to_string(
                root.join("fixtures/broker-product/v1-to-v2-migration-policy.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let _: ManifoldBrokerProductLockV1MigrationReceipt = serde_json::from_str(
            &std::fs::read_to_string(
                root.join("fixtures/broker-product/v1-to-v2-migration-receipt.json"),
            )
            .unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn v1_migration_proves_binding_and_forbids_pmb_relabel() {
        let v1 = ManifoldBrokerProductSpec {
            schema_id: schema(crate::BROKER_PRODUCT_SPEC_SCHEMA),
            product_id: id("product.legacy"),
            standalone_enabled: true,
            embedded_enabled: false,
            requested_features: vec![],
        };
        let bytes = serde_json::to_vec(&resolve_broker_product(&v1).unwrap()).unwrap();
        let mut policy = ManifoldBrokerProductLockV1MigrationPolicy {
            schema_id: schema(BROKER_PRODUCT_LOCK_MIGRATION_POLICY_V1_SCHEMA),
            policy_id: id("policy.product.v1_to_v2"),
            source_schema_id: schema(crate::BROKER_PRODUCT_LOCK_SCHEMA),
            target_schema_id: schema(BROKER_PRODUCT_LOCK_V2_SCHEMA),
            forbid_pmb_target: true,
            policy_fingerprint: String::new(),
        };
        policy.policy_fingerprint = migration_policy_fingerprint(&policy);
        assert_eq!(
            migrate_v1_product_lock_to_v2(&v1, &bytes, &pmb_product_spec(), &policy),
            Err(ManifoldBrokerProductV2Error::MigrationPmbRelabelForbidden)
        );
        let mut target = pmb_product_spec();
        target.product_id = id("product.legacy.v2");
        target.descriptors[0].descriptor_id = id("feature.legacy");
        target.descriptors[0].source_commit = "0".repeat(40);
        let (_, receipt) = migrate_v1_product_lock_to_v2(&v1, &bytes, &target, &policy).unwrap();
        assert_eq!(receipt.source_lock_sha256, sha256(&bytes));
        assert_eq!(receipt.policy_id, policy.policy_id);
        let mut bad = bytes;
        bad.push(b'x');
        assert_eq!(
            migrate_v1_product_lock_to_v2(&v1, &bad, &target, &policy),
            Err(ManifoldBrokerProductV2Error::MigrationSourceBytesMismatch)
        );
        let changed_source_spec = ManifoldBrokerProductSpec {
            product_id: id("product.changed_source"),
            ..v1.clone()
        };
        assert_eq!(
            migrate_v1_product_lock_to_v2(
                &changed_source_spec,
                &serde_json::to_vec(
                    &resolve_broker_product(&ManifoldBrokerProductSpec {
                        product_id: id("product.legacy"),
                        standalone_enabled: true,
                        embedded_enabled: false,
                        requested_features: vec![],
                        schema_id: schema(crate::BROKER_PRODUCT_SPEC_SCHEMA)
                    })
                    .unwrap()
                )
                .unwrap(),
                &target,
                &policy
            ),
            Err(ManifoldBrokerProductV2Error::MigrationSourceBytesMismatch)
        );
        let mut stale_policy = policy.clone();
        stale_policy.forbid_pmb_target = false;
        assert_eq!(
            migrate_v1_product_lock_to_v2(
                &v1,
                &serde_json::to_vec(&resolve_broker_product(&v1).unwrap()).unwrap(),
                &target,
                &stale_policy
            ),
            Err(ManifoldBrokerProductV2Error::MigrationPolicyMismatch)
        );
        stale_policy.policy_fingerprint = migration_policy_fingerprint(&stale_policy);
        assert_eq!(
            migrate_v1_product_lock_to_v2(
                &v1,
                &serde_json::to_vec(&resolve_broker_product(&v1).unwrap()).unwrap(),
                &target,
                &stale_policy
            ),
            Err(ManifoldBrokerProductV2Error::MigrationPolicyMismatch)
        );
        let mut relabelled_pmb = pmb_product_spec();
        relabelled_pmb.descriptors[0].descriptor_id = id("feature.relabelled_pmb");
        assert_eq!(
            migrate_v1_product_lock_to_v2(
                &v1,
                &serde_json::to_vec(&resolve_broker_product(&v1).unwrap()).unwrap(),
                &relabelled_pmb,
                &policy
            ),
            Err(ManifoldBrokerProductV2Error::MigrationPmbRelabelForbidden)
        );
    }
    #[test]
    fn migration_fixture_is_produced_from_committed_v1_bytes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source_spec: ManifoldBrokerProductSpec = serde_json::from_str(
            &std::fs::read_to_string(root.join("fixtures/broker-product/base-standalone.json"))
                .unwrap(),
        )
        .unwrap();
        let source_bytes =
            std::fs::read(root.join("fixtures/broker-product/base-standalone.lock.json")).unwrap();
        let mut target = pmb_product_spec();
        target.product_id = id("product.legacy.v2");
        target.descriptors[0].descriptor_id = id("feature.legacy");
        target.descriptors[0].source_commit = "0".repeat(40);
        let mut policy = ManifoldBrokerProductLockV1MigrationPolicy {
            schema_id: schema(BROKER_PRODUCT_LOCK_MIGRATION_POLICY_V1_SCHEMA),
            policy_id: id("policy.product.v1_to_v2"),
            source_schema_id: schema(crate::BROKER_PRODUCT_LOCK_SCHEMA),
            target_schema_id: schema(BROKER_PRODUCT_LOCK_V2_SCHEMA),
            forbid_pmb_target: true,
            policy_fingerprint: String::new(),
        };
        policy.policy_fingerprint = migration_policy_fingerprint(&policy);
        let (_, receipt) =
            migrate_v1_product_lock_to_v2(&source_spec, &source_bytes, &target, &policy).unwrap();
        assert_eq!(receipt.source_lock_sha256, sha256(&source_bytes));
        assert_eq!(
            receipt.policy_fingerprint,
            migration_policy_fingerprint(&policy)
        );
        let mut actual = serde_json::to_vec_pretty(&receipt).unwrap();
        actual.push(b'\n');
        let expected =
            std::fs::read(root.join("fixtures/broker-product/v1-to-v2-migration-receipt.json"))
                .unwrap();
        assert_eq!(actual, expected);
    }
}
