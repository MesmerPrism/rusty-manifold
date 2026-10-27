//! Explicit source-owned development policy for delegated new-effect authority.
//!
//! This selection is not a caller permit, a wait deadline or cleanup authority.
//! Owners must retain their accepted identity, revision, revocation and once
//! checks. Omission preserves finite policy; owned cleanup never consults this
//! lifetime policy.

use rusty_manifold_model::{DottedId, SchemaId};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Versioned semantic lifetime selection installed by an authority constructor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldDevelopmentLifetimePolicy {
    /// Public semantic contract version.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit source-owned policy identity.
    pub policy_id: DottedId,
    /// Very-long renewable delegated-authority horizon; never a task deadline.
    pub delegated_authority_horizon_ms: u64,
}

impl ManifoldDevelopmentLifetimePolicy {
    /// Returns the one public policy bundled with this source version.
    #[must_use]
    pub fn source_owned_v1() -> &'static Self {
        static POLICY: OnceLock<ManifoldDevelopmentLifetimePolicy> = OnceLock::new();
        POLICY.get_or_init(|| {
            serde_json::from_str(include_str!(
                "../contracts/development-lifetime-policy.v1.json"
            ))
            .expect("bundled public development lifetime contract")
        })
    }

    /// Checks a constructor-selected semantic policy; no caller can alter it.
    #[must_use]
    pub fn is_source_owned_v1(&self) -> bool {
        self == Self::source_owned_v1()
    }

    /// Resolves a finite default only after an accepted owner selected this policy.
    #[must_use]
    pub fn selected_horizon(policy: Option<&Self>, finite_ms: u64) -> u64 {
        policy
            .filter(|value| value.is_source_owned_v1())
            .map_or(finite_ms, |value| value.delegated_authority_horizon_ms)
    }
}
