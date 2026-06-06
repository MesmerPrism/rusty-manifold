use super::*;

/// Rejection for a command dispatch receipt.
///
/// Dispatch rejection is distinct from command authority rejection. It reports
/// why a reviewed command was not handed to downstream transport or execution,
/// without mutating authority state or running the command.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandDispatchRejection {
    /// Schema identifier for this dispatch rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Dispatch receipt id this rejection belongs to.
    pub dispatch_id: DottedId,
    /// Stable rejection code.
    pub rejection_code: DottedId,
    /// Human-readable explanation.
    pub message: String,
    /// Whether retrying after refreshing authority state may help.
    pub retryable: bool,
    /// Current authority revision.
    pub current_authority_revision: Revision,
}

/// Source-only receipt preparing a reviewed command for downstream dispatch.
///
/// This is a handoff contract between Manifold authority and a later transport
/// or executor. It confirms ack/rejection shape and review provenance without
/// opening a transport, contacting a host, executing the command, or mutating
/// accepted authority state.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandDispatchReceipt {
    /// Schema identifier for this dispatch receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable dispatch receipt id.
    pub dispatch_id: DottedId,
    /// Authority that prepared the dispatch receipt.
    pub authority_id: DottedId,
    /// Authority revision used by this receipt.
    pub authority_revision: Revision,
    /// Command id being prepared for dispatch.
    pub command_id: DottedId,
    /// Command request id being prepared for dispatch.
    pub request_id: DottedId,
    /// Dispatch receipt outcome.
    pub outcome: ManifoldCommandDispatchReceiptOutcome,
    /// Accepted command ack. Present only for ready receipts.
    pub ack: Option<ManifoldCommandAck>,
    /// Dispatch rejection. Present only for rejected receipts.
    pub rejection: Option<ManifoldCommandDispatchRejection>,
    /// Command authority review being handed off.
    pub review: ManifoldCommandAuthorityReview,
}

impl ManifoldCommandDispatchReceipt {
    /// Validates that this dispatch receipt matches the supplied snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic command dispatch handoff for the supplied
    /// authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.command_dispatch_receipt.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.dispatch_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.dispatch_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.dispatch_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.command_id != self.review.audit_event.envelope.command_id
            || self.request_id != self.review.audit_event.envelope.request_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.dispatch_id.clone(),
                self.command_id.to_string(),
                ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldCommandDispatchReceiptOutcome::CommandDispatchReady => {
                if self.ack.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        "ack".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome != ManifoldCommandAuthorityReviewOutcome::CommandAccepted {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let ack = self.ack.as_ref().expect("ack presence checked");
                if Some(ack) != self.review.accepted.as_ref() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        self.request_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let expected_accepted_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.dispatch_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;
                if ack.accepted_revision != expected_accepted_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        ack.accepted_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                Ok(())
            }
            ManifoldCommandDispatchReceiptOutcome::CommandDispatchRejected => {
                if self.ack.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome != ManifoldCommandAuthorityReviewOutcome::CommandRejected {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("dispatch rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.command_dispatch_rejection.v1"
                    || rejection.dispatch_id != self.dispatch_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                    || rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.dispatch_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

/// Command dispatch receipt outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldCommandDispatchReceiptOutcome {
    /// Accepted command review is ready for downstream dispatch.
    CommandDispatchReady,
    /// Command review was not accepted for downstream dispatch.
    CommandDispatchRejected,
}
