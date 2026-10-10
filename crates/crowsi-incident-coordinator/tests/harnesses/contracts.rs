//! Event, receipt, and schema contracts share one test executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../anchor_security.rs"]
mod anchor_security;
#[path = "../checkpoint_invariants.rs"]
mod checkpoint_invariants;
#[path = "../checkpoint_security.rs"]
mod checkpoint_security;
#[path = "../command_release_security.rs"]
mod command_release_security;
#[path = "../containment_aggregation.rs"]
mod containment_aggregation;
#[path = "../containment_unknown.rs"]
mod containment_unknown;
#[path = "../event_schema_variants.rs"]
mod event_schema_variants;
#[path = "../production_event_boundary.rs"]
mod production_event_boundary;
#[path = "../receipt_immutability.rs"]
mod receipt_immutability;
#[path = "../schema_documents.rs"]
mod schema_documents;
#[path = "../schema_instance_shapes.rs"]
mod schema_instance_shapes;
#[path = "../security_event_boundaries.rs"]
mod security_event_boundaries;
