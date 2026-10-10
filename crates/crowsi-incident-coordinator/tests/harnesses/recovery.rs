//! State transition and recovery scenarios share one test executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../durable_recovery.rs"]
mod durable_recovery;
#[path = "../durable_replay.rs"]
mod durable_replay;
#[path = "../failure_states.rs"]
mod failure_states;
#[path = "../recovery_control.rs"]
mod recovery_control;
#[path = "../recovery_happy_path.rs"]
mod recovery_happy_path;
#[path = "../replay_and_epoch.rs"]
mod replay_and_epoch;
#[path = "../state_machine.rs"]
mod state_machine;
