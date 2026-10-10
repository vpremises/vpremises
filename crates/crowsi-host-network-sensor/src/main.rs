use std::env;
use std::io::{self, Write};

use crowsi_host_network_sensor::{
    SensorError, evaluate_drift, now_rfc3339, observe_host, read_baseline, sample_baseline,
    sample_snapshot,
};
use serde::Serialize;

fn main() {
    if let Err(error) = run() {
        eprintln!("host network sensor failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), SensorError> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["sample"] | ["sample", "snapshot"] => write_json(&sample_snapshot()?),
        ["sample", "baseline"] => write_json(&sample_baseline()?),
        ["observe"] => {
            let timestamp = now_rfc3339();
            write_json(&observe_host(&timestamp)?)
        }
        ["evaluate"] => {
            let baseline = read_baseline(io::stdin().lock())?;
            let timestamp = now_rfc3339();
            let snapshot = observe_host(&timestamp)?;
            write_json(&evaluate_drift(&baseline, &snapshot)?)
        }
        ["--help" | "-h" | "help"] => {
            println!(
                "usage: crowsi-host-network-sensor \
                 [sample [snapshot|baseline]|observe|evaluate]"
            );
            Ok(())
        }
        _ => Err(SensorError::InvalidArguments),
    }
}

fn write_json(value: &impl Serialize) -> Result<(), SensorError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value).map_err(|_| SensorError::InputReadFailed)?;
    writeln!(output).map_err(|_| SensorError::InputReadFailed)
}
