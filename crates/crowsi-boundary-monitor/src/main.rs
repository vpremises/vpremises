use crowsi_boundary_monitor::{
    COVERAGE_INPUT_SCHEMA, ControlAuthority, ControlCoverageInputV2, CoverageAssetInputV2,
    EnforcerStatus, LifelineStatus, MAX_DOCUMENT_BYTES, SensorStatus, evaluate, evaluate_coverage,
    parse_coverage_input, parse_input, validate_coverage_input,
};
use std::{
    env,
    error::Error,
    fs::File,
    io::{self, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const SAMPLE: &[u8] = include_bytes!("../examples/boundary-input.sample.json");
const COVERAGE_SAMPLE: &[u8] = include_bytes!("../examples/control-coverage.sample.json");

enum Operation {
    Boundary(Vec<u8>),
    Coverage(Vec<u8>),
    UnconfiguredCoverage,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("boundary evaluation failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let operation = match arguments.as_slice() {
        [] => Operation::Boundary(SAMPLE.to_vec()),
        [command] if command == "sample" => Operation::Boundary(SAMPLE.to_vec()),
        [command, path] if command == "evaluate" => Operation::Boundary(read_bounded(path)?),
        [command] if command == "coverage-sample" => Operation::Coverage(COVERAGE_SAMPLE.to_vec()),
        [command] if command == "coverage-unconfigured" => Operation::UnconfiguredCoverage,
        [command, path] if command == "evaluate-coverage" => {
            Operation::Coverage(read_bounded(path)?)
        }
        [command] if matches!(command.as_str(), "help" | "-h" | "--help") => {
            println!(
                "usage: crowsi-boundary-monitor \
                 [sample|evaluate INPUT|coverage-sample|coverage-unconfigured|\
                 evaluate-coverage INPUT]"
            );
            return Ok(());
        }
        _ => return Err("expected a supported boundary or coverage operation".into()),
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match operation {
        Operation::Boundary(source) => {
            serde_json::to_writer_pretty(&mut output, &evaluate(parse_input(&source)?))?;
        }
        Operation::Coverage(source) => {
            serde_json::to_writer_pretty(
                &mut output,
                &evaluate_coverage(parse_coverage_input(&source)?),
            )?;
        }
        Operation::UnconfiguredCoverage => {
            serde_json::to_writer_pretty(
                &mut output,
                &evaluate_coverage(validate_coverage_input(unconfigured_coverage()?)?),
            )?;
        }
    }
    writeln!(output)?;
    Ok(())
}

fn unconfigured_coverage() -> Result<ControlCoverageInputV2, Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(ControlCoverageInputV2 {
        schema: COVERAGE_INPUT_SCHEMA.to_owned(),
        generated_at_epoch_s: now,
        external_actions: false,
        assets: vec![CoverageAssetInputV2 {
            id: "local-network-estate".to_owned(),
            authority: ControlAuthority::None,
            sensor_status: SensorStatus::Unknown,
            observed_at_epoch_s: now,
            observation_ttl_s: 60,
            enforcer_status: EnforcerStatus::Absent,
            supported_actions: Vec::new(),
            lifeline_status: LifelineStatus::Unknown,
            last_drill_at_epoch_s: None,
            drill_ttl_s: 86_400,
        }],
    })
}

fn read_bounded(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = File::open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err("input must be a regular file".into());
    }
    let mut source = Vec::new();
    file.take(u64::try_from(MAX_DOCUMENT_BYTES + 1)?)
        .read_to_end(&mut source)?;
    if source.len() > MAX_DOCUMENT_BYTES {
        return Err("input exceeds the size limit".into());
    }
    Ok(source)
}
