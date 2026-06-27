use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tabled::{Table, Tabled};
use tracing_subscriber::EnvFilter;

use barzakh_adversary::deploy::esp_image::EspImageBuilder;
use barzakh_adversary::deploy::qemu::{self, QemuConfig};
use barzakh_adversary::validate::runner::validate_all;
use barzakh_adversary::{create_all_payloads, Arch, PayloadConfig};
use barzakh_core::{BarzakhScanner, Baseline, ReportFormat, Severity};

#[derive(Parser)]
#[command(
    name = "barzakh",
    about = "Barzakh — UEFI Firmware Security Analysis Platform",
    long_about = "A comprehensive UEFI bootkit detection engine with 30 security detectors,\n\
                  adversary payload generation, QEMU integration, and firmware analysis tools.",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose/debug output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a firmware image or memory dump for bootkits
    Scan(ScanArgs),

    /// Manage firmware baselines
    Baseline {
        #[command(subcommand)]
        command: BaselineCommands,
    },

    /// Generate scan reports
    Report(ReportArgs),

    /// Validate scanner detection accuracy against corpus
    Validate(ValidateArgs),

    /// Red-team adversary payload generation
    Adversary {
        #[command(subcommand)]
        command: AdversaryCommands,
    },

    /// List and inspect security detectors
    Detectors {
        #[command(subcommand)]
        command: DetectorCommands,
    },

    /// QEMU firmware emulation integration
    Qemu {
        #[command(subcommand)]
        command: QemuCommands,
    },

    /// Build EFI System Partition images
    Esp {
        #[command(subcommand)]
        command: EspCommands,
    },

    /// Display platform information and statistics
    Info,
}

// ─── Scan ────────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct ScanArgs {
    /// Path to firmware image or memory dump
    #[arg(short, long)]
    target: PathBuf,

    /// Path to baseline configuration JSON
    #[arg(short, long)]
    baseline: Option<PathBuf>,

    /// Specific detector types to run (comma-separated)
    #[arg(long, value_delimiter = ',')]
    scan_types: Option<Vec<String>>,

    /// Output findings as JSON to stdout
    #[arg(long)]
    json: bool,

    /// Suppress progress output, only set exit code
    #[arg(short, long)]
    quiet: bool,

    /// Auto-generate report after scan
    #[arg(long)]
    report: Option<PathBuf>,

    /// Report format (json, html, markdown)
    #[arg(long, default_value = "json")]
    format: String,
}

// ─── Baseline ────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum BaselineCommands {
    /// Create a baseline from a known-good firmware image
    Create(BaselineCreateArgs),

    /// Display baseline contents
    Show(BaselineShowArgs),
}

#[derive(Parser)]
struct BaselineCreateArgs {
    /// Path to clean firmware image
    #[arg(short, long)]
    target: PathBuf,

    /// Output path for baseline JSON
    #[arg(short, long, default_value = "baseline.json")]
    output: PathBuf,
}

#[derive(Parser)]
struct BaselineShowArgs {
    /// Path to baseline JSON file
    path: PathBuf,
}

// ─── Report ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct ReportArgs {
    /// Path to firmware image to scan and report on
    #[arg(short, long)]
    target: PathBuf,

    /// Optional baseline
    #[arg(short, long)]
    baseline: Option<PathBuf>,

    /// Output path for report
    #[arg(short, long, default_value = "report.json")]
    output: PathBuf,

    /// Report format (json, html, markdown)
    #[arg(short, long, default_value = "json")]
    format: String,
}

// ─── Validate ────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct ValidateArgs {
    /// Path to corpus directory
    #[arg(short, long)]
    corpus: PathBuf,

    /// Optional baseline JSON
    #[arg(short, long)]
    baseline: Option<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

// ─── Adversary ───────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum AdversaryCommands {
    /// Generate a specific adversary payload
    Generate(AdversaryGenerateArgs),

    /// List all available adversary payloads
    List,

    /// Generate a full test corpus (malicious + clean pairs)
    Corpus(AdversaryCorpusArgs),

    /// Validate payloads against the scanner
    Validate(AdversaryValidateArgs),
}

#[derive(Parser)]
struct AdversaryGenerateArgs {
    /// Payload name (use 'adversary list' to see available)
    #[arg(short, long)]
    payload: String,

    /// Output path for generated binary
    #[arg(short, long)]
    output: PathBuf,

    /// Target architecture
    #[arg(short, long, value_enum, default_value = "x86-64")]
    arch: ArchArg,

    /// Image size in bytes
    #[arg(short, long, default_value = "65536")]
    size: usize,
}

#[derive(Parser)]
struct AdversaryCorpusArgs {
    /// Output directory for corpus files
    #[arg(short, long, default_value = "corpus")]
    output: PathBuf,
}

#[derive(Parser)]
struct AdversaryValidateArgs {
    /// Directory containing generated corpus dumps
    #[arg(short, long)]
    corpus: PathBuf,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Clone, ValueEnum)]
enum ArchArg {
    #[value(name = "x86-64")]
    X86_64,
    #[value(name = "aarch64")]
    Aarch64,
    #[value(name = "riscv64")]
    RiscV64,
}

impl From<ArchArg> for Arch {
    fn from(a: ArchArg) -> Self {
        match a {
            ArchArg::X86_64 => Arch::X86_64,
            ArchArg::Aarch64 => Arch::Aarch64,
            ArchArg::RiscV64 => Arch::RiscV64,
        }
    }
}

// ─── Detectors ───────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum DetectorCommands {
    /// List all available security detectors
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show details about a specific detector
    Info {
        /// Detector name
        name: String,
    },
}

// ─── QEMU ────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum QemuCommands {
    /// Show QEMU launch configuration for a firmware image
    Run(QemuRunArgs),

    /// Dump memory from a QEMU instance
    Dump(QemuDumpArgs),
}

#[derive(Parser)]
struct QemuRunArgs {
    /// ESP disk image to boot
    #[arg(short, long)]
    esp: PathBuf,

    /// Target architecture
    #[arg(short, long, value_enum, default_value = "x86-64")]
    arch: ArchArg,

    /// OVMF/firmware path
    #[arg(short, long)]
    firmware: Option<String>,

    /// VM memory in MB
    #[arg(short, long, default_value = "256")]
    memory: u32,

    /// Timeout in seconds
    #[arg(short, long, default_value = "30")]
    timeout: u32,
}

#[derive(Parser)]
struct QemuDumpArgs {
    /// Output path for memory dump
    #[arg(short, long)]
    output: PathBuf,

    /// Target architecture
    #[arg(short, long, value_enum, default_value = "x86-64")]
    arch: ArchArg,
}

// ─── ESP ─────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum EspCommands {
    /// Build an ESP image with an embedded payload
    Build(EspBuildArgs),
}

#[derive(Parser)]
struct EspBuildArgs {
    /// Path to payload binary to embed
    #[arg(short, long)]
    payload: PathBuf,

    /// Output ESP image path
    #[arg(short, long, default_value = "esp.img")]
    output: PathBuf,

    /// ESP image size in MB
    #[arg(short, long, default_value = "64")]
    size: u32,
}

// ─── Table row types ─────────────────────────────────────────────────────────

#[derive(Tabled)]
struct DetectorRow {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Detector")]
    name: String,
}

#[derive(Tabled)]
struct PayloadRow {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Payload")]
    name: String,
    #[tabled(rename = "Arch")]
    arch: String,
    #[tabled(rename = "Expected Detections")]
    detections: usize,
}

#[derive(Tabled)]
struct FindingRow {
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Detector")]
    detector: String,
    #[tabled(rename = "Title")]
    title: String,
}

#[derive(Tabled)]
struct ValidationRow {
    #[tabled(rename = "Payload")]
    name: String,
    #[tabled(rename = "Detected")]
    detected: String,
    #[tabled(rename = "Expected")]
    expected: usize,
    #[tabled(rename = "Matched")]
    matched: usize,
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Err(e) = run(cli) {
        eprintln!("{} {}", "error:".red().bold(), e);
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Scan(args) => cmd_scan(args),
        Commands::Baseline { command } => match command {
            BaselineCommands::Create(args) => cmd_baseline_create(args),
            BaselineCommands::Show(args) => cmd_baseline_show(args),
        },
        Commands::Report(args) => cmd_report(args),
        Commands::Validate(args) => cmd_validate(args),
        Commands::Adversary { command } => match command {
            AdversaryCommands::Generate(args) => cmd_adversary_generate(args),
            AdversaryCommands::List => cmd_adversary_list(),
            AdversaryCommands::Corpus(args) => cmd_adversary_corpus(args),
            AdversaryCommands::Validate(args) => cmd_adversary_validate(args),
        },
        Commands::Detectors { command } => match command {
            DetectorCommands::List { json } => cmd_detectors_list(json),
            DetectorCommands::Info { name } => cmd_detectors_info(&name),
        },
        Commands::Qemu { command } => match command {
            QemuCommands::Run(args) => cmd_qemu_run(args),
            QemuCommands::Dump(args) => cmd_qemu_dump(args),
        },
        Commands::Esp { command } => match command {
            EspCommands::Build(args) => cmd_esp_build(args),
        },
        Commands::Info => cmd_info(),
    }
}

// ─── Command Implementations ─────────────────────────────────────────────────

fn cmd_scan(args: ScanArgs) -> Result<()> {
    let baseline = match args.baseline {
        Some(ref path) => Some(Baseline::load(path)?),
        None => None,
    };

    let mut scanner = BarzakhScanner::new(baseline);
    let detector_count = scanner.detector_count();

    if !args.quiet && !args.json {
        println!(
            "{} {} {}",
            "▶".cyan().bold(),
            "Scanning".bold(),
            args.target.display()
        );
        println!("  {} detectors loaded", detector_count.to_string().cyan());
    }

    let pb = if !args.quiet && !args.json {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message("Running detectors...");
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let scan_types: Option<Vec<String>> = args.scan_types;
    let scan_types_refs: Option<Vec<&str>> = scan_types
        .as_ref()
        .map(|v| v.iter().map(|s| s.as_str()).collect());

    let result = scanner.scan(&args.target, scan_types_refs.as_deref());

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result.findings)?);
        if result.summary.bootkit_detected {
            process::exit(1);
        }
        return Ok(());
    }

    if !args.quiet {
        println!();
        println!(
            "{} Scan complete in {:.3}s",
            "✓".green().bold(),
            result.scan_info.duration_seconds
        );
        println!();

        if result.findings.is_empty() {
            println!("  {} No threats detected", "●".green());
        } else {
            let rows: Vec<FindingRow> = result
                .findings
                .iter()
                .map(|f| FindingRow {
                    severity: format_severity(&f.severity),
                    detector: f.detector.clone(),
                    title: f.title.clone(),
                })
                .collect();
            println!("{}", Table::new(&rows));
        }

        println!();
        println!("  {} {}", "Findings:".bold(), result.summary.total_findings);
        println!(
            "    {} {} {} {} {} {} {} {}",
            "Critical:".red().bold(),
            result.summary.critical_count,
            "High:".yellow().bold(),
            result.summary.high_count,
            "Medium:".bright_yellow(),
            result.summary.medium_count,
            "Low:".green(),
            result.summary.low_count,
        );

        if result.summary.bootkit_detected {
            println!();
            println!("  {} {}", "⚠".red().bold(), "BOOTKIT DETECTED".red().bold());
        }
    }

    if let Some(report_path) = args.report {
        let format = ReportFormat::from_str(&args.format)
            .ok_or_else(|| anyhow::anyhow!("Unknown format: {}", args.format))?;
        scanner.generate_report(&report_path, format)?;
        if !args.quiet {
            println!("  Report written to: {}", report_path.display());
        }
    }

    if result.summary.bootkit_detected {
        process::exit(1);
    }

    Ok(())
}

fn cmd_baseline_create(args: BaselineCreateArgs) -> Result<()> {
    println!(
        "{} Creating baseline from {}",
        "▶".cyan().bold(),
        args.target.display()
    );

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&args.target, None);

    let baseline_data = serde_json::json!({
        "source": args.target.display().to_string(),
        "findings_at_creation": result.summary.total_findings,
        "scan_info": {
            "duration_seconds": result.scan_info.duration_seconds,
        },
        "pcr_values": {},
        "memory_map": [],
        "boot_services_table": [],
        "event_log": [],
    });

    std::fs::write(&args.output, serde_json::to_string_pretty(&baseline_data)?)?;
    println!(
        "{} Baseline written to: {}",
        "✓".green().bold(),
        args.output.display()
    );

    Ok(())
}

fn cmd_baseline_show(args: BaselineShowArgs) -> Result<()> {
    let baseline = Baseline::load(&args.path)?;
    println!("{} Baseline: {}", "▶".cyan().bold(), args.path.display());
    println!("{}", serde_json::to_string_pretty(&baseline)?);
    Ok(())
}

fn cmd_report(args: ReportArgs) -> Result<()> {
    let baseline = match args.baseline {
        Some(ref path) => Some(Baseline::load(path)?),
        None => None,
    };

    let mut scanner = BarzakhScanner::new(baseline);

    println!(
        "{} Scanning {} for report...",
        "▶".cyan().bold(),
        args.target.display()
    );

    scanner.scan(&args.target, None);

    let format = ReportFormat::from_str(&args.format)
        .ok_or_else(|| anyhow::anyhow!("Unknown format: {}", args.format))?;

    scanner.generate_report(&args.output, format)?;
    println!(
        "{} Report written to: {}",
        "✓".green().bold(),
        args.output.display()
    );

    Ok(())
}

fn cmd_validate(args: ValidateArgs) -> Result<()> {
    let baseline = match args.baseline {
        Some(ref path) => Some(Baseline::load(path)?),
        None => None,
    };

    let scanner = BarzakhScanner::new(baseline);

    if !args.json {
        println!(
            "{} Validating against corpus: {}",
            "▶".cyan().bold(),
            args.corpus.display()
        );
    }

    let metrics = scanner.validate_against_corpus(&args.corpus)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&metrics)?);
    } else {
        println!();
        println!("  {}", "Validation Results".bold());
        println!("  ─────────────────────────────");
        println!(
            "  True Positives:  {}",
            metrics.true_positives.to_string().green()
        );
        println!(
            "  False Positives: {}",
            metrics.false_positives.to_string().red()
        );
        println!(
            "  True Negatives:  {}",
            metrics.true_negatives.to_string().green()
        );
        println!(
            "  False Negatives: {}",
            metrics.false_negatives.to_string().red()
        );
        println!("  ─────────────────────────────");
        println!(
            "  TPR: {}",
            format!("{:.4}", metrics.true_positive_rate).cyan().bold()
        );
        println!(
            "  FPR: {}",
            format!("{:.4}", metrics.false_positive_rate).cyan().bold()
        );
    }

    Ok(())
}

fn cmd_adversary_generate(args: AdversaryGenerateArgs) -> Result<()> {
    let payloads = create_all_payloads();
    let payload = payloads
        .iter()
        .find(|p| p.name() == args.payload)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown payload '{}'. Use 'barzakh adversary list' to see available payloads.",
                args.payload
            )
        })?;

    let config = PayloadConfig {
        arch: args.arch.into(),
        size: args.size,
    };

    println!(
        "{} Generating payload: {}",
        "▶".cyan().bold(),
        payload.name().yellow()
    );

    let data = payload.generate(&config)?;
    std::fs::write(&args.output, &data)?;

    println!(
        "{} Written {} bytes to {}",
        "✓".green().bold(),
        data.len(),
        args.output.display()
    );

    Ok(())
}

fn cmd_adversary_list() -> Result<()> {
    let payloads = create_all_payloads();

    let rows: Vec<PayloadRow> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| PayloadRow {
            index: i + 1,
            name: p.name().to_string(),
            arch: format!("{:?}", p.arch()),
            detections: p.expected_detections().len(),
        })
        .collect();

    println!(
        "{} {} adversary payloads available:\n",
        "▶".cyan().bold(),
        payloads.len().to_string().yellow()
    );
    println!("{}", Table::new(&rows));
    Ok(())
}

fn cmd_adversary_corpus(args: AdversaryCorpusArgs) -> Result<()> {
    println!(
        "{} Generating test corpus to {}",
        "▶".cyan().bold(),
        args.output.display()
    );

    let generated = barzakh_adversary::corpus::generate_corpus(&args.output)?;

    println!(
        "{} Generated {} files",
        "✓".green().bold(),
        generated.len().to_string().yellow()
    );

    for name in &generated {
        let icon = if name.starts_with("malicious_") {
            "⚡".red()
        } else {
            "○".green()
        };
        println!("  {} {}", icon, name);
    }

    Ok(())
}

fn cmd_adversary_validate(args: AdversaryValidateArgs) -> Result<()> {
    let payloads = create_all_payloads();

    if !args.json {
        println!(
            "{} Validating {} payloads against scanner...",
            "▶".cyan().bold(),
            payloads.len()
        );
    }

    let report = validate_all(&payloads, &args.corpus)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let rows: Vec<ValidationRow> = report
        .results
        .iter()
        .map(|r| ValidationRow {
            name: r.payload_name.clone(),
            detected: if r.detected {
                "YES".green().to_string()
            } else {
                "NO".red().to_string()
            },
            expected: r.expected_findings,
            matched: r.matched_findings,
        })
        .collect();

    println!();
    println!("{}", Table::new(&rows));
    println!();
    println!("  {}", "Summary".bold());
    println!("  ─────────────────────────────");
    println!("  Total payloads: {}", report.total_payloads);
    println!(
        "  Detected:       {}",
        report.detected_count.to_string().green()
    );
    println!(
        "  Missed:         {}",
        report.missed_count.to_string().red()
    );
    println!(
        "  TPR:            {}",
        format!("{:.2}%", report.true_positive_rate * 100.0)
            .cyan()
            .bold()
    );

    Ok(())
}

fn cmd_detectors_list(json: bool) -> Result<()> {
    let detectors = barzakh_core::detectors::create_all_detectors(None);

    if json {
        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        println!("{}", serde_json::to_string_pretty(&names)?);
        return Ok(());
    }

    let rows: Vec<DetectorRow> = detectors
        .iter()
        .enumerate()
        .map(|(i, d)| DetectorRow {
            index: i + 1,
            name: d.name().to_string(),
        })
        .collect();

    println!(
        "{} {} security detectors available:\n",
        "▶".cyan().bold(),
        detectors.len().to_string().yellow()
    );
    println!("{}", Table::new(&rows));
    Ok(())
}

fn cmd_detectors_info(name: &str) -> Result<()> {
    let detectors = barzakh_core::detectors::create_all_detectors(None);

    let detector = detectors.iter().find(|d| d.name() == name).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown detector '{}'. Use 'barzakh detectors list' to see available detectors.",
            name
        )
    })?;

    println!("{} {}", "Detector:".bold(), detector.name().cyan());
    Ok(())
}

fn cmd_qemu_run(args: QemuRunArgs) -> Result<()> {
    let config = QemuConfig {
        arch: args.arch.into(),
        memory_mb: args.memory,
        firmware_path: args.firmware,
        timeout_secs: args.timeout,
    };

    let qemu_args = config.build_args(&args.esp);

    println!("{} QEMU Launch Configuration", "▶".cyan().bold());
    println!("  Binary:   {}", config.binary_name().yellow());
    println!("  Arch:     {:?}", config.arch);
    println!("  Memory:   {}MB", config.memory_mb);
    println!("  Timeout:  {}s", config.timeout_secs);
    println!("  ESP:      {}", args.esp.display());
    println!();
    println!("  {}", "Command:".bold());
    println!("  {} {}", config.binary_name(), qemu_args.join(" "));

    Ok(())
}

fn cmd_qemu_dump(args: QemuDumpArgs) -> Result<()> {
    let config = QemuConfig {
        arch: args.arch.into(),
        ..QemuConfig::default()
    };

    qemu::dump_memory(&config, &args.output)?;
    Ok(())
}

fn cmd_esp_build(args: EspBuildArgs) -> Result<()> {
    println!("{} Building ESP image ({}MB)", "▶".cyan().bold(), args.size);

    let payload_data = std::fs::read(&args.payload)?;
    let builder = EspImageBuilder::new(args.size);
    builder.build_with_payload(&payload_data, &args.output)?;

    println!(
        "{} ESP image written to: {}",
        "✓".green().bold(),
        args.output.display()
    );
    println!(
        "  Payload: {} ({} bytes)",
        args.payload.display(),
        payload_data.len()
    );

    Ok(())
}

fn cmd_info() -> Result<()> {
    let detectors = barzakh_core::detectors::create_all_detectors(None);
    let payloads = create_all_payloads();

    println!();
    println!("  {}", "Barzakh — UEFI Firmware Security Platform".bold());
    println!("  ═══════════════════════════════════════════");
    println!();
    println!("  Version:       {}", env!("CARGO_PKG_VERSION").cyan());
    println!("  Detectors:     {}", detectors.len().to_string().yellow());
    println!("  Payloads:      {}", payloads.len().to_string().yellow());
    println!("  Architectures: x86_64, aarch64, riscv64");
    println!("  Report formats: JSON, HTML, Markdown");
    println!();
    println!("  {}", "Detector Categories:".bold());
    println!("    • TPM/PCR analysis (PCR, PCR Oracle, PCR Replay, Attestation)");
    println!("    • Memory forensics (Memory, Hook, Runtime Hook, SMM)");
    println!("    • Firmware structure (Firmware Volume, SPI Integrity, MBR)");
    println!("    • Secure Boot chain (SecureBoot, SecureBoot Chain, Differ)");
    println!("    • Behavioral analysis (Entropy, Self-Erasure, Time Travel)");
    println!("    • Intel ME/Ring -3 (HECI, ME SPI, AMT, fTPM, ME DMA)");
    println!();

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn format_severity(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "CRIT".red().bold().to_string(),
        Severity::High => "HIGH".yellow().bold().to_string(),
        Severity::Medium => "MED".bright_yellow().to_string(),
        Severity::Low => "LOW".green().to_string(),
        Severity::Info => "INFO".blue().to_string(),
    }
}
