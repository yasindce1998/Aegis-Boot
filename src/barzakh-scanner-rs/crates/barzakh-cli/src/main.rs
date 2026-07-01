use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tabled::{Table, Tabled};
use tracing_subscriber::EnvFilter;

use barzakh_core::{BarzakhScanner, Baseline, ReportFormat, Severity};

#[derive(Parser)]
#[command(
    name = "barzakh",
    about = "Barzakh — UEFI Firmware Security Analysis Platform",
    long_about = "A comprehensive UEFI bootkit detection engine with 30 security detectors\n\
                  for firmware integrity verification and threat analysis.",
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

    /// List and inspect security detectors
    Detectors {
        #[command(subcommand)]
        command: DetectorCommands,
    },

    /// Display platform information and statistics
    Info,

    /// Run the automated fuzzing harness
    Fuzz(FuzzArgs),
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

// ─── Fuzz ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct FuzzArgs {
    /// Number of mutation iterations
    #[arg(short, long, default_value = "1")]
    iterations: u32,

    /// Output directory for generated corpus
    #[arg(short, long, default_value = "./fuzz_corpus")]
    output_dir: PathBuf,

    /// Enable payload mutation
    #[arg(long)]
    mutate: bool,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
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

// ─── Table row types ─────────────────────────────────────────────────────────

#[derive(Tabled)]
struct DetectorRow {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Detector")]
    name: String,
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
        Commands::Detectors { command } => match command {
            DetectorCommands::List { json } => cmd_detectors_list(json),
            DetectorCommands::Info { name } => cmd_detectors_info(&name),
        },
        Commands::Info => cmd_info(),
        Commands::Fuzz(args) => cmd_fuzz(args),
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

fn cmd_info() -> Result<()> {
    let detectors = barzakh_core::detectors::create_all_detectors(None);

    println!();
    println!("  {}", "Barzakh — UEFI Firmware Security Scanner".bold());
    println!("  ═══════════════════════════════════════════");
    println!();
    println!("  Version:       {}", env!("CARGO_PKG_VERSION").cyan());
    println!("  Detectors:     {}", detectors.len().to_string().yellow());
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
    println!("    • Ring -4/Microarch (Microcode, Spectre, Thermal, Voltage, Debug, Rowhammer)");
    println!();

    Ok(())
}

fn cmd_fuzz(args: FuzzArgs) -> Result<()> {
    use barzakh_adversary::harness::{FuzzHarness, HarnessConfig};

    let config = HarnessConfig {
        iterations: args.iterations,
        output_dir: args.output_dir.clone(),
        mutate: args.mutate,
        parallel: true,
    };

    if !args.json {
        println!(
            "{} Running fuzzing harness ({} iterations, mutate={})",
            "▶".cyan().bold(),
            args.iterations,
            args.mutate
        );
        println!("  Output dir: {}", args.output_dir.display());
    }

    let harness = FuzzHarness::new(config);
    let result = harness.run()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!();
        println!(
            "{} Fuzzing complete in {:.2}s",
            "✓".green().bold(),
            result.duration_secs
        );
        println!("  Total runs:  {}", result.total_runs.to_string().cyan());
        println!(
            "  Coverage:    {}",
            format!("{:.1}%", result.gap_report.coverage_pct).green()
        );
        println!(
            "  Gaps found:  {}",
            result.gap_report.total_gaps.to_string().yellow()
        );

        if !result.gap_report.entries.is_empty() {
            println!();
            println!("  {}", "Detection Gaps:".bold());
            for gap in &result.gap_report.entries {
                println!(
                    "    {} {} → missed: {}",
                    "•".red(),
                    gap.payload_name,
                    gap.missed_detectors.join(", ")
                );
            }
        }

        if !result.gap_report.undetected_categories.is_empty() {
            println!();
            println!("  {}", "Undetected categories:".bold());
            for cat in &result.gap_report.undetected_categories {
                println!("    {} {}", "○".yellow(), cat);
            }
        }
    }

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
