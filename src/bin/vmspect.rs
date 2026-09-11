//! # vmspect CLI
//!
//! Command-line entry point for the static inspection and analysis of virtual disk images.
//! Supports analyzing individual images or scanning entire directories sequentially or
//! concurrently.

use std::env;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use vmspect::prelude::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Configuration parsed from the command line.
#[derive(Debug, Default)]
struct CliConfig {
    /// Mandatory path to the target image file or directory.
    target_path: Option<PathBuf>,
    /// Prints structured JSON-formatted output.
    json_format: bool,
    /// Runs the analysis in parallel via [`ConcurrentProcessor`].
    concurrent: bool,
    /// Explicitly permits the external read-only `qemu-nbd` helper.
    force_nbd: bool,
    /// Recursive search when the target is a directory.
    recursive: bool,
    /// Disables collection of installed applications.
    no_apps: bool,
    /// Disables collection of guest-OS metadata.
    no_system: bool,
    /// Forces reading of the `SYSTEM` hive on Windows.
    include_system: bool,
    /// Maximum number of worker threads in concurrent mode.
    max_workers: Option<usize>,
    /// Requests complete reports, including installed programs, for directory JSON output.
    full_report: bool,
    /// Directory names or paths excluded from recursive discovery.
    excluded_directories: Vec<PathBuf>,
    /// Maximum discovery depth, with the selected root at depth zero.
    max_depth: Option<usize>,
    /// Suppresses discovery warnings on stderr while retaining them in JSON output.
    quiet_discovery: bool,
}

fn print_help() {
    println!(
        r#"vmspect {VERSION} - Static inspection and forensic analysis of virtual disk images

USAGE:
    vmspect [OPTIONS] <PATH>

ARGUMENTS:
    <PATH>                     Path to a virtual disk file (.vmdk, .raw, .qcow2, .vhdx, .vdi, etc.)
                               or to a directory containing VM disk images.

OPTIONS:
    --json                     Prints structured JSON output to stdout.
    --concurrent               Enables concurrent image processing via ConcurrentProcessor.
    --force-nbd                Explicitly permits qemu-nbd for formats without direct support.
    -r, --recursive            Searches images recursively when scanning a directory.
    --no-apps                  Skips extraction of the installed-software catalog.
    --no-system                Skips extraction of guest-OS information and metadata.
    --include-system           Also extracts the SYSTEM hive from the Registry on Windows images.
    --full-report              Include installed programs in directory JSON output.
    --exclude <DIR>            Exclude a directory path or name from recursive discovery.
    --max-depth <NUM>          Maximum discovery depth (selected root is depth 0).
    --quiet-discovery          Suppress discovery warnings on stderr.
    -w, --workers <NUM>        Worker threads for a directory (default: 1 sequential, 2 concurrent).
    -h, --help                 Shows this help information.
    -V, --version              Shows the current tool version.

EXAMPLES:
    vmspect disk.vmdk
    vmspect disk.qcow2 --json
    vmspect fixtures --concurrent --recursive
    vmspect disk.vmdk --force-nbd
"#
    );
}

fn print_version() {
    println!("vmspect {}", VERSION);
}

fn parse_args() -> std::result::Result<CliConfig, String> {
    parse_args_from(env::args().skip(1))
}

fn parse_args_from<I>(mut args: I) -> std::result::Result<CliConfig, String>
where
    I: Iterator<Item = String>,
{
    let mut config = CliConfig::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            "-V" | "--version" => {
                print_version();
                process::exit(0);
            }
            "--json" => {
                config.json_format = true;
            }
            "--concurrent" => {
                config.concurrent = true;
            }
            "--force-nbd" => {
                config.force_nbd = true;
            }
            "-r" | "--recursive" => {
                config.recursive = true;
            }
            "--no-apps" => {
                config.no_apps = true;
            }
            "--no-system" => {
                config.no_system = true;
            }
            "--include-system" => {
                config.include_system = true;
            }
            "--full-report" => {
                config.full_report = true;
            }
            "--exclude" => {
                config
                    .excluded_directories
                    .push(PathBuf::from(args.next().ok_or_else(|| {
                        "A directory is required for --exclude".to_string()
                    })?));
            }
            "--max-depth" => {
                let value = args
                    .next()
                    .ok_or_else(|| "A numeric value is required for --max-depth".to_string())?;
                config.max_depth = Some(
                    value
                        .parse()
                        .map_err(|_| format!("Invalid maximum depth: '{}'", value))?,
                );
            }
            "--quiet-discovery" => {
                config.quiet_discovery = true;
            }
            "-w" | "--workers" => {
                let value = args
                    .next()
                    .ok_or_else(|| "A numeric value is required for --workers".to_string())?;
                let num = value
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid worker count: '{}'", value))?;
                if num == 0 {
                    return Err("Worker count must be at least 1".to_string());
                }
                config.max_workers = Some(num);
            }
            other if other.starts_with("--workers=") => {
                let value = other.trim_start_matches("--workers=");
                let num = value
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid worker count: '{}'", value))?;
                if num == 0 {
                    return Err("Worker count must be at least 1".to_string());
                }
                config.max_workers = Some(num);
            }
            other if other.starts_with('-') => {
                return Err(format!(
                    "Unknown option: '{}'. Use --help to see the available options.",
                    other
                ));
            }
            positional => {
                if config.target_path.is_none() {
                    config.target_path = Some(PathBuf::from(positional));
                } else {
                    return Err(format!("Unexpected positional argument: '{}'", positional));
                }
            }
        }
    }

    Ok(config)
}

fn main() {
    let config = match parse_args() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Argument error: {}", err);
            eprintln!("Run 'vmspect --help' for the correct usage.");
            process::exit(1);
        }
    };

    let path = match config.target_path {
        Some(ref p) => p,
        None => {
            eprintln!("Error: a path to a disk image or directory is required.");
            eprintln!("Usage: vmspect [OPTIONS] <PATH>");
            eprintln!("Run 'vmspect --help' for more information.");
            process::exit(1);
        }
    };

    if !path.exists() {
        eprintln!(
            "Error: the supplied path does not exist: {}",
            path.display()
        );
        process::exit(1);
    }

    let options = Options {
        force_nbd: config.force_nbd,
        no_apps: config.no_apps,
        no_system: config.no_system,
        include_system: config.include_system,
        ..Default::default()
    };

    if config.force_nbd {
        eprintln!(
            "Warning: --force-nbd launches qemu-nbd as an external read-only helper. It does not mount or attach the image, but is disabled by default because it adds another I/O layer."
        );
    }

    if path.is_file() {
        run_file(path, &options, config.json_format);
    } else if path.is_dir() {
        run_directory(path, &config, &options);
    } else {
        eprintln!(
            "Error: the supplied path is neither a file nor a valid directory: {}",
            path.display()
        );
        process::exit(1);
    }
}

fn run_file(path: &Path, options: &Options, json_format: bool) {
    if is_secondary_extent(path) && !json_format {
        eprintln!(
            "Note: '{}' looks like a secondary extent fragment. If analysis fails, point at the main .vmdk descriptor instead.",
            path.display()
        );
    }

    if json_format {
        let engine = InspectionEngine::new(options.clone());
        match engine.inspect(path) {
            Ok(report) => match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error serializing JSON: {}", e);
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Inspection error on '{}': {}", path.display(), e);
                process::exit(1);
            }
        }
    } else {
        println!("============================================================");
        println!("  Starting inspection of: {}", path.display());
        println!("============================================================");

        let start = Instant::now();
        let result = inspect_with_progress(path, options, |progress| {
            let detail_str = progress.detail.as_deref().unwrap_or("");
            if !detail_str.is_empty() {
                eprintln!(
                    "[{:>3}%] {} ({})",
                    progress.percentage, progress.stage, detail_str
                );
            } else {
                eprintln!("[{:>3}%] {}", progress.percentage, progress.stage);
            }
        });

        match result {
            Ok(report) => {
                print_human_report(&report, start.elapsed().as_millis() as u64);
            }
            Err(e) => {
                eprintln!("\nError inspecting image '{}': {}", path.display(), e);
                process::exit(1);
            }
        }
    }
}

fn run_directory(directory: &Path, config: &CliConfig, options: &Options) {
    let discovery = match list_vms_with_options(
        directory,
        &DiscoveryOptions {
            recursive: config.recursive,
            excluded_directories: config.excluded_directories.clone(),
            emit_warnings: !config.quiet_discovery,
            max_depth: config.max_depth,
        },
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!(
                "Error listing images in '{}': {}",
                directory.display(),
                error
            );
            process::exit(1);
        }
    };
    let images = discovery.images;
    if images.is_empty() {
        if config.json_format {
            let value = serde_json::json!({
                "reports": [],
                "errors": [],
                "discovery_warnings": discovery.warnings,
                "inaccessible_directories": discovery.inaccessible_directories,
            });
            println!(
                "{}",
                serde_json::to_string(&value).expect("JSON value is serializable")
            );
        } else {
            println!(
                "No virtual disk images were found in '{}'.",
                directory.display()
            );
        }
        return;
    }
    let workers = config
        .max_workers
        .unwrap_or(if config.concurrent { 2 } else { 1 })
        .max(1);
    let mut batch_options = options.clone();
    // Directory discovery is an initial listing; fetch complete reports only when requested.
    if !config.full_report {
        batch_options.no_apps = true;
    }
    let start = Instant::now();
    let result = InspectionEngine::new(batch_options).inspect_batch(images, workers);
    match result {
        Ok(batch) if config.json_format => {
            let value = if config.full_report {
                serde_json::json!({ "reports": batch.reports, "errors": batch.errors, "discovery_warnings": discovery.warnings, "inaccessible_directories": discovery.inaccessible_directories })
            } else {
                let summaries = batch
                    .reports
                    .iter()
                    .map(InspectionReport::summary)
                    .collect::<Vec<_>>();
                serde_json::json!({ "reports": summaries, "errors": batch.errors, "discovery_warnings": discovery.warnings, "inaccessible_directories": discovery.inaccessible_directories })
            };
            match serde_json::to_string_pretty(&value) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("Error serializing JSON: {error}");
                    process::exit(1);
                }
            }
        }
        Ok(batch) => {
            for report in &batch.reports {
                print_human_report(report, report.stats.duration_ms);
            }
            for error in &batch.errors {
                eprintln!(
                    "Warning: analysis of '{}': {}",
                    error.path.display(),
                    error.error
                );
            }
            println!(
                "Processed {}/{} images in {} ms with {} errors.",
                batch.reports.len(),
                batch.reports.len() + batch.errors.len(),
                start.elapsed().as_millis(),
                batch.errors.len()
            );
        }
        Err(error) => {
            eprintln!("Error during batch processing: {error}");
            process::exit(1);
        }
    }
}

fn print_human_report(report: &InspectionReport, duration_ms: u64) {
    let img = &report.image;
    let os = &report.operating_system;
    let info = &report.guest_info;

    println!("\n[+] IMAGE INFO");
    println!("    File:            {}", img.path.display());
    println!("    Format:          {}", img.format.to_uppercase());
    println!("    Hypervisor:      {}", img.hypervisor.name());
    println!(
        "    Virtual Size:    {} ({} bytes)",
        format_bytes(img.virtual_size),
        img.virtual_size
    );
    println!(
        "    On-disk Size:    {} ({} bytes)",
        format_bytes(img.actual_size),
        img.actual_size
    );

    println!("\n[+] PARTITIONS ({:?})", report.scheme);
    if report.partitions.is_empty() {
        println!("    (No recognizable partitions were identified)");
    } else {
        for p in &report.partitions {
            let label = p
                .label
                .as_deref()
                .map(|l| format!(" [Label: {}]", l))
                .unwrap_or_default();
            println!(
                "    #{} - FS: {:<10} Size: {:<10} Offset: {:<12} Type: {}{}",
                p.index,
                p.file_system.name(),
                format_bytes(p.size),
                p.start,
                p.kind,
                label
            );
        }
    }

    println!("\n[+] OPERATING SYSTEM {}", os.icon());
    println!("    Family:          {:?}", os);
    if !info.os_name.is_empty() {
        println!("    Name / Version:  {}", info.formatted_os_string());
    } else {
        println!("    Name / Version:  Not detected or unavailable");
    }
    if let Some(ref tools) = info.guest_tools {
        if tools.present {
            if let Some(ref ver) = tools.version {
                println!("    Guest Tools:     {} {}", tools.kind, ver);
            } else {
                println!("    Guest Tools:     {}", tools.kind);
            }
        }
    }

    if !report.warnings.is_empty() {
        println!("\n[!] WARNINGS ({})", report.warnings.len());
        for warning in &report.warnings {
            println!("    - {}", warning);
        }
    }

    println!(
        "\n[+] INSTALLED SOFTWARE ({})",
        report.installed_programs.len()
    );
    if report.installed_programs.is_empty() {
        println!("    (No applications detected or extraction disabled)");
    } else {
        for (idx, prog) in report.installed_programs.iter().enumerate() {
            let ver = prog.version.as_deref().unwrap_or("-");
            let publisher = prog.publisher.as_deref().unwrap_or("-");
            println!(
                "    {:>4}. {:<45} | Version: {:<20} | Publisher: {}",
                idx + 1,
                prog.name,
                ver,
                publisher
            );
        }
    }

    println!("\n[+] STATISTICS");
    println!("    Access Mode:     {}", report.stats.access_mode);
    println!(
        "    Bytes Read:      {}",
        format_bytes(report.stats.bytes_read)
    );
    println!("    Read Operations: {}", report.stats.read_operations);
    println!("    Cache Hits:      {}", report.stats.cache_hits);
    println!("    Source Location: {}", report.stats.source_location);
    if report.stats.nbd_requests > 0 {
        println!("    NBD Requests:    {}", report.stats.nbd_requests);
    }
    println!(
        "    Phase Durations: identify {} ms | backend {} ms | partitions {} ms | guest {} ms | report {} ms",
        report.stats.identification_duration_ms,
        report.stats.backend_initialization_duration_ms,
        report.stats.partition_detection_duration_ms,
        report.stats.guest_analysis_duration_ms,
        report.stats.report_generation_duration_ms
    );
    println!(
        "    Duration:        {} ms ({:.2} s)",
        duration_ms,
        duration_ms as f64 / 1000.0
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_basic() {
        let args = vec!["image.vmdk".to_string()];
        let cfg = parse_args_from(args.into_iter()).unwrap();
        assert_eq!(cfg.target_path, Some(PathBuf::from("image.vmdk")));
        assert!(!cfg.json_format);
        assert!(!cfg.concurrent);
        assert!(!cfg.force_nbd);
    }

    #[test]
    fn test_parse_optional_flags() {
        let args = vec![
            "--json".to_string(),
            "--concurrent".to_string(),
            "--force-nbd".to_string(),
            "--recursive".to_string(),
            "--no-apps".to_string(),
            "--no-system".to_string(),
            "--include-system".to_string(),
            "--workers".to_string(),
            "8".to_string(),
            "/path/vms".to_string(),
        ];
        let cfg = parse_args_from(args.into_iter()).unwrap();
        assert_eq!(cfg.target_path, Some(PathBuf::from("/path/vms")));
        assert!(cfg.json_format);
        assert!(cfg.concurrent);
        assert!(cfg.force_nbd);
        assert!(cfg.recursive);
        assert!(cfg.no_apps);
        assert!(cfg.no_system);
        assert!(cfg.include_system);
        assert_eq!(cfg.max_workers, Some(8));
    }

    #[test]
    fn test_parse_workers_equals_format() {
        let args = vec!["--workers=12".to_string(), "disk.qcow2".to_string()];
        let cfg = parse_args_from(args.into_iter()).unwrap();
        assert_eq!(cfg.max_workers, Some(12));
        assert_eq!(cfg.target_path, Some(PathBuf::from("disk.qcow2")));
    }

    #[test]
    fn test_parse_discovery_and_full_report_flags() {
        let args = vec![
            "--exclude".to_string(),
            "fixtures".to_string(),
            "--exclude".to_string(),
            "tempdir".to_string(),
            "--max-depth".to_string(),
            "2".to_string(),
            "--quiet-discovery".to_string(),
            "--full-report".to_string(),
            "sample-vm".to_string(),
        ];
        let cfg = parse_args_from(args.into_iter()).unwrap();
        assert_eq!(
            cfg.excluded_directories,
            vec![PathBuf::from("fixtures"), PathBuf::from("tempdir")]
        );
        assert_eq!(cfg.max_depth, Some(2));
        assert!(cfg.quiet_discovery);
        assert!(cfg.full_report);
    }

    #[test]
    fn test_parse_rejects_incomplete_or_invalid_values() {
        assert!(parse_args_from(vec!["--exclude".to_string()].into_iter()).is_err());
        assert!(
            parse_args_from(vec!["--max-depth".to_string(), "no".to_string()].into_iter()).is_err()
        );
        assert!(
            parse_args_from(vec!["--workers".to_string(), "0".to_string()].into_iter()).is_err()
        );
    }

    #[test]
    fn test_parse_unknown_option_error() {
        let args = vec!["--unknown-option".to_string(), "disk.raw".to_string()];
        let err = parse_args_from(args.into_iter()).unwrap_err();
        assert!(err.contains("Unknown option"));
    }

    #[test]
    fn test_parse_multiple_positional_error() {
        let args = vec!["disk1.vmdk".to_string(), "disk2.vmdk".to_string()];
        let err = parse_args_from(args.into_iter()).unwrap_err();
        assert!(err.contains("Unexpected positional argument"));
    }
}
