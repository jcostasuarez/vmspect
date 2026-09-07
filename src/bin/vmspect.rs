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
    /// Forces the `qemu-nbd` backend even for natively-readable formats.
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
    --force-nbd                Forces the qemu-nbd backend for every disk format.
    -r, --recursive            Searches images recursively when scanning a directory.
    --no-apps                  Skips extraction of the installed-software catalog.
    --no-system                Skips extraction of guest-OS information and metadata.
    --include-system           Also extracts the SYSTEM hive from the Registry on Windows images.
    -w, --workers <NUM>        Maximum number of concurrent threads (default: logical CPU cores).
    -h, --help                 Shows this help information.
    -V, --version              Shows the current tool version.

EXAMPLES:
    vmspect disk.vmdk
    vmspect disk.qcow2 --json
    vmspect /var/lib/libvirt/images/ --concurrent --recursive
    vmspect C:\VMs\Windows10.vmdk --force-nbd
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
            "-w" | "--workers" => {
                let value = args
                    .next()
                    .ok_or_else(|| "A numeric value is required for --workers".to_string())?;
                let num = value
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid worker count: '{}'", value))?;
                config.max_workers = Some(num);
            }
            other if other.starts_with("--workers=") => {
                let value = other.trim_start_matches("--workers=");
                let num = value
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid worker count: '{}'", value))?;
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
    let images = match list_vms(directory, config.recursive) {
        Ok(imgs) => imgs,
        Err(e) => {
            eprintln!("Error listing images in '{}': {}", directory.display(), e);
            process::exit(1);
        }
    };

    if images.is_empty() {
        if config.json_format {
            println!("[]");
        } else {
            println!(
                "No virtual disk images were found in '{}'.",
                directory.display()
            );
        }
        return;
    }

    let max_workers = config.max_workers.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    if config.concurrent {
        if !config.json_format {
            println!("============================================================");
            println!("  Concurrent Scan: {} images found", images.len());
            println!("  Directory: {}", directory.display());
            println!("  Worker threads: {}", max_workers);
            println!("============================================================\n");
        }

        let start = Instant::now();
        let result = ConcurrentProcessor::inspect_images(images, options, max_workers);

        match result {
            Ok(reports) => {
                if config.json_format {
                    match serde_json::to_string_pretty(&reports) {
                        Ok(json) => println!("{}", json),
                        Err(e) => {
                            eprintln!("Error serializing JSON: {}", e);
                            process::exit(1);
                        }
                    }
                } else {
                    for (i, report) in reports.iter().enumerate() {
                        println!(
                            "\n--- [Image {}/{}] ----------------------------------------",
                            i + 1,
                            reports.len()
                        );
                        print_human_report(report, report.stats.duration_ms);
                    }

                    let total_duration = start.elapsed().as_millis() as u64;
                    println!("\n============================================================");
                    println!("  Concurrent Batch Summary:");
                    println!("  Total images processed: {}", reports.len());
                    println!(
                        "  Total elapsed time: {} ms ({:.2} s)",
                        total_duration,
                        total_duration as f64 / 1000.0
                    );
                    println!("============================================================");
                }
            }
            Err(e) => {
                eprintln!("Error during concurrent processing: {}", e);
                process::exit(1);
            }
        }
    } else {
        // Sequential mode for the directory
        if !config.json_format {
            println!("============================================================");
            println!("  Sequential Scan: {} images found", images.len());
            println!("  Directory: {}", directory.display());
            println!("============================================================\n");
        }

        let start = Instant::now();
        let mut reports = Vec::with_capacity(images.len());

        for (i, image_path) in images.iter().enumerate() {
            if !config.json_format {
                println!(
                    "[{}/{}] Inspecting '{}'...",
                    i + 1,
                    images.len(),
                    image_path.display()
                );
            }

            let engine = InspectionEngine::new(options.clone());
            match engine.inspect(image_path) {
                Ok(report) => {
                    if !config.json_format {
                        print_human_report(&report, report.stats.duration_ms);
                        println!();
                    }
                    reports.push(report);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: analysis of '{}' failed: {}",
                        image_path.display(),
                        e
                    );
                }
            }
        }

        if config.json_format {
            match serde_json::to_string_pretty(&reports) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error serializing JSON: {}", e);
                    process::exit(1);
                }
            }
        } else {
            let total_duration = start.elapsed().as_millis() as u64;
            println!("============================================================");
            println!("  Sequential Scan Summary:");
            println!(
                "  Successfully completed images: {}/{}",
                reports.len(),
                images.len()
            );
            println!(
                "  Total time: {} ms ({:.2} s)",
                total_duration,
                total_duration as f64 / 1000.0
            );
            println!("============================================================");
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
    if report.stats.nbd_requests > 0 {
        println!("    NBD Requests:    {}", report.stats.nbd_requests);
    }
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
