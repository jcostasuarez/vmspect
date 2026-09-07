use std::path::Path;
use vmspect::{inspect_with_progress, InspectionProgressEvent, Options};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let disk_path = if args.len() > 1 {
        Path::new(&args[1])
    } else {
        println!("Usage: cargo run --example basic_inspection -- <path_to_disk_image>");
        println!("Example: cargo run --example basic_inspection -- disk.vmdk");
        return Ok(());
    };

    let options = Options::default();

    println!("Starting inspection of '{}'...", disk_path.display());
    let report = inspect_with_progress(disk_path, &options, |p: InspectionProgressEvent| {
        println!(
            "[{:>3}%] {}{}",
            p.percentage,
            p.stage,
            p.detail.map(|d| format!(" - {}", d)).unwrap_or_default()
        );
    })?;

    println!("\n=== INSPECTION REPORT ===");
    println!(
        "Format: {} ({})",
        report.image.format,
        report.image.hypervisor.name()
    );
    println!("Partition scheme: {:?}", report.scheme);
    println!(
        "Operating system: {} {:?}",
        report.operating_system.icon(),
        report.operating_system
    );
    println!("OS details: {}", report.guest_info.formatted_os_string());
    if let Some(ref tools) = report.guest_info.guest_tools {
        if tools.present {
            println!(
                "Guest tools: {} (version: {})",
                tools.kind,
                tools.version.as_deref().unwrap_or("N/A")
            );
        }
    }
    println!("Partitions found: {}", report.partitions.len());
    for p in &report.partitions {
        println!(
            "  - #{} [{}] {} (start: 0x{:X}, size: {} bytes)",
            p.index,
            p.kind,
            p.file_system.name(),
            p.start,
            p.size
        );
    }
    println!("Programs identified: {}", report.installed_programs.len());
    for prog in report.installed_programs.iter().take(15) {
        println!(
            "  * {} (version: {}, publisher: {})",
            prog.name,
            prog.version.as_deref().unwrap_or("N/A"),
            prog.publisher.as_deref().unwrap_or("N/A")
        );
    }

    Ok(())
}
