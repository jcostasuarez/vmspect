use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use vmspect::{InspectionEngine, Options};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let images = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if images.is_empty() {
        println!("Usage: cargo run --example batch_polling -- <disk_image> [disk_image ...]");
        return Ok(());
    }

    let engine = Arc::new(InspectionEngine::new(Options::default()));
    let progress = engine.progress();

    let worker_engine = Arc::clone(&engine);
    let handle = std::thread::spawn(move || worker_engine.inspect_batch(images, 2));

    loop {
        let snapshot = progress.snapshot();
        let percentage = progress.completion_percentage();
        let completed = progress.completed_tasks();
        let total = progress.total_tasks();

        println!("[{percentage:>5.1}%] {completed}/{total}");
        if handle.is_finished()
            || (snapshot.total_tasks > 0 && snapshot.completed_tasks >= snapshot.total_tasks)
        {
            break;
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    let result = handle.join().expect("worker thread panicked")?;
    let snapshot = progress.snapshot();
    println!(
        "Finished at {}%: {} reports, {} image errors",
        snapshot.percentage,
        result.reports.len(),
        result.errors.len()
    );
    Ok(())
}
