//! A simple target application for DLL injection testing.
//!
//! This application runs indefinitely, allowing a DLL injector to attach
//! and inject a DLL into its process space.

fn main() {
    let arch = if cfg!(target_pointer_width = "64") {
        "64"
    } else {
        "32"
    };

    let mut counter = 0;

    loop {
        println!("  [*][Target][{arch}] application is running... ({counter})");

        std::thread::sleep(std::time::Duration::from_secs(1));

        counter += 1;
        if counter >= 2 {
            println!("  [*][Target][{arch}] application is exiting after 2 seconds.");
            break;
        }
    }
}
