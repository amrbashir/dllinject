//! Example of using the dllinject crate to inject a DLL into a target process
//! for both 32-bit and 64-bit architectures.
//!
//! This example builds a sample DLL for both architectures and injects it into a
//! running process.
//!
//! Run `cargo run --example sample`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use windows_sys::Win32::System::Threading::*;

fn encode_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Get the path to the built DLL for the specified architecture
fn dll_paths(sample_dll_dir: &Path) -> (PathBuf, PathBuf) {
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .or_else(|_| std::env::var("CARGO_BUILD_TARGET_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| sample_dll_dir.join("target"));

    let dll_32 = target_dir
        .join("i686-pc-windows-msvc")
        .join("debug")
        .join("sample_dll.dll");

    let dll_64 = target_dir
        .join("x86_64-pc-windows-msvc")
        .join("debug")
        .join("sample_dll.dll");

    (dll_32, dll_64)
}

/// Build the sample DLL for both 32-bit and 64-bit architectures
fn build_dual_dll(manifest_dir: &Path) -> (PathBuf, PathBuf) {
    let sample_dll_dir = manifest_dir.join("examples").join("sample_dll");

    let status = Command::new("cargo")
        .args(&["build", "--target", "i686-pc-windows-msvc"])
        .current_dir(&sample_dll_dir)
        .stdout(Stdio::piped())
        .status()
        .expect("Failed to build 32-bit DLL");
    if !status.success() {
        panic!("Building 32-bit DLL failed");
    }

    let status = Command::new("cargo")
        .args(&["build", "--target", "x86_64-pc-windows-msvc"])
        .current_dir(&sample_dll_dir)
        .status()
        .expect("Failed to build 64-bit DLL");
    if !status.success() {
        panic!("Building 64-bit DLL failed");
    }

    dll_paths(&sample_dll_dir)
}

fn run_target_and_inject(
    manifest_dir: &Path,
    target: &str,
    dll32_path: &[u16],
    dll64_path: &[u16],
) {
    let target_arch = match target {
        "x86_64-pc-windows-msvc" => "64",
        "i686-pc-windows-msvc" => "32",
        _ => panic!("Unsupported target architecture"),
    };

    let current_arch = if cfg!(target_pointer_width = "64") {
        "64"
    } else {
        "32"
    };

    println!("[*][HOST] Injecting from {current_arch}-bit into {target_arch}-bit process");

    // Determine the target directory
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .or_else(|_| std::env::var("CARGO_BUILD_TARGET_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("target"));

    println!("[*][HOST] Building target executable {target_arch}-bit");
    let status = Command::new("cargo")
        .args(&["build", "--example", "target", "--target", target])
        .current_dir(&manifest_dir)
        .status()
        .expect("Failed to build target process");
    if !status.success() {
        panic!("Building target process failed");
    }

    let target_exe = target_dir
        .join(target)
        .join("debug")
        .join("examples")
        .join("target.exe");

    println!("[*][HOST] Starting target process");
    let mut target_process = Command::new(&target_exe)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::inherit())
        .spawn()
        .expect("Failed to start target process");

    // Sleep for a moment (give the target process time to print some output)
    // to see the effect of the injection
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Open the target process for injection
    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, target_process.id()) };
    if process.is_null() {
        panic!("Failed to open process");
    }

    let dll_32 = dll32_path.as_ptr();
    let dll_64 = dll64_path.as_ptr();

    let res = unsafe { dllinject::InjectDll(process as _, dll_32, dll_64) };
    if res != 0 {
        panic!("DLL injection failed with error code: {}", res);
    }

    let status = target_process
        .wait()
        .expect("Failed to wait on target process");
    if !status.success() {
        panic!("Target process exited with failure");
    }

    println!(" [*][HOST] DLL injection succeeded");
}

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = Path::new(&manifest_dir);

    // Build the sample DLL for both architectures
    let (dll_32_path, dll_64_path) = build_dual_dll(&manifest_dir);
    let dll32_path = encode_wide_null(&dll_32_path.to_string_lossy());
    let dll64_path = encode_wide_null(&dll_64_path.to_string_lossy());

    // Run the target process and inject the DLLs for x86_64
    run_target_and_inject(
        &manifest_dir,
        "x86_64-pc-windows-msvc",
        &dll32_path,
        &dll64_path,
    );

    // Run the target process and inject the DLLs for i686
    run_target_and_inject(
        &manifest_dir,
        "i686-pc-windows-msvc",
        &dll32_path,
        &dll64_path,
    );
}
