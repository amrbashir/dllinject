fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = std::path::PathBuf::from(manifest_dir);

    let target = std::env::var("TARGET").unwrap();

    let cpp_path = manifest_dir.join("cpp");
    println!("cargo:rerun-if-changed={}", cpp_path.display());

    let libraries_path = cpp_path.join("libraries");

    let mut build = cc::Build::new();
    build.file(cpp_path.join("main.cpp"));
    build.include(cpp_path.as_path());
    build.include(libraries_path.as_path());
    build.include(libraries_path.join("wil"));
    build.define("UNICODE", Some("1"));

    // Add wow64ext.cpp only for 32-bit Windows target
    if target.as_str() == "i686-pc-windows-msvc" {
        build.include(libraries_path.join("wow64ext"));
        build.file(libraries_path.join("wow64ext/wow64ext.cpp"));
    }

    build.compile("dllinject-cpp");
}
