fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV");
    let profile = std::env::var("PROFILE");
    if target_env.as_deref() == Ok("msvc") && profile.as_deref() == Ok("release") {
        // Use a deterministic PE timestamp and a portable CodeView PDB reference.
        println!("cargo::rustc-link-arg-bin=nyra-fw=/Brepro");
        println!("cargo::rustc-link-arg-bin=nyra-fw=/PDBALTPATH:%_PDB%");
    }
}
