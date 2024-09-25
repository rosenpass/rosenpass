use clap::CommandFactory;
use std::env;
use std::fs::create_dir_all;
use std::path::Path;
use std::path::PathBuf;

mod cli {
    include!("src/cli.rs");
}

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=./");
    let dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let cmd = cli::Cli::command();
    let base_dir = PathBuf::from(dir);

    let man_dir = Path::join(&base_dir, "man");
    create_dir_all(&man_dir)?;
    clap_mangen::generate_to(cmd.clone(), &man_dir)?;

    println!("cargo:rustc-env=TARGET={}", env::var("TARGET").unwrap());
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    println!(
        "cargo:rustc-env=ROSENPASS_MAN={}/rosenpass.1",
        man_dir.display()
    );

    Ok(())
}
