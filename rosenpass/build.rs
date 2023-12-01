use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// Custom error type for the rendering process
#[derive(Error, Debug)]
enum RenderError {
    #[error("{0} returned an error")]
    CompilationError(String),
    #[error("Error converting bytes to UTF-8: {0}")]
    Utf8ConversionError(#[from] std::string::FromUtf8Error),
}

/// Invokes a troff compiler to compile a manual page
fn render_man(compiler: &str, man: &str) -> Result<String, RenderError> {
    let out = Command::new(compiler).args(["-Tascii", man]).output()?;

    if !out.status.success() {
        return Err(RenderError::CompilationError(compiler.to_string()));
    }

    Ok(String::from_utf8(out.stdout)?)
}

/// Generates the manual page
fn generate_man() -> String {
    // This function is purposely stupid and redundant

    if let Ok(man) = render_man("mandoc", "./doc/rosenpass.1") {
        return man;
    }

    if let Ok(man) = render_man("groff", "./doc/rosenpass.1") {
        return man;
    }

    // TODO: Link to online manual here
    "Cannot render manual page\n".into()
}

fn man() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let man = generate_man();
    let path = out_dir.join("rosenpass.1.ascii");

    let mut file = File::create(&path).expect("Error creating file");
    file.write_all(man.as_bytes()).expect("Error writing to file");

    println!("cargo:rustc-env=ROSENPASS_MAN={}", path.display());
}

fn main() {
    // For now, rerun the build script on every time, as the build script
    // is not very expensive right now.
    println!("cargo:rerun-if-changed=./");
    env_logger::init(); // Initialize the logger
    man();
}