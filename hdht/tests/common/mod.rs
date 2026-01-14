//! code related to testing across languages: ways to invoke `make`, wrappers aroundn running
//! processes, functions to create and use a tempdir, etc.
//!
//! TODO separate out test utils
use std::{
    fs::File,
    io::Write,
    process::{Command, Output},
    sync::OnceLock,
};

use async_process::Stdio;
use tempfile::TempDir;

pub mod js;
pub mod setup;

pub type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

pub static _PATH_TO_DATA_DIR: &str = "tests/common/js/data";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Problem in tests: {0}")]
    TestError(String),
}

macro_rules! join_paths {
    ( $path:expr$(,)?) => {
        $path
    };
    ( $p1:expr,  $p2:expr) => {{
        let p = std::path::Path::new(&*$p1).join($p2);
        p.display().to_string()
    }};
    ( $p1:expr,  $p2:expr, $($tail:tt)+) => {{
        let p = std::path::Path::new($p1).join($p2);
        join_paths!(p.display().to_string(), $($tail)*)
    }};
}
pub(crate) use join_paths;
use tracing_subscriber::EnvFilter;

#[allow(dead_code)]
pub fn run_command(cmd: &str) -> Result<Output> {
    check_cmd_output(Command::new("sh").arg("-c").arg(cmd).output()?)
}
pub fn git_root() -> Result<String> {
    let x = Command::new("sh")
        .arg("-c")
        .arg("git rev-parse --show-toplevel")
        .output()?;
    Ok(String::from_utf8(x.stdout)?.trim().to_string())
}

pub fn _get_data_dir() -> Result<String> {
    Ok(join_paths!(git_root()?, &_PATH_TO_DATA_DIR))
}

pub fn _run_script_relative_to_git_root(script: &str) -> Result<Output> {
    Ok(Command::new("sh")
        .arg("-c")
        .arg(format!("cd {} && {}", git_root()?, script))
        .output()?)
}

pub fn _run_code(
    code_string: &str,
    script_file_name: &str,
    build_command: impl FnOnce(&str, &str) -> String,
    copy_dirs: Vec<String>,
) -> Result<(TempDir, async_process::Child)> {
    let working_dir = tempfile::tempdir()?;

    let script_path = working_dir.path().join(script_file_name);
    let script_file = File::create(&script_path)?;

    write!(&script_file, "{}", &code_string)?;

    let working_dir_path = working_dir.path().display().to_string();
    // copy dirs into working dir
    for dir in copy_dirs {
        let dir_cp_cmd = Command::new("cp")
            .arg("-r")
            .arg(&dir)
            .arg(&working_dir_path)
            .output()?;
        if dir_cp_cmd.status.code() != Some(0) {
            return Err(Box::new(Error::TestError(format!(
                "failed to copy dir [{dir}] to [{working_dir_path}] got stderr: {}",
                String::from_utf8_lossy(&dir_cp_cmd.stderr),
            ))));
        }
    }
    let script_path_str = script_path.display().to_string();
    let cmd = build_command(&working_dir_path, &script_path_str);
    Ok((
        working_dir,
        async_process::Command::new("sh")
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("-c")
            .arg(cmd)
            .spawn()?,
    ))
}

pub fn _run_make_from_with(dir: &str, arg: &str) -> Result<Output> {
    let path = join_paths!(git_root()?, dir);
    let cmd = format!("cd {path} && flock make.lock make {arg} && rm -f make.lock ");
    let cmd_res = Command::new("sh").arg("-c").arg(cmd).output()?;
    let out = check_cmd_output(cmd_res)?;
    Ok(out)
}

pub fn check_cmd_output(out: Output) -> Result<Output> {
    if out.status.code() != Some(0) {
        return Err(Box::new(Error::TestError(format!(
            "comand output status was not zero. Got:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ))));
    }
    Ok(out)
}

#[allow(unused)]
pub fn log() {
    use tracing_subscriber::fmt::format::FmtSpan;
    static START_LOGS: OnceLock<()> = OnceLock::new();
    START_LOGS.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_target(true)
            .with_line_number(true)
            // print when instrumented funtion enters
            //.with_span_events(FmtSpan::ENTER | FmtSpan::EXIT)
            .with_file(true)
            .with_env_filter(EnvFilter::from_default_env()) // Reads `RUST_LOG` environment variable
            .without_time()
            .init();
    });
}
