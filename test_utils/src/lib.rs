//! Test utilities for the hyperswarm workspace.
//!
//! Provides common testing infrastructure including:
//! - JavaScript REPL integration via rusty_nodejs_repl
//! - Testnet setup for hyperdht interop testing
//! - Common utilities for running commands and managing temp files

// Re-export rusty_nodejs_repl for use by test code
pub use rusty_nodejs_repl;
pub use rusty_nodejs_repl::Repl;

use std::{
    collections::BTreeSet,
    fs::File,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Output},
    sync::OnceLock,
};

use async_process::Stdio;
use rusty_nodejs_repl::Config;
use tempfile::TempDir;
use tracing_subscriber::EnvFilter;

mod js;
pub type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

/// Relative path from git root to the JS test directory
pub static REL_PATH_TO_JS_DIR: &str = "./hdht/tests/common/js";
/// Relative path from git root to node_modules
pub static REL_PATH_TO_NODE_MODULES: &str = "./hdht/tests/common/js/node_modules";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Problem in tests: {0}")]
    TestError(String),
}

/// Join path components into a string
#[macro_export]
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
        $crate::join_paths!(p.display().to_string(), $($tail)*)
    }};
}

/// Run a shell command and return its output
#[allow(dead_code)]
pub fn run_command(cmd: &str) -> Result<Output> {
    check_cmd_output(Command::new("sh").arg("-c").arg(cmd).output()?)
}

/// Get the git repository root directory
pub fn git_root() -> Result<String> {
    let x = Command::new("sh")
        .arg("-c")
        .arg("git rev-parse --show-toplevel")
        .output()?;
    Ok(String::from_utf8(x.stdout)?.trim().to_string())
}

/// Run a script relative to git root
#[allow(dead_code)]
pub fn run_script_relative_to_git_root(script: &str) -> Result<Output> {
    Ok(Command::new("sh")
        .arg("-c")
        .arg(format!("cd {} && {}", git_root()?, script))
        .output()?)
}

/// Run code in a temporary directory with an async process
#[allow(dead_code)]
pub fn run_code(
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

/// Run make from a directory with an argument
#[allow(dead_code)]
pub fn run_make_from_with(dir: &str, arg: &str) -> Result<Output> {
    let path = join_paths!(git_root()?, dir);
    let cmd = format!("cd {path} && flock make.lock make {arg} && rm -f make.lock ");
    let cmd_res = Command::new("sh").arg("-c").arg(cmd).output()?;
    let out = check_cmd_output(cmd_res)?;
    Ok(out)
}

/// Check that a command succeeded
pub fn check_cmd_output(out: Output) -> Result<Output> {
    if out.status.code() != Some(0) {
        return Err(Box::new(Error::TestError(format!(
            "command output status was not zero. Got:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ))));
    }
    Ok(out)
}

/// Initialize tracing/logging for tests
#[allow(unused)]
pub fn init_logging() {
    use tracing_subscriber::fmt::format::FmtSpan;
    static START_LOGS: OnceLock<()> = OnceLock::new();
    START_LOGS.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_target(true)
            .with_line_number(true)
            .with_file(true)
            .with_env_filter(EnvFilter::from_default_env())
            .without_time()
            .init();
    });
}

// ============================================================================
// JavaScript REPL utilities
// ============================================================================

/// Ensure JS dependencies are installed
pub fn require_js_data() -> Result<()> {
    let _ = run_make_from_with(REL_PATH_TO_JS_DIR, "node_modules")?;
    Ok(())
}

/// Get the path to node_modules
pub fn path_to_node_modules() -> Result<PathBuf> {
    let p = join_paths!(git_root()?, &REL_PATH_TO_NODE_MODULES);
    Ok(p.into())
}

/// JavaScript for creating a keypair
#[allow(unused)]
pub const KEYPAIR_JS: &str = "
createKeyPair = require('hyperdht/lib/crypto.js').createKeyPair;
seed = new Uint8Array(32);
seed[0] = 1;
keyPair = createKeyPair(seed)
";

/// Create a new JavaScript REPL with standard configuration
pub async fn make_repl() -> Repl {
    require_js_data().unwrap();

    let mut conf = Config::build().unwrap();
    conf.before.push(
        "
sleep = (ms = 10) => new Promise(resolve => setTimeout(resolve, ms))

deferred = () => {
  const o = {};
  const p = new Promise((resolve_og, reject) => {
      const resolve = (...x) => {
        p.ready = true;
        resolve_og(...x);
      }
      Object.assign(o, {resolve, reject, ready: false});
  });
  return Object.assign(p, o);
}
stringify = JSON.stringify;
write = process.stdout.write.bind(process.stdout);
writeJson = x => write(stringify(x))
outputJson = x => output(stringify(x))
"
        .into(),
    );
    conf.path_to_node_modules = Some(path_to_node_modules().unwrap().display().to_string());
    conf.start().await.unwrap()
}

// ============================================================================
// Testnet - HyperDHT test network via JavaScript
// ============================================================================

/// A test network running in JavaScript via the REPL
pub struct Testnet {
    pub repl: Repl,
}

impl Testnet {
    /// Create a new testnet
    pub async fn new() -> Result<Self> {
        let mut repl = make_repl().await;
        let r = repl
            .run_tcp(
                "
createTestnet = require('hyperdht/testnet.js');
testnet = await createTestnet();
",
            )
            .await;
        repl.print().await?;
        r?;
        Ok(Self { repl })
    }

    /// Get the bootstrap address (node at index 1)
    pub async fn bootstrap_addr(&mut self) -> Result<SocketAddr> {
        self.get_node_address(1).await
    }

    /// Get the address of a node by index
    /// Alias: `get_node_i_address`
    pub async fn get_node_address(&mut self, node_index: usize) -> Result<SocketAddr> {
        Ok(self
            .repl
            .json_run_tcp::<String, _>(format!(
                "
bs_node = testnet.nodes[{node_index}]
outputJson(`${{bs_node.host}}:${{bs_node.port}}`)
"
            ))
            .await?
            .parse()?)
    }

    /// Alias for `get_node_address` for backward compatibility
    pub async fn get_node_i_address(&mut self, node_index: usize) -> Result<SocketAddr> {
        self.get_node_address(node_index).await
    }

    /// Create a topic buffer padded with zeros.
    /// The variable in JS is named "topic"
    pub async fn make_topic(&mut self, topic: &str) -> Result<[u8; 32]> {
        Ok(self
            .repl
            .json_run_tcp(format!(
                "
const b4a = require('b4a')
topic = b4a.alloc(32);
topic.write('{topic}', 0);
outputJson([...topic])
"
            ))
            .await?)
    }

    /// Get public keys from a lookup query
    pub async fn get_pub_keys_for_lookup(&mut self) -> Result<Vec<Vec<u8>>> {
        let node_index = "testnet.nodes.length - 1";
        let found_pk_js: Vec<Vec<u8>> = self
            .repl
            .json_run_tcp(format!(
                "
lookup_node = testnet.nodes[{node_index}];
query = await lookup_node.lookup(topic);
let out = [];
for await (const x of query) {{
    out.push([...x.peers[0].publicKey])
}}
outputJson(out)
",
            ))
            .await?;
        // dedupe
        let set: BTreeSet<Vec<u8>> = found_pk_js.into_iter().collect();
        Ok(set.into_iter().collect())
    }
}
