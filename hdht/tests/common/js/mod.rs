use rusty_nodejs_repl::{Config, Repl};

use super::{_run_make_from_with, git_root, join_paths};
use std::path::PathBuf;

pub static REL_PATH_TO_NODE_MODULES: &str = "./hdht/tests/common/js/node_modules";
pub static REL_PATH_TO_JS_DIR: &str = "./hdht/tests/common/js";

pub fn require_js_data() -> Result<(), Box<dyn std::error::Error>> {
    let _ = _run_make_from_with(REL_PATH_TO_JS_DIR, "node_modules")?;
    Ok(())
}

pub fn path_to_node_modules() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let p = join_paths!(git_root()?, &REL_PATH_TO_NODE_MODULES);
    Ok(p.into())
}

pub const KEYPAIR_JS: &str = "
createKeyPair = require('hyperdht/lib/crypto.js').createKeyPair;
seed = new Uint8Array(32);
seed[0] = 1;
keyPair = createKeyPair(seed)
";

pub async fn make_repl() -> Repl {
    require_js_data().unwrap();

    let mut conf = Config::build().unwrap();
    conf.before.push(
        "
stringify = JSON.stringify;
write = process.stdout.write.bind(process.stdout);
writeJson = x => write(stringify(x))
"
        .into(),
    );
    conf.path_to_node_modules = Some(path_to_node_modules().unwrap().display().to_string());
    conf.start().await.unwrap()
}
