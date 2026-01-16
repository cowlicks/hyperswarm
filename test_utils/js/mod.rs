//! Code for running javascript.
//!
//! TODO move out javascript test utilities
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

// TODO move these
// test utils below
#[allow(unused)]
pub const KEYPAIR_JS: &str = "
createKeyPair = require('hyperdht/lib/crypto.js').createKeyPair;
seed = new Uint8Array(32);
seed[0] = 1;
keyPair = createKeyPair(seed)
";

// Add to js preamble (with Config.befeore.push(..)
// to make console log show the line it logs from
const _CONSOLE_LOCATION: &str = r"
ogConsoles = {};
['log', 'warn', 'error'].forEach((methodName) => {

  ogConsoles[methodName] = console[methodName];

  const originalMethod = console[methodName];

  console[methodName] = (...args) => {
    let initiator = 'unknown place';
    try {
      throw new Error();
    } catch (e) {
      if (typeof e.stack === 'string') {
        initiator = e.stack;
        let isFirst = true;
        for (const line of e.stack.split('\n')) {
          const matches = line.match(/^\s+at\s+(.*)/);
          if (matches) {
            if (!isFirst) { // first line - current function
                            // second line - caller (what we are looking for)
              initiator = matches[1];
              break;
            }
            isFirst = false;
          }
        }
      }
    }
    originalMethod.apply(console, [...args, '\n', `  at ${initiator}`]);
  };
});
";

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
