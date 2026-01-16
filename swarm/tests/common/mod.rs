//! Test utilities for hyperswarm

use std::net::SocketAddr;
use std::path::PathBuf;
use rusty_nodejs_repl::{Config, Repl};

pub type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

pub struct Testnet {
    pub repl: Repl,
}

impl Testnet {
    pub async fn new() -> Result<Self> {
        let mut repl = make_repl().await;
        repl.run_tcp(
            "
createTestnet = require('hyperdht/testnet.js');
testnet = await createTestnet();
",
        )
        .await?;
        repl.print().await?;
        Ok(Self { repl })
    }

    pub async fn bootstrap_addr(&mut self) -> Result<SocketAddr> {
        Ok(self
            .repl
            .json_run_tcp::<String, _>(
                "
bs_node = testnet.nodes[1]
outputJson(`${bs_node.host}:${bs_node.port}`)
",
            )
            .await?
            .parse()?)
    }
}

fn path_to_node_modules() -> PathBuf {
    // Go from swarm/tests/common to hdht/tests/common/js/node_modules
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../hdht/tests/common/js/node_modules")
}

async fn make_repl() -> Repl {
    let mut conf = Config::build().unwrap();
    conf.before.push(
        "
sleep = (ms = 10) => new Promise(resolve => setTimeout(resolve, ms))
stringify = JSON.stringify;
write = process.stdout.write.bind(process.stdout);
writeJson = x => write(stringify(x))
outputJson = x => output(stringify(x))
"
        .into(),
    );
    conf.path_to_node_modules = Some(path_to_node_modules().display().to_string());
    conf.start().await.unwrap()
}
