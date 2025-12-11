use std::net::SocketAddr;

use crate::common::js::make_repl;

use super::Result;
use rusty_nodejs_repl::Repl;
#[derive()]
pub struct Testnet {
    pub repl: Repl,
}

impl Testnet {
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

    /// Get the address of a node from an existing testnet in js
    /// NB: `testnet` must exist in the js context already
    pub async fn get_node_i_address(&mut self, node_index: usize) -> Result<SocketAddr> {
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
    /// Create a target/topic. whith the argument `topic` written to to the beggining of the buffer,
    /// and padded with zeros. The variable in js is named "topic"
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
}
