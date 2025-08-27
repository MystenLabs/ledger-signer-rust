pub mod cli;
pub mod constants;
pub mod device;
pub mod errors;
pub mod ledger;
pub mod path;
pub mod types;

use crate::cli::{return_error, run_cli, set_panic_hook};
use std::io;
use std::io::stdin;

#[tokio::main]
pub async fn main() {
    cli::check_subcommand();

    let reader = stdin();
    // TODO id should come from jsonrpc request
    set_panic_hook(0);
    let buf_reader = io::BufReader::new(reader);

    match run_cli(buf_reader, ledger::ConnectionType::Auto).await {
        Ok(result) => println!("{}", serde_json::to_string(&result).unwrap()),
        Err((e, id)) => {
            return_error(&e.to_string(), id);
        }
    }
}
