pub mod cli;
pub mod constants;
pub mod device;
pub mod errors;
pub mod ledger;
pub mod path;
pub mod types;
pub mod utils;

use crate::cli::{return_error, run_cli, set_panic_hook};
use std::io;
use std::io::stdin;

#[tokio::main]
pub async fn main() {
    cli::check_subcommand();

    let reader = stdin();
    set_panic_hook();
    let buf_reader = io::BufReader::new(reader);
    let ledger_conn = ledger::get_connection().await.unwrap();

    match run_cli(buf_reader, ledger_conn).await {
        Ok(result) => println!("{}", serde_json::to_string(&result).unwrap()),
        Err((e, id)) => {
            return_error(&e.to_string(), id);
        }
    }
}
