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
    match run_cli(buf_reader).await {
        Ok(result) => println!("{}", serde_json::to_string(&result).unwrap()),
        Err(e) => {
            return_error(&e.to_string());
        }
    }
}
