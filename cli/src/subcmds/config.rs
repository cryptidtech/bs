// SPDX-License-Identifier: FSL-1.1

/// Config command
pub mod command;
pub use command::Command;

use crate::{Config, Error};

/// processes plog subcommands
pub async fn go(cmd: Option<Command>, config: &Config) -> Result<(), Error> {
    let cmd = cmd.unwrap_or_default();

    match cmd {
        Command::Print => {
            println!("{}", toml::to_string(config)?);
        }
    }

    Ok(())
}
