// SPDX-License-Identifier: FSL-1.1
use structopt::StructOpt;

/// Plog commands
#[derive(Debug, Default, StructOpt)]
pub enum Command {
    /// Print command
    #[default]
    #[structopt(name = "open")]
    Print,
}
