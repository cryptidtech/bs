use crate::subcmds;
use structopt::StructOpt;

/// CLI commands for BetterSign
#[derive(Debug, StructOpt)]
pub enum Command {
    /// Config commands
    #[structopt(name = "config")]
    Config {
        /// Config sub-command
        #[structopt(subcommand)]
        cmd: Option<subcmds::config::Command>,
    },
    /*
    /// Key operations
    #[structopt(name = "key")]
    Key {
        /// Key subcommand
        #[structopt(subcommand)]
        cmd: KeyCommand,
    },
    */
    /// Provenance log operations
    #[structopt(name = "plog")]
    Plog {
        /// Provenance log subcommand
        #[structopt(subcommand)]
        cmd: Box<subcmds::plog::Command>,
    },
}
