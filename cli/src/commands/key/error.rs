// SPDX-License-Identifier: FSL-1.1

/// SshAgent error
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// multikey error
    #[error(transparent)]
    Multikey(#[from] multikey::Error),
    /// missing codec
    #[error("no key codec collected from user")]
    NoCodec,
    /// missing comment
    #[error("no comment collected from user")]
    NoComment,
    /// missing answer
    #[error("no answer collected from user")]
    NoAnswer,
    /// we're in an error state but no error was specified
    #[error("error state without error specified")]
    NoError,
    /// error to return when result is called on a non-terminal state
    #[error("error calling result on non-terminal state")]
    NoResult,
    /// something went wrong and you're going to have a hell of a time debugging it
    #[error("key generation failed")]
    KeyGenerationFailed,
}
