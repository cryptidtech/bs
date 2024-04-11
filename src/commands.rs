// SPDX-License-Identifier: FSL-1.1
use crate::Error;

/// implementor state can be reached from `S`
pub trait TransitionFrom<S> {}
/// implementor is a terminal state
pub trait Terminal {}

/// The possible return values from the State::next method
pub enum Transition<C, V> {
    /// Transition to the next state
    Next(Box<dyn State<C, V>>),
    /// A terminal state has been reached
    Complete(Box<dyn State<C, V>>),
}

impl<C, V> Transition<C, V> {
    /// function to create the next state and enforce defined state transitions at compile time
    pub fn next<S, N>(_s: S, n: N) -> Transition<C, V>
    where
        S: State<C, V>,
        N: State<C, V> + TransitionFrom<S>,
    {
        Transition::Next(Box::new(n))
    }

    /// function to return a complete transition while enforcing transition rules
    pub fn complete<S>(s: S) -> Transition<C, V>
    where
        S: State<C, V> + Terminal,
    {
        Transition::Complete(Box::new(s))
    }
}

#[async_trait::async_trait]
/// A generic trait representing a state in a state graph
pub trait State<C, V>: Send + Sync + 'static {
    /// Run the state handler and return the next state
    async fn next(self: Box<Self>, context: &mut C) -> Result<Transition<C, V>, Error>;

    /// Get the status of this process
    async fn status(&self, context: &mut C) -> Result<String, Error>;

    /// Get the result of this state if it is a terminal one
    async fn result(&self, context: &mut C) -> Result<V, Error>;
}

/// Runs a state graph to completion
pub async fn run_to_completion<C, V>(
    state: impl State<C, V>,
    context: &mut C,
) -> Result<V, Error> 
where
    C: Send + Sync + 'static,
    V: Send + Sync + 'static
{
    let mut state: Box<dyn State<C, V>> = Box::new(state);

    loop {
        // get the status string
        let _status = state.status(context).await?;

        // TODO: send the status to the status line
        
        let transition = { state.next(context).await? };

        state = match transition {
            Transition::Next(s) => s,
            Transition::Complete(s) => return s.result(context).await
        }
    }
}

/// Used to define the states in a state graph like so: `states!(Foo, Bar, Baz, Failure)` The terminal states
/// must have brackets around them like so: `states!(Foo, Bar, [Baz], [Failure])`
macro_rules! states {
    ([$s:ident]) => {
        struct $s; impl Terminal for $s {}
    };
    ($s:ident, [$t:ident]) => {
        struct $s; pub struct $t; impl Terminal for $t {}
    };
    ([$s:ident], [$t:ident]) => {
        struct $s; impl Terminal for $s {} struct $t; impl Terminal for $t {}
    };
    ($s:ident, $($t:tt)*) => {
        struct $s; states!($($t)*);
    };
    ([$s:ident], $($t:tt)*) => {
        struct $s; impl Terminal for $s {} states!($($t)*);
    }
}

/// Used to define valid state transitions. Typically the happy path is specified first and then
/// any additional paths afterwards. Here's an example:
/// ```
/// // the happy path
/// path!(Foo -> Bar -> Baz);
///
/// // also a path that skips Bar
/// path!(Foo -> Baz);
///
/// // also Bar can loop
/// path!(Bar -> Bar);
/// ```
macro_rules! path {
    ($f:ident -> $t:ident) => {
        impl TransitionFrom<$f> for $t {}
    };
    ($f:ident -> $t:ident -> $($r:tt)*) => {
        impl TransitionFrom<$f> for $t {}
        path!($t -> $($r)*);
    }
}

/// Used to define multiple paths from the first state to multiple other states. This is typically
/// used after the happy path is defined with `path!()` to define alternate routes like so:
/// ```
/// // the happy path 
/// path!(Foo -> Bar -> Baz -> Qux);
///
/// // alternate paths. it's also legal to go Foo -> Bar -> Qux and Foo -> Qux
/// paths!(Foo -> Baz, Qux);
///
/// ```
macro_rules! paths {
    ($f:ident -> $($t:ident),+ $(,)?) => {
        $(path!($f -> $t);)+
    }
}

/// Used to define the failure state—which is usually a terminal state—and all of the states that
/// can transition to it like so:
/// ```
/// failures!(Foo, Bar, Baz -> Failure);
/// ```
macro_rules! failures {
    ($($s:ident),+ $(,)? -> $f:ident) => {
        $(path!($s -> $f);)+
    };
}

/// Wasm loader state machine
pub mod wasm;

/// key generator state machine
pub mod keygen;
