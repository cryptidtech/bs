use crate::cond_send::CondSync;

use super::value::Value;
use std::fmt::Debug;

/// Trait Pairable is: [Pairs], [Send], [Sync], [Clone], [Debug]
pub trait Pairable: Pairs + Send + Sync + 'static {}
impl<P: Pairs + Send + Sync + 'static> Pairable for P {}

/// Trait to a key-value storage mechanism
pub trait Pairs: CondSync + Debug {
    /// get a value associated with the key
    fn get(&self, key: &str) -> Option<Value>;

    /// add a key-value pair to the storage, returns the previous value if the
    /// key already exists in the data structure
    fn put(&mut self, key: &str, value: &Value) -> Option<Value>;
}
