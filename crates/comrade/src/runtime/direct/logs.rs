use comrade_reference::Log;

pub(crate) struct Logger;

impl Log for Logger {
    fn log(&self, msg: &str) {
        tracing::info!("{}", msg);
    }
}
