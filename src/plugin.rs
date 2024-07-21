use nu_plugin::{Plugin, PluginCommand};

use crate::command::Cer;

pub struct CerPlugin;

impl Plugin for CerPlugin {
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![Box::new(Cer)]
    }
}
