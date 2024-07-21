mod certificate;
mod command;
mod error;
mod plugin;

use nu_plugin::{serve_plugin, JsonSerializer};
use plugin::CerPlugin;

// cargo build --release
// mkdir ($env.APPDATA | path join "nushell\\plugins")
// cp target\release\nu_plugin_cer.exe ($env.APPDATA | path join "nushell\\plugins")
// plugin add ($env.APPDATA | path join "nushell\\plugins\\nu_plugin_cer.exe")
// plugin use cer

fn main() {
    serve_plugin(&CerPlugin, JsonSerializer)
}
