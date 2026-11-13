//! One running app per data directory: the first process registers a key
//! with `AppInstance.FindOrRegisterForKey` (Windows App SDK app lifecycle,
//! "App instancing"); a later one hands its activation to that process with
//! `RedirectActivationToAsync` and ends. The registered process hears of it
//! through `Activated`, raised on a background thread, and shows its main
//! window. The key names the data directory, so a development instance with
//! its own `EGRIO_DATA_DIR` runs beside the installed app, each with its own
//! Runtime.

use windows_core::{EventRevoker, Result};

use egrio_ui::backend::UiEvent;

use super::bindings::AppInstance;

/// Ends this process when another holds the key; otherwise keeps the
/// registration whose `Activated` shows the main window.
pub fn claim() -> Result<EventRevoker> {
    let directory = egrio_desktop::app_paths::app_data_dir()
        .map(|directory| directory.display().to_string())
        .unwrap_or_default();
    let key = format!("Egrio|{}", directory.to_lowercase());
    let registered = AppInstance::FindOrRegisterForKey(&key)?;
    if !registered.IsCurrent()? {
        log::info!("Egrio is running already, so this process hands over and ends");
        let arguments = AppInstance::GetCurrent()?.GetActivatedEventArgs()?;
        // Before the UI thread's apartment exists, so the wait blocks
        // nothing that the redirection needs.
        registered.RedirectActivationToAsync(&arguments)?.join()?;
        std::process::exit(0);
    }
    registered.Activated(|_, _| super::on_main(|| super::post(UiEvent::Reopen)))
}
