//! Egrio's own update: a check for a newer release, at launch unless the
//! user turned it off and whenever the settings page asks, and the upgrade,
//! which downloads this platform's installer and hands it to the system.
//! Where the installer replaces the running app, the app quits after.

use egrio_desktop::updates;

use super::Ui;
use crate::backend::Backend;
use crate::messages::{Level, Source};
use crate::msg::{Msg, UpdateMsg};

impl<B: Backend> Ui<B> {
    pub(super) fn update(&mut self, msg: UpdateMsg) {
        let text = self.state.text();
        match msg {
            UpdateMsg::Check { asked } => {
                if std::mem::replace(&mut self.state.update.checking, true) {
                    return;
                }
                self.spawn(async move {
                    Msg::Update(UpdateMsg::Checked {
                        asked,
                        result: updates::newer_release().await,
                    })
                });
            }
            UpdateMsg::Checked { asked, result } => {
                let update = &mut self.state.update;
                update.checking = false;
                match result {
                    Ok(Some(release)) => {
                        update.current = false;
                        update.failed = false;
                        let version = release.version.clone();
                        update.available = Some(release);
                        // An answer the user asked for shows in place.
                        if !asked {
                            self.note(
                                Level::Info,
                                Source::Update,
                                text.new_version(&version),
                                None,
                            );
                        }
                    }
                    Ok(None) => {
                        update.available = None;
                        update.current = true;
                        update.failed = false;
                    }
                    // A check at launch that finds no network says nothing.
                    Err(error) if !asked => {
                        log::info!("the update check at launch failed: {error}")
                    }
                    Err(error) => {
                        update.failed = true;
                        self.note(
                            Level::Error,
                            Source::Update,
                            text.update_check_failed(),
                            Some(error),
                        );
                    }
                }
            }
            UpdateMsg::Upgrade => {
                let update = &mut self.state.update;
                let Some(release) = update.available.clone() else {
                    return;
                };
                // Without an installer for this system, the release's page.
                if release.installer.is_none() {
                    if let Err(error) = self.backend.open_url(&release.page) {
                        self.note(
                            Level::Error,
                            Source::Update,
                            text.upgrade_failed(),
                            Some(error),
                        );
                    }
                    return;
                }
                if std::mem::replace(&mut update.downloading, true) {
                    return;
                }
                self.spawn(async move {
                    Msg::Update(UpdateMsg::Downloaded(
                        updates::download_installer(&release).await,
                    ))
                });
            }
            UpdateMsg::Downloaded(result) => {
                self.state.update.downloading = false;
                match result.and_then(|path| self.backend.open_installer(&path)) {
                    Ok(()) if updates::INSTALLER_REPLACES_APP => self.dispatch(Msg::Quit),
                    // The system's installer shows itself.
                    Ok(()) => {}
                    Err(error) => self.note(
                        Level::Error,
                        Source::Update,
                        text.upgrade_failed(),
                        Some(error),
                    ),
                }
            }
        }
    }
}
