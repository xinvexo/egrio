//! The two independent ways Egrio takes over traffic. Any combination is
//! valid: with both on, applications that honor the system proxy reach the
//! Core listener through it and everything else is captured by TUN. There is
//! no third mode; a platform implements each layer as Runtime capabilities.

use serde::{Deserialize, Serialize};

/// One capture layer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureLayer {
    SystemProxy,
    Tun,
}

/// Which capture layers are on.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureLayers {
    pub system_proxy: bool,
    pub tun: bool,
}

impl CaptureLayers {
    pub const NONE: Self = Self {
        system_proxy: false,
        tun: false,
    };

    #[must_use]
    pub const fn any(self) -> bool {
        self.system_proxy || self.tun
    }

    #[must_use]
    pub const fn get(self, layer: CaptureLayer) -> bool {
        match layer {
            CaptureLayer::SystemProxy => self.system_proxy,
            CaptureLayer::Tun => self.tun,
        }
    }

    /// These layers with one layer switched, the other kept.
    #[must_use]
    pub const fn with(self, layer: CaptureLayer, enabled: bool) -> Self {
        match layer {
            CaptureLayer::SystemProxy => Self {
                system_proxy: enabled,
                ..self
            },
            CaptureLayer::Tun => Self {
                tun: enabled,
                ..self
            },
        }
    }
}

/// The layers a platform implements.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct CaptureSupport {
    pub system_proxy: bool,
    pub tun: bool,
}

impl CaptureSupport {
    #[must_use]
    pub const fn covers(self, layers: CaptureLayers) -> bool {
        (self.system_proxy || !layers.system_proxy) && (self.tun || !layers.tun)
    }
}

/// What the three platforms this project ships implement: both layers. An
/// OS it does not implement supports neither, so a host that asks for a
/// layer there is refused rather than told nothing happened.
#[must_use]
pub fn capture_support_for_os(os: &str) -> CaptureSupport {
    let implemented = matches!(os, "macos" | "linux" | "windows");
    CaptureSupport {
        system_proxy: implemented,
        tun: implemented,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_one_layer_keeps_the_other() {
        let both = CaptureLayers {
            system_proxy: true,
            tun: true,
        };
        assert_eq!(
            both.with(CaptureLayer::Tun, false),
            CaptureLayers {
                system_proxy: true,
                tun: false
            }
        );
        assert_eq!(
            CaptureLayers::NONE.with(CaptureLayer::SystemProxy, true),
            CaptureLayers {
                system_proxy: true,
                tun: false
            }
        );
        assert!(both.get(CaptureLayer::SystemProxy) && both.any());
        assert!(!CaptureLayers::NONE.any());
    }

    #[test]
    fn the_platforms_shipped_support_both_layers_and_the_rest_support_none() {
        for os in ["macos", "linux", "windows"] {
            let support = capture_support_for_os(os);
            assert!(support.system_proxy && support.tun, "{os}");
            assert!(support.covers(CaptureLayers {
                system_proxy: true,
                tun: true
            }));
        }
        let support = capture_support_for_os("freebsd");
        assert!(!support.system_proxy && !support.tun);
        assert!(support.covers(CaptureLayers::NONE));
        assert!(!support.covers(CaptureLayers {
            system_proxy: false,
            tun: true
        }));
    }
}
