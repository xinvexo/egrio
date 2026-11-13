//! Display-only enrichment for attributed connection processes. Resolvers
//! use the actual executable path to obtain native application/file metadata;
//! explicitly supported platform identities can resolve without a path.
//! Unknown attribution remains unresolved. Never feeds routing or telemetry.

use serde::{Deserialize, Serialize};

/// One resolved process identity for UI display. `display_name` /
/// `icon_png_base64` stay `None` when the platform cannot resolve the
/// attributed executable or explicitly requested application identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessDisplayIdentity {
    pub identifier: String,
    pub display_name: Option<String>,
    pub icon_png_base64: Option<String>,
}

impl ProcessDisplayIdentity {
    /// The neutral fallback every platform uses for identifiers it cannot
    /// resolve: echo the identifier, no name, no icon.
    pub fn unresolved(identifier: String) -> Self {
        Self {
            identifier,
            display_name: None,
            icon_png_base64: None,
        }
    }
}

/// A connection process display query. `identifier` preserves the attributed
/// process identity (for example an executable filename); `path` is its
/// absolute executable path when known. Identity and path together distinguish
/// unrelated executables with equal names. Batch resolvers preserve query
/// order and echo each identifier; the result DTO intentionally has no path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessDisplayQuery {
    pub identifier: String,
    pub path: Option<String>,
}
