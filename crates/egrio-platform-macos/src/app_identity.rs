//! Display-only executable-path enrichment: app names and icons for the
//! connections UI, never routing metadata. Every result preserves its request
//! position and identifier; equal process names with distinct paths remain
//! independent identities.
//!
//! SDK basis: NSURL `URLByResolvingSymlinksInPath`/`URLByStandardizingPath`,
//! NSBundle `objectForInfoDictionaryKey:` (localized Info.plist values),
//! NSFileManager `displayNameAtPath:`, NSWorkspace `iconForFile:` and
//! `URLForApplicationWithBundleIdentifier:`, NSBitmapImageRep.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use egrio_platform::{ProcessDisplayIdentity, ProcessDisplayQuery};
use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::Bool;
use objc2::AllocAnyThread;
use objc2_app_kit::{
    NSBitmapImageFileType, NSBitmapImageRep, NSCompositingOperation, NSDeviceRGBColorSpace,
    NSGraphicsContext, NSWorkspace,
};
use objc2_foundation::{
    NSBundle, NSDictionary, NSFileManager, NSPoint, NSRect, NSSize, NSString, NSURL,
};

const BATCH_LIMIT: usize = 128;
const CACHE_CAPACITY: usize = 256;
const ICON_PIXELS: isize = 32;
const ICON_PNG_LIMIT: usize = 32 * 1024;
/// A resolved identity is kept five minutes; an unresolved one thirty
/// seconds, so an app installed meanwhile shows up soon.
const RESOLVED_TTL: Duration = Duration::from_secs(300);
const UNRESOLVED_TTL: Duration = Duration::from_secs(30);

/// Resolves attributed paths or explicit installed bundle-ID queries. The
/// bounded cache keys by the complete identity/path pair.
pub fn resolve_app_display_identities(
    requests: &[ProcessDisplayQuery],
) -> Result<Vec<ProcessDisplayIdentity>, String> {
    if requests.len() > BATCH_LIMIT {
        return Err("identity request exceeds the 128-query batch limit".into());
    }
    Ok(requests.iter().map(resolve).collect())
}

type CacheKey = (String, Option<String>);

struct Entry {
    identity: ProcessDisplayIdentity,
    expires: Instant,
    accessed: u64,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<CacheKey, Entry>,
    sequence: u64,
}

impl Cache {
    fn get(&mut self, key: &CacheKey, now: Instant) -> Option<ProcessDisplayIdentity> {
        let expired = self.entries.get(key)?.expires <= now;
        if expired {
            self.entries.remove(key);
            return None;
        }
        self.sequence += 1;
        let entry = self.entries.get_mut(key)?;
        entry.accessed = self.sequence;
        Some(entry.identity.clone())
    }

    fn insert(&mut self, key: CacheKey, identity: ProcessDisplayIdentity, now: Instant) {
        self.sequence += 1;
        let ttl = if identity.display_name.is_none() && identity.icon_png_base64.is_none() {
            UNRESOLVED_TTL
        } else {
            RESOLVED_TTL
        };
        self.entries.insert(
            key,
            Entry {
                identity,
                expires: now + ttl,
                accessed: self.sequence,
            },
        );
        while self.entries.len() > CACHE_CAPACITY {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.accessed)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

fn resolve(query: &ProcessDisplayQuery) -> ProcessDisplayIdentity {
    let key = (query.identifier.clone(), query.path.clone());
    let now = Instant::now();
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(hit) = cache.get_or_insert_with(Cache::default).get(&key, now) {
        return hit;
    }
    drop(cache);
    // The AppKit and Foundation calls autorelease; a worker thread has no
    // pool of its own until it exits.
    let identity = autoreleasepool(|_| match location(query) {
        Some(location) => ProcessDisplayIdentity {
            identifier: query.identifier.clone(),
            display_name: Some(location.display_name),
            icon_png_base64: icon_png_base64(&location.icon_path),
        },
        None => ProcessDisplayIdentity::unresolved(query.identifier.clone()),
    });
    CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(Cache::default)
        .insert(key, identity.clone(), now);
    identity
}

struct Location {
    display_name: String,
    icon_path: String,
}

fn location(query: &ProcessDisplayQuery) -> Option<Location> {
    if query.identifier.is_empty() {
        return None;
    }
    let url = match &query.path {
        // A supplied path is authoritative: a missing or invalid executable
        // never turns into some other installed app with the same name.
        Some(path) => {
            if !path.starts_with('/') || path.contains('\0') || path.len() > 4096 {
                return None;
            }
            NSURL::fileURLWithPath(&NSString::from_str(path))
        }
        // An explicit installed bundle ID is also a supported query; it is
        // not a signing-identifier or helper-name alias table.
        None => {
            if query.identifier.contains('/') || !query.identifier.contains('.') {
                return None;
            }
            let identifier = NSString::from_str(&query.identifier);
            let installed = NSWorkspace::sharedWorkspace()
                .URLForApplicationWithBundleIdentifier(&identifier)?;
            let matches = NSBundle::bundleWithURL(&installed)
                .and_then(|bundle| bundle.bundleIdentifier())
                .is_some_and(|found| found.to_string() == query.identifier);
            if !matches {
                return None;
            }
            installed
        }
    };
    let path = url
        .URLByResolvingSymlinksInPath()?
        .URLByStandardizingPath()?
        .path()?
        .to_string();
    let directory = existing(&path)?;
    if let Some(app) = outermost_application(&path) {
        if let Some(bundle) = NSBundle::bundleWithURL(&file_url(&app)) {
            let display_name = ["CFBundleDisplayName", "CFBundleName"]
                .into_iter()
                .filter_map(|key| info_string(&bundle, key))
                .find(|name| !name.is_empty())
                .unwrap_or_else(|| application_filename(&app));
            return Some(Location {
                display_name,
                icon_path: app,
            });
        }
    }
    if directory {
        return None;
    }
    Some(Location {
        display_name: path.rsplit('/').next().unwrap_or(&path).to_string(),
        icon_path: path,
    })
}

/// Whether `path` exists, as whether it is a directory.
fn existing(path: &str) -> Option<bool> {
    let mut directory = Bool::NO;
    // SAFETY: `directory` outlives the call.
    let exists = unsafe {
        NSFileManager::defaultManager()
            .fileExistsAtPath_isDirectory(&NSString::from_str(path), &mut directory)
    };
    exists.then(|| directory.as_bool())
}

fn file_url(path: &str) -> Retained<NSURL> {
    NSURL::fileURLWithPath(&NSString::from_str(path))
}

/// The outermost `.app` bundle on the path whose executable exists: a helper
/// inside an app's bundle shows as that app.
fn outermost_application(path: &str) -> Option<String> {
    let mut candidate = String::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        candidate.push('/');
        candidate.push_str(component);
        if !component.to_ascii_lowercase().ends_with(".app") {
            continue;
        }
        let executable = NSBundle::bundleWithURL(&file_url(&candidate))
            .and_then(|bundle| bundle.executableURL())
            .and_then(|executable| executable.path());
        if executable.is_some_and(|executable| existing(&executable.to_string()).is_some()) {
            return Some(candidate);
        }
    }
    None
}

fn info_string(bundle: &NSBundle, key: &str) -> Option<String> {
    let value = bundle.objectForInfoDictionaryKey(&NSString::from_str(key))?;
    value
        .downcast::<NSString>()
        .ok()
        .map(|value| value.to_string())
}

fn application_filename(app: &str) -> String {
    let name = NSFileManager::defaultManager()
        .displayNameAtPath(&NSString::from_str(app))
        .to_string();
    match name.to_ascii_lowercase().strip_suffix(".app") {
        Some(stem) => name[..stem.len()].to_string(),
        None => name,
    }
}

fn icon_png_base64(path: &str) -> Option<String> {
    let icon = NSWorkspace::sharedWorkspace().iconForFile(&NSString::from_str(path));
    // SAFETY: no planes, so the representation allocates its own buffer;
    // the color space name is AppKit's constant.
    let bitmap = unsafe {
        NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel(
            NSBitmapImageRep::alloc(),
            std::ptr::null_mut(),
            ICON_PIXELS,
            ICON_PIXELS,
            8,
            4,
            true,
            false,
            NSDeviceRGBColorSpace,
            0,
            0,
        )
    }?;
    let context = NSGraphicsContext::graphicsContextWithBitmapImageRep(&bitmap)?;
    NSGraphicsContext::saveGraphicsState_class();
    NSGraphicsContext::setCurrentContext(Some(&context));
    let side = ICON_PIXELS as f64;
    icon.drawInRect_fromRect_operation_fraction(
        NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(side, side)),
        NSRect::ZERO,
        NSCompositingOperation::Copy,
        1.0,
    );
    NSGraphicsContext::restoreGraphicsState_class();
    // SAFETY: an empty property dictionary of the declared type.
    let png = unsafe {
        bitmap.representationUsingType_properties(NSBitmapImageFileType::PNG, &NSDictionary::new())
    }?
    .to_vec();
    (png.len() <= ICON_PNG_LIMIT).then(|| base64::engine::general_purpose::STANDARD.encode(png))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_paths_keep_equal_names_independent_and_unknown_unresolved() {
        let identities = resolve_app_display_identities(&[
            ProcessDisplayQuery {
                identifier: "same-name".into(),
                path: Some("/usr/bin/true".into()),
            },
            ProcessDisplayQuery {
                identifier: "same-name".into(),
                path: Some("/usr/bin/false".into()),
            },
            ProcessDisplayQuery {
                identifier: "unknown".into(),
                path: None,
            },
        ])
        .expect("path queries are answered in order");
        assert_eq!(identities.len(), 3);
        assert_eq!(identities[0].display_name.as_deref(), Some("true"));
        assert_eq!(identities[1].display_name.as_deref(), Some("false"));
        assert!(identities[0]
            .icon_png_base64
            .as_ref()
            .is_some_and(|icon| !icon.is_empty()));
        assert_eq!(
            identities[2],
            ProcessDisplayIdentity::unresolved("unknown".into())
        );
    }

    #[test]
    fn a_helper_inside_an_app_bundle_shows_as_the_app() {
        let identities = resolve_app_display_identities(&[
            ProcessDisplayQuery {
                identifier: "finder".into(),
                path: Some("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder".into()),
            },
            ProcessDisplayQuery {
                identifier: "com.apple.finder".into(),
                path: None,
            },
            ProcessDisplayQuery {
                identifier: "missing".into(),
                path: Some("/nonexistent/egrio-test".into()),
            },
        ])
        .unwrap();
        assert_eq!(identities[0].display_name.as_deref(), Some("Finder"));
        assert_eq!(identities[1].display_name.as_deref(), Some("Finder"));
        assert_eq!(
            identities[2],
            ProcessDisplayIdentity::unresolved("missing".into())
        );
    }
}
