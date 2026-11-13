//! Display-only enrichment for the connections UI on Windows: resolves a
//! captured executable path into the owning app's icon for the connections
//! table. Never feeds routing or telemetry; a query the resolver cannot
//! satisfy echoes its identifier back with empty fields and the UI keeps its
//! raw-identifier fallback (a neutral glyph plus the executable name).
//!
//! Icon extraction uses the documented Win32 shell/GDI path, implemented from
//! the Microsoft API references (not from memory):
//! - `SHGetFileInfoW` + `SHFILEINFOW` + `SHGFI_ICON`/`SHGFI_LARGEICON` obtain
//!   the file's associated icon:
//!   <https://learn.microsoft.com/windows/win32/api/shellapi/nf-shellapi-shgetfileinfow>
//! - `GetIconInfo` + `ICONINFO` + `DestroyIcon` expose and release the icon's
//!   color/mask bitmaps:
//!   <https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-geticoninfo>
//! - `GetObjectW`/`GetDIBits` with a top-down 32-bpp `BITMAPINFOHEADER` read
//!   the color bitmap as straight BGRA:
//!   <https://learn.microsoft.com/windows/win32/api/wingdi/nf-wingdi-getdibits>
//! - `CoInitializeEx`/`CoUninitialize` satisfy the documented COM requirement
//!   for `SHGetFileInfo`:
//!   <https://learn.microsoft.com/windows/win32/api/shellapi/nf-shellapi-shgetfileinfow#remarks>

use egrio_platform::{ProcessDisplayIdentity, ProcessDisplayQuery};

/// Resolves each query's owning application into its icon. Windows keys on the
/// absolute executable path (`query.path`); the returned identity stays keyed
/// on `query.identifier` so the UI cache and grouping are unchanged.
#[cfg(windows)]
pub fn resolve_app_display_identities(
    queries: &[ProcessDisplayQuery],
) -> Vec<ProcessDisplayIdentity> {
    // SHGetFileInfo requires COM on the calling thread; initialize once per
    // batch (the resolver command runs this on a blocking thread).
    let _com = unsafe { ComApartment::enter() };
    queries
        .iter()
        .map(|query| {
            let icon_png_base64 = query
                .path
                .as_deref()
                .filter(|path| !path.is_empty())
                .and_then(|path| unsafe { extract_icon_png_base64(path) });
            ProcessDisplayIdentity {
                identifier: query.identifier.clone(),
                // The connections table already shows the executable name; a
                // friendlier product name from the version resource is a
                // possible later enrichment. Icon is the missing piece.
                display_name: None,
                icon_png_base64,
            }
        })
        .collect()
}

/// Non-Windows fallback so the crate builds in the workspace off Windows: no
/// resolver, every query echoes back unresolved.
#[cfg(not(windows))]
pub fn resolve_app_display_identities(
    queries: &[ProcessDisplayQuery],
) -> Vec<ProcessDisplayIdentity> {
    queries
        .iter()
        .map(|query| ProcessDisplayIdentity::unresolved(query.identifier.clone()))
        .collect()
}

#[cfg(windows)]
mod imp {
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use base64::Engine as _;
    use windows_sys::Win32::Graphics::Gdi::{
        CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits, GetObjectW, BITMAP, BITMAPINFO,
        BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
    };
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED,
    };
    use windows_sys::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
    use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

    // Guard against pathological icon sizes so a bad handle cannot make us
    // allocate without bound ("一切有界").
    const MAX_ICON_EDGE: i32 = 512;

    // `CoInitializeEx` return values we treat as "COM is usable on this
    // thread": S_OK (we initialized it) and S_FALSE (already initialized on
    // this thread). Both mean we own a matching `CoUninitialize`.
    const S_OK: i32 = 0;
    const S_FALSE: i32 = 1;

    /// Owns the thread's COM initialization for the batch when we performed
    /// it, and balances it on drop. If COM was already initialized under a
    /// different apartment model the call fails and we leave it untouched.
    pub(super) struct ComApartment {
        owns_uninitialize: bool,
    }

    impl ComApartment {
        pub(super) unsafe fn enter() -> Self {
            let hr = CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED as u32);
            ComApartment {
                owns_uninitialize: hr == S_OK || hr == S_FALSE,
            }
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            if self.owns_uninitialize {
                unsafe { CoUninitialize() };
            }
        }
    }

    fn to_wide_null(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Extracts the file's associated large icon and returns it as a base64
    /// PNG, or `None` if the path has no obtainable icon.
    pub(super) unsafe fn extract_icon_png_base64(path: &str) -> Option<String> {
        let wide = to_wide_null(path);
        let mut info: SHFILEINFOW = zeroed();
        let obtained = SHGetFileInfoW(
            wide.as_ptr(),
            0,
            &mut info,
            size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_LARGEICON,
        );
        if obtained == 0 {
            return None;
        }
        let icon = info.hIcon;
        let rgba = hicon_to_rgba(icon);
        DestroyIcon(icon);
        let (width, height, pixels) = rgba?;
        let png = encode_png(width, height, &pixels)?;
        Some(base64::engine::general_purpose::STANDARD.encode(png))
    }

    /// Converts an `HICON` into a top-down RGBA image via its color bitmap.
    /// Deletes the bitmaps `GetIconInfo` hands us on every path.
    unsafe fn hicon_to_rgba(
        icon: windows_sys::Win32::UI::WindowsAndMessaging::HICON,
    ) -> Option<(u32, u32, Vec<u8>)> {
        let mut icon_info: ICONINFO = zeroed();
        if GetIconInfo(icon, &mut icon_info) == 0 {
            return None;
        }
        let color = icon_info.hbmColor;
        let mask = icon_info.hbmMask;
        let rgba = color_bitmap_to_rgba(color);
        if !color.is_null() {
            DeleteObject(color);
        }
        if !mask.is_null() {
            DeleteObject(mask);
        }
        rgba
    }

    unsafe fn color_bitmap_to_rgba(
        color: windows_sys::Win32::Graphics::Gdi::HBITMAP,
    ) -> Option<(u32, u32, Vec<u8>)> {
        // A monochrome icon carries no color bitmap (the image lives in the
        // mask, split top/bottom); those are legacy and rare for apps, so we
        // leave them to the UI's neutral glyph rather than reconstructing them.
        if color.is_null() {
            return None;
        }
        let mut bitmap: BITMAP = zeroed();
        if GetObjectW(
            color,
            size_of::<BITMAP>() as i32,
            &mut bitmap as *mut BITMAP as *mut _,
        ) == 0
        {
            return None;
        }
        let width = bitmap.bmWidth;
        let height = bitmap.bmHeight;
        if width <= 0 || height <= 0 || width > MAX_ICON_EDGE || height > MAX_ICON_EDGE {
            return None;
        }

        let dc = CreateCompatibleDC(ptr::null_mut());
        if dc.is_null() {
            return None;
        }
        let mut header: BITMAPINFO = zeroed();
        header.bmiHeader = BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            // Negative height requests a top-down image so row 0 is the top.
            biHeight: -height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB as u32,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        };
        let mut pixels = vec![0u8; width as usize * height as usize * 4];
        let scan_lines = GetDIBits(
            dc,
            color,
            0,
            height as u32,
            pixels.as_mut_ptr() as *mut _,
            &mut header,
            DIB_RGB_COLORS,
        );
        DeleteDC(dc);
        if scan_lines == 0 {
            return None;
        }

        normalize_bgra_to_rgba(&mut pixels);
        Some((width as u32, height as u32, pixels))
    }

    /// GetDIBits yields straight BGRA. Swap to RGBA, and if every alpha byte
    /// is zero (an icon delivered without an alpha channel would otherwise
    /// render fully transparent) force the image opaque.
    fn normalize_bgra_to_rgba(pixels: &mut [u8]) {
        let has_alpha = pixels.chunks_exact(4).any(|pixel| pixel[3] != 0);
        for pixel in pixels.chunks_exact_mut(4) {
            pixel.swap(0, 2);
            if !has_alpha {
                pixel[3] = 255;
            }
        }
    }

    fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Option<Vec<u8>> {
        let mut buffer = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut buffer, width, height);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().ok()?;
            writer.write_image_data(rgba).ok()?;
        }
        Some(buffer)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn normalizes_bgra_and_repairs_missing_alpha() {
            let mut pixels = vec![1, 2, 3, 0, 4, 5, 6, 0];

            normalize_bgra_to_rgba(&mut pixels);

            assert_eq!(pixels, vec![3, 2, 1, 255, 6, 5, 4, 255]);
        }

        #[test]
        fn encodes_rgba_as_png() {
            let png = encode_png(1, 1, &[3, 2, 1, 255]).expect("encode PNG");

            assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        }
    }
}

#[cfg(windows)]
use imp::{extract_icon_png_base64, ComApartment};

#[cfg(all(test, windows))]
mod tests {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn echoes_queries_without_obtainable_icons() {
        let queries = vec![
            ProcessDisplayQuery {
                identifier: "missing.exe".into(),
                path: Some(r"C:\does\not\exist\missing.exe".into()),
            },
            ProcessDisplayQuery {
                identifier: "no-path".into(),
                path: None,
            },
        ];

        let resolved = resolve_app_display_identities(&queries);

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].identifier, "missing.exe");
        assert_eq!(resolved[0].icon_png_base64, None);
        assert_eq!(resolved[1].identifier, "no-path");
        assert_eq!(resolved[1].icon_png_base64, None);
    }

    #[test]
    #[ignore = "requires a full Windows shell image with Explorer icon resources"]
    fn resolves_a_system_executable_icon() {
        // explorer.exe ships on every Windows install and carries an icon;
        // keep this as an explicit environment smoke rather than a contract
        // gate so Server Core or stripped CI images do not fail valid code.
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let queries = vec![ProcessDisplayQuery {
            identifier: "explorer.exe".into(),
            path: Some(format!(r"{system_root}\explorer.exe")),
        }];

        let resolved = resolve_app_display_identities(&queries);
        assert_eq!(resolved.len(), 1);

        // The real executable resolves to a PNG icon.
        assert_eq!(resolved[0].identifier, "explorer.exe");
        let icon = resolved[0]
            .icon_png_base64
            .as_deref()
            .expect("explorer.exe resolves to an icon");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(icon)
            .expect("icon is valid base64");
        assert_eq!(
            &bytes[..8],
            b"\x89PNG\r\n\x1a\n",
            "decoded icon must be a PNG"
        );
    }
}
