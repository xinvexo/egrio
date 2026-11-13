//! What the app needs of its windows as Win32 windows: the handle behind a
//! WinUI window (`IWindowNative` in the Windows App SDK's
//! `microsoft.ui.xaml.window.h`), the display scale, bringing a window to the
//! front, and the app icon and in-app mark, read from embedded `.ico` files
//! ("Icons": each file's directory entries point at its images, which
//! `CreateIconFromResourceEx` decodes, PNG images included).

use windows_core::{Interface, Result};

use super::bindings::{
    CreateIconFromResourceEx, DestroyIcon, GetDpiForSystem, GetDpiForWindow, GetSystemMetrics,
    GetSystemMetricsForDpi, IsIconic, SendMessageW, SetForegroundWindow, ShowWindow, Window, HICON,
    HWND, ICON_BIG, ICON_SMALL, LR_DEFAULTCOLOR, SM_CXICON, SM_CXSMICON, SW_RESTORE, WM_SETICON,
};

const ICON: &[u8] = include_bytes!("../../icons/icon.ico");
const APP_MARK: &[u8] = include_bytes!("../../icons/app-mark.ico");
/// The notification area's transparent snowflakes: blue with capture on,
/// grey with both capture layers off.
const TRAY_ON: &[u8] = include_bytes!("../../icons/tray-on.ico");
const TRAY_OFF: &[u8] = include_bytes!("../../icons/tray-off.ico");

#[allow(non_snake_case)]
mod native {
    use windows_core::{IUnknown, HRESULT};

    use super::HWND;

    #[windows_core::interface("eecdbf0e-bae9-4cb6-a68e-9598e1cb57bb")]
    pub unsafe trait IWindowNative: IUnknown {
        pub fn WindowHandle(&self, hwnd: *mut HWND) -> HRESULT;
    }
}
use native::IWindowNative;

/// The Win32 window of a WinUI window.
pub fn handle(window: &Window) -> Result<HWND> {
    let native: IWindowNative = window.cast()?;
    let mut hwnd: HWND = std::ptr::null_mut();
    // SAFETY: an out pointer for the handle.
    unsafe { native.WindowHandle(&mut hwnd) }.ok()?;
    Ok(hwnd)
}

/// Device pixels per device-independent pixel on the primary display.
pub fn system_scale() -> f64 {
    // SAFETY: no arguments.
    f64::from(unsafe { GetDpiForSystem() }) / 96.0
}

/// Device pixels per device-independent pixel where the window is.
pub fn scale(window: &Window) -> f64 {
    match handle(window) {
        // SAFETY: a window handle of this process.
        Ok(hwnd) => f64::from(unsafe { GetDpiForWindow(hwnd) }.max(96)) / 96.0,
        Err(_) => system_scale(),
    }
}

/// Shows the window if it is minimized and makes it the foreground window.
pub fn restore_and_focus(window: &Window) -> Result<()> {
    let hwnd = handle(window)?;
    // SAFETY: a window handle of this process.
    unsafe {
        if IsIconic(hwnd).as_bool() {
            let _ = ShowWindow(hwnd, SW_RESTORE);
        }
    }
    window.Activate()?;
    // SAFETY: as above. Windows may refuse the foreground to a background
    // process, which then flashes the taskbar button instead.
    unsafe {
        let _ = SetForegroundWindow(hwnd);
    }
    Ok(())
}

/// The app icon at `size` device pixels, the image of the embedded `.ico`
/// closest to it from above.
pub struct AppIcon(HICON);

/// The transparent in-app mark that suits `size` device pixels. Its ICO
/// images are PNG, which XAML's `BitmapImage` decodes too.
pub fn mark_image(size: i32) -> Option<&'static [u8]> {
    let (offset, length) = image_entry(APP_MARK, size)?;
    APP_MARK.get(offset..offset + length)
}

impl AppIcon {
    pub fn new(size: i32) -> Option<Self> {
        Self::from_ico(ICON, size)
    }

    fn from_ico(file: &'static [u8], size: i32) -> Option<Self> {
        let (offset, length) = image_entry(file, size)?;
        let image = file.get(offset..offset + length)?;
        // SAFETY: the bytes of one icon image; 0x00030000 is the format
        // version the function documents for icons.
        let icon = unsafe {
            CreateIconFromResourceEx(
                image.as_ptr(),
                image.len() as u32,
                true.into(),
                0x0003_0000,
                size,
                size,
                LR_DEFAULTCOLOR as u32,
            )
        };
        (!icon.is_null()).then_some(Self(icon))
    }

    /// The notification area's icon at the system display scale.
    pub fn tray(connected: bool) -> Option<Self> {
        let file = if connected { TRAY_ON } else { TRAY_OFF };
        // SAFETY: no pointers.
        Self::from_ico(file, unsafe {
            GetSystemMetricsForDpi(SM_CXSMICON, GetDpiForSystem())
        })
    }

    pub fn raw(&self) -> HICON {
        self.0
    }
}

impl Drop for AppIcon {
    fn drop(&mut self) {
        // SAFETY: an icon this owns.
        unsafe {
            let _ = DestroyIcon(self.0);
        }
    }
}

/// Gives a window the app icon in its title bar and taskbar button; the
/// icons stay alive as long as the process, as `WM_SETICON` requires.
pub fn set_icon(window: &Window) {
    let Ok(hwnd) = handle(window) else { return };
    thread_local! {
        static ICONS: Option<(AppIcon, AppIcon)> = {
            // SAFETY: no pointers.
            let big = unsafe { GetSystemMetrics(SM_CXICON) };
            // SAFETY: no pointers.
            let small = unsafe { GetSystemMetrics(SM_CXSMICON) };
            AppIcon::new(small).zip(AppIcon::new(big))
        };
    }
    ICONS.with(|icons| {
        if let Some((small, big)) = icons {
            // SAFETY: a window of this process and icons that outlive it.
            unsafe {
                SendMessageW(
                    hwnd,
                    WM_SETICON as u32,
                    ICON_SMALL as usize,
                    small.raw() as isize,
                );
                SendMessageW(
                    hwnd,
                    WM_SETICON as u32,
                    ICON_BIG as usize,
                    big.raw() as isize,
                );
            }
        }
    });
}

/// The offset and length of the image in an `.ico` file that suits `size`:
/// the smallest at least that large, else the largest. A width byte of 0
/// means 256.
fn image_entry(file: &[u8], size: i32) -> Option<(usize, usize)> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(file.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(file.get(at..at + 4)?.try_into().ok()?));
    if u16_at(2)? != 1 {
        return None;
    }
    let entries = (0..usize::from(u16_at(4)?)).filter_map(|index| {
        let entry = 6 + index * 16;
        let width = match *file.get(entry)? {
            0 => 256,
            width => i32::from(width),
        };
        Some((
            width,
            u32_at(entry + 12)? as usize,
            u32_at(entry + 8)? as usize,
        ))
    });
    let (mut above, mut largest): (Option<(i32, usize, usize)>, Option<(i32, usize, usize)>) =
        (None, None);
    for entry in entries {
        if entry.0 >= size && above.is_none_or(|best| entry.0 < best.0) {
            above = Some(entry);
        }
        if largest.is_none_or(|best| entry.0 > best.0) {
            largest = Some(entry);
        }
    }
    above
        .or(largest)
        .map(|(_, offset, length)| (offset, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_smallest_image_at_least_as_large() {
        // `cargo xtask icons` writes 16, 20, 24, 32, 40, 48, 64 and 256 px.
        let (offset, _) = image_entry(ICON, 28).unwrap();
        let (exact, _) = image_entry(ICON, 32).unwrap();
        assert_eq!(offset, exact);
        // Larger than every image: the largest, the 256-pixel PNG.
        let (largest, length) = image_entry(ICON, 1000).unwrap();
        assert_eq!(&ICON[largest + 1..largest + 4], b"PNG");
        assert!(largest + length <= ICON.len());
    }
}
