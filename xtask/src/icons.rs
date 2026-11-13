//! `cargo xtask icons`: generates the desktop icons from the PNG artwork in
//! `design/icons`. System app icons have their white-background artwork;
//! the in-app and installer mark is transparent. The Windows and Linux tray
//! share ready-sized ice-blue and silver crystal snowflakes, the macOS menu
//! bar black template snowflakes.
//!
//! - `icon.icns`: the app inside macOS's centered 824 px content area; 16 and
//!   32 px use ARGB planes (`ic04`, `ic05`), the rest PNG (`ic07`–`ic14`).
//! - `icon.ico`: the Windows executable, window and taskbar icon, 16–256 px.
//! - `<size>x<size>.png`: the Linux hicolor application icons.
//! - `app-mark.ico`: the transparent in-app mark at 16–256 px.
//! - `tray-on.ico`, `tray-off.ico` and `tray-{on,off}-<size>x<size>.png`:
//!   the Windows and Linux tray icons.
//! - `tray-macos-on.png`, `tray-macos-off.png`: the menu bar's 22 pt template
//!   images at twice the pixels, copied from the ready-sized masters.
//!
//! Windows packaging composites the transparent mark on white installer
//! sidebars and a header bitmap (`installer_artwork`).

use std::path::Path;

use tiny_skia::{FilterQuality, Pixmap, PixmapPaint, Transform};

use super::root;

const SOURCES: &str = "design/icons";
const OUTPUT: &str = "desktop/egrio/icons";

/// The ICO's images, smallest first.
const ICO_SIZES: [u32; 8] = [16, 20, 24, 32, 40, 48, 64, 256];

/// How an icns representation stores its pixels.
#[derive(Clone, Copy)]
enum Encoding {
    /// "ARGB", then the alpha, red, green and blue planes, each run-length
    /// encoded (`icns_rle`), with straight color.
    Argb,
    Png,
}

/// The icns representations: each type, its pixel size and encoding, the
/// ones `iconutil` writes. macOS reads the PNG data an `icp4` or `icp5`
/// representation may hold as pixels, so the 16 and 32 pixel ones are ARGB.
const ICNS_TYPES: [(&[u8; 4], u32, Encoding); 10] = [
    (b"ic04", 16, Encoding::Argb),
    (b"ic05", 32, Encoding::Argb),
    (b"ic07", 128, Encoding::Png),
    (b"ic08", 256, Encoding::Png),
    (b"ic09", 512, Encoding::Png),
    (b"ic10", 1024, Encoding::Png),
    (b"ic11", 32, Encoding::Png),
    (b"ic12", 64, Encoding::Png),
    (b"ic13", 256, Encoding::Png),
    (b"ic14", 512, Encoding::Png),
];

/// The Linux hicolor application icon sizes.
pub const LINUX_SIZES: [u32; 5] = [32, 48, 128, 256, 512];

/// The ready-sized tray artwork, shared by Windows and Linux.
const TRAY_SIZES: [u32; 8] = [16, 20, 24, 32, 48, 64, 128, 256];

/// The sizes the Linux tray offers its host.
const LINUX_TRAY_SIZES: [u32; 7] = [16, 20, 24, 32, 48, 64, 128];

pub fn generate() -> Result<(), String> {
    let root = root();
    let sources = root.join(SOURCES);
    let output = root.join(OUTPUT);
    let app = load(&sources.join("app-icon.png"))?;
    let mark = load(&sources.join("app-mark.png"))?;
    let macos = macos_canvas(&app)?;
    std::fs::create_dir_all(&output).map_err(|error| format!("{}: {error}", output.display()))?;
    write(&output.join("icon.icns"), &icns(&macos)?)?;
    write(&output.join("icon.ico"), &ico(&app)?)?;
    write(&output.join("app-mark.ico"), &ico(&mark)?)?;
    for size in LINUX_SIZES {
        write(
            &output.join(format!("{size}x{size}.png")),
            &render(&app, size)?,
        )?;
    }
    for name in ["tray-macos-on.png", "tray-macos-off.png"] {
        let path = sources.join(name);
        let png = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        write(&output.join(name), &png)?;
    }
    for state in ["on", "off"] {
        let images = TRAY_SIZES
            .iter()
            .map(|size| {
                let path = sources.join(format!("tray/{state}/{size}.png"));
                std::fs::read(&path)
                    .map(|png| (*size, png))
                    .map_err(|error| format!("{}: {error}", path.display()))
            })
            .collect::<Result<Vec<_>, String>>()?;
        for (size, png) in &images {
            if LINUX_TRAY_SIZES.contains(size) {
                write(&output.join(format!("tray-{state}-{size}x{size}.png")), png)?;
            }
        }
        write(
            &output.join(format!("tray-{state}.ico")),
            &ico_images(images),
        )?;
    }
    Ok(())
}

/// The scales, in percent, the installer's sidebar is rendered at.
#[cfg(windows)]
pub const SIDEBAR_SCALES: [u32; 8] = [100, 125, 150, 175, 200, 225, 250, 300];

/// The sidebar picks its display scale; Modern UI scales the header bitmap.
#[cfg(windows)]
pub fn installer_artwork(output: &Path) -> Result<(), String> {
    let mark = load(&root().join(SOURCES).join("app-mark.png"))?;
    std::fs::create_dir_all(output).map_err(|error| format!("{}: {error}", output.display()))?;
    for scale in SIDEBAR_SCALES {
        write(
            &output.join(format!("{scale}.bmp")),
            &bmp(&mark, scale as f32 / 100.0, (164.0, 314.0, 128.0))?,
        )?;
    }
    write(
        &output.join("header.bmp"),
        &bmp(&mark, 3.0, (150.0, 57.0, 40.0))?,
    )
}

fn load(path: &Path) -> Result<Pixmap, String> {
    Pixmap::load_png(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// The macOS bundle's artwork leaves 100 px clear on every side.
fn macos_canvas(app: &Pixmap) -> Result<Pixmap, String> {
    let mut canvas = Pixmap::new(1024, 1024).expect("macOS icon canvas");
    let artwork = resize(app, 824, 824)?;
    canvas.draw_pixmap(
        100,
        100,
        artwork.as_ref(),
        &PixmapPaint::default(),
        Transform::identity(),
        None,
    );
    Ok(canvas)
}

/// Bicubic sampling on premultiplied RGBA preserves translucent edges.
/// Reduce by at most two at each step so small icons sample the artwork's
/// details instead of skipping most source pixels in a single large step.
fn resize(image: &Pixmap, width: u32, height: u32) -> Result<Pixmap, String> {
    let mut reduced = image.clone();
    while reduced.width() > 2 * width || reduced.height() > 2 * height {
        let next_width = (reduced.width() / 2).max(width);
        let next_height = (reduced.height() / 2).max(height);
        reduced = resample(&reduced, next_width, next_height)?;
    }
    if reduced.width() == width && reduced.height() == height {
        Ok(reduced)
    } else {
        resample(&reduced, width, height)
    }
}

fn resample(image: &Pixmap, width: u32, height: u32) -> Result<Pixmap, String> {
    let mut canvas = Pixmap::new(width, height)
        .ok_or_else(|| format!("no {width} by {height} px icon canvas"))?;
    canvas.draw_pixmap(
        0,
        0,
        image.as_ref(),
        &PixmapPaint {
            quality: FilterQuality::Bicubic,
            ..PixmapPaint::default()
        },
        Transform::from_scale(
            width as f32 / image.width() as f32,
            height as f32 / image.height() as f32,
        ),
        None,
    );
    Ok(canvas)
}

fn render(image: &Pixmap, size: u32) -> Result<Vec<u8>, String> {
    resize(image, size, size)?
        .encode_png()
        .map_err(|error| format!("encode a {size} px PNG: {error}"))
}

#[cfg(windows)]
/// Installer artwork on an opaque white canvas as a bottom-up 24-bit BMP.
fn bmp(app: &Pixmap, scale: f32, layout: (f32, f32, f32)) -> Result<Vec<u8>, String> {
    let width = (layout.0 * scale).round() as u32;
    let height = (layout.1 * scale).round() as u32;
    let size = (layout.2 * scale).round() as u32;
    let mut pixmap = Pixmap::new(width, height).expect("installer artwork canvas");
    pixmap.fill(tiny_skia::Color::WHITE);
    let icon = resize(app, size, size)?;
    pixmap.draw_pixmap(
        ((width - size) / 2) as i32,
        ((height - size) / 2) as i32,
        icon.as_ref(),
        &PixmapPaint::default(),
        Transform::identity(),
        None,
    );
    let (width, height) = (width as usize, height as usize);
    let row = (width * 3).next_multiple_of(4);
    let size = 54 + row * height;
    let mut file = Vec::with_capacity(size);
    file.extend(b"BM");
    file.extend((size as u32).to_le_bytes());
    file.extend(0u32.to_le_bytes());
    file.extend(54u32.to_le_bytes());
    file.extend(40u32.to_le_bytes());
    file.extend((width as i32).to_le_bytes());
    file.extend((height as i32).to_le_bytes());
    file.extend(1u16.to_le_bytes());
    file.extend(24u16.to_le_bytes());
    file.extend(0u32.to_le_bytes());
    file.extend(((row * height) as u32).to_le_bytes());
    file.extend([0; 16]);
    for line in pixmap.pixels().chunks(width).rev() {
        let start = file.len();
        for pixel in line {
            let pixel = pixel.demultiply();
            file.extend([pixel.blue(), pixel.green(), pixel.red()]);
        }
        file.resize(start + row, 0);
    }
    Ok(file)
}

/// An icns ARGB representation with straight color.
fn argb(image: &Pixmap, size: u32) -> Result<Vec<u8>, String> {
    let pixels: Vec<_> = resize(image, size, size)?
        .pixels()
        .iter()
        .map(|pixel| pixel.demultiply())
        .collect();
    let mut data = b"ARGB".to_vec();
    for channel in [
        tiny_skia::ColorU8::alpha,
        tiny_skia::ColorU8::red,
        tiny_skia::ColorU8::green,
        tiny_skia::ColorU8::blue,
    ] {
        let plane: Vec<u8> = pixels.iter().map(|pixel| channel(*pixel)).collect();
        data.extend(icns_rle(&plane));
    }
    Ok(data)
}

/// A byte below 0x80 precedes that many and one literals; a byte from 0x80
/// precedes one byte that repeats that count less 125 times.
fn icns_rle(plane: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut index = 0;
    while index < plane.len() {
        let run = run_length(&plane[index..]);
        if run >= 3 {
            encoded.push((run + 125) as u8);
            encoded.push(plane[index]);
            index += run;
            continue;
        }
        let start = index;
        while index < plane.len() && index - start < 128 && run_length(&plane[index..]) < 3 {
            index += 1;
        }
        encoded.push((index - start - 1) as u8);
        encoded.extend_from_slice(&plane[start..index]);
    }
    encoded
}

fn run_length(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take(130)
        .take_while(|&&byte| byte == bytes[0])
        .count()
}

/// An ICO of PNG images (`ICONDIR`, then an `ICONDIRENTRY` per image).
fn ico(image: &Pixmap) -> Result<Vec<u8>, String> {
    let images = ICO_SIZES
        .iter()
        .map(|size| render(image, *size).map(|png| (*size, png)))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ico_images(images))
}

/// Wraps ready-sized PNGs without resampling their pixels.
fn ico_images(images: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend(0u16.to_le_bytes());
    file.extend(1u16.to_le_bytes());
    file.extend((images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len();
    for (size, png) in &images {
        let side = if *size >= 256 { 0 } else { *size as u8 };
        file.extend([side, side, 0, 0]);
        file.extend(1u16.to_le_bytes());
        file.extend(32u16.to_le_bytes());
        file.extend((png.len() as u32).to_le_bytes());
        file.extend((offset as u32).to_le_bytes());
        offset += png.len();
    }
    for (_, png) in images {
        file.extend(png);
    }
    file
}

/// The icns header followed by each representation's type, length and data.
fn icns(image: &Pixmap) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    for (kind, size, encoding) in ICNS_TYPES {
        let data = match encoding {
            Encoding::Argb => argb(image, size)?,
            Encoding::Png => render(image, size)?,
        };
        body.extend(kind);
        body.extend((data.len() as u32 + 8).to_be_bytes());
        body.extend(data);
    }
    let mut file = b"icns".to_vec();
    file.extend((body.len() as u32 + 8).to_be_bytes());
    file.extend(body);
    Ok(file)
}

fn write(path: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(path, data).map_err(|error| format!("{}: {error}", path.display()))?;
    eprintln!("xtask: wrote {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::icns_rle;

    fn decode(mut encoded: &[u8]) -> Vec<u8> {
        let mut plane = Vec::new();
        while let Some((&head, rest)) = encoded.split_first() {
            if head < 0x80 {
                let count = usize::from(head) + 1;
                plane.extend_from_slice(&rest[..count]);
                encoded = &rest[count..];
            } else {
                plane.extend(std::iter::repeat_n(rest[0], usize::from(head) - 125));
                encoded = &rest[1..];
            }
        }
        plane
    }

    #[test]
    fn an_icns_plane_survives_its_run_length_encoding() {
        let mut plane = vec![0; 300];
        plane.extend((0..=255u8).cycle().take(400));
        plane.extend([7, 7, 1, 1, 1, 2, 9, 9, 9, 9, 4]);
        let encoded = icns_rle(&plane);
        assert_eq!(decode(&encoded), plane);
        assert!(encoded.len() < plane.len());
    }
}
