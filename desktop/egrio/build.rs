//! Links the Windows application manifest (`windows/egrio.manifest`) and
//! the Windows resources (the app icon and the version) into the
//! executable, and compiles the Linux app's resources
//! (`linux/egrio.gresource.xml`) with `glib-compile-resources`, which comes
//! with GLib's development files; macOS needs nothing here.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=windows/egrio.manifest");
    println!("cargo:rerun-if-changed=icons/icon.ico");
    println!("cargo:rerun-if-changed=linux");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = Path::new(&manifest_dir);
    match target_os.as_str() {
        "windows" if target_env == "msvc" => {
            windows_manifest(manifest_dir);
            windows_resources(manifest_dir);
        }
        "linux" => linux_resources(manifest_dir),
        _ => {}
    }
}

fn windows_manifest(manifest_dir: &Path) {
    let manifest = manifest_dir.join("windows").join("egrio.manifest");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
}

/// `RT_ICON`, `RT_GROUP_ICON` and `RT_VERSION` from WinUser.h.
const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const RT_VERSION: u16 = 16;
/// US English, the language of the version strings.
const LANGUAGE_EN_US: u16 = 0x0409;
/// The code page of the version strings: Unicode.
const CODE_PAGE_UNICODE: u16 = 1200;

/// Writes the app icon and the version as a resource file, which the linker
/// takes as an input (".res files as linker input"), so Explorer, the Start
/// menu, the installed-apps list and Task Manager show Egrio's icon and
/// name. The file format is "Resource file formats" in the Win32 docs:
/// `RESOURCEHEADER` before each resource, one `RT_ICON` per image of
/// `icons/icon.ico` and the `RT_GROUP_ICON` directory (`NEWHEADER` and
/// `RESDIR`) naming them, and `VS_VERSIONINFO`.
fn windows_resources(manifest_dir: &Path) {
    let icon = std::fs::read(manifest_dir.join("icons").join("icon.ico")).unwrap();
    let u16_at = |at: usize| u16::from_le_bytes([icon[at], icon[at + 1]]);
    let u32_at = |at: usize| u32::from_le_bytes(icon[at..at + 4].try_into().unwrap()) as usize;
    assert_eq!(u16_at(2), 1, "icons/icon.ico holds icons");
    let count = u16_at(4);
    // A resource file opens with an empty resource.
    let mut file = vec![0, 0, 0, 0, 32, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0, 0];
    file.resize(32, 0);
    let mut group = [0, 1, count].map(u16::to_le_bytes).concat();
    for id in 1..=count {
        let entry = 6 + usize::from(id - 1) * 16;
        let (length, offset) = (u32_at(entry + 8), u32_at(entry + 12));
        resource(&mut file, RT_ICON, id, &icon[offset..offset + length]);
        // The image's size, colors, planes, bit count and length as the
        // file's directory gives them, then its resource ID.
        group.extend_from_slice(&icon[entry..entry + 12]);
        group.extend_from_slice(&id.to_le_bytes());
    }
    resource(&mut file, RT_GROUP_ICON, 1, &group);
    resource(&mut file, RT_VERSION, 1, &version_info());
    let path = Path::new(&std::env::var("OUT_DIR").unwrap()).join("egrio.res");
    std::fs::write(&path, file).unwrap();
    println!("cargo:rustc-link-arg-bins={}", path.display());
}

/// Appends one resource with a numeric type and name to a resource file.
fn resource(file: &mut Vec<u8>, kind: u16, name: u16, data: &[u8]) {
    let words = |values: [u16; 2]| values.map(u16::to_le_bytes).concat();
    file.extend((data.len() as u32).to_le_bytes());
    // The header's own size, then the type and the name as numbers.
    file.extend(32u32.to_le_bytes());
    file.extend(words([0xFFFF, kind]));
    file.extend(words([0xFFFF, name]));
    // The data version; the memory flags, which Windows ignores, and the
    // language; the version and the characteristics, which are for tools.
    file.extend(0u32.to_le_bytes());
    file.extend(words([0, LANGUAGE_EN_US]));
    file.extend([0; 8]);
    file.extend_from_slice(data);
    align(file);
}

/// Pads to the next 32-bit boundary, as resources and version blocks are.
fn align(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}

/// The value of a version block: none, text, or binary data.
enum Value<'a> {
    None,
    Text(&'a str),
    Binary(Vec<u8>),
}

/// One block of `VS_VERSIONINFO` (`StringFileInfo`, `StringTable`, `String`,
/// `VarFileInfo`, `Var`): its length, its value's length (characters for
/// text, bytes for binary data) and type, its key, its value and its
/// children, each starting on a 32-bit boundary.
fn version_block(key: &str, value: Value, children: &[Vec<u8>]) -> Vec<u8> {
    let mut block = vec![0; 6];
    block.extend(key.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
    align(&mut block);
    let (value_length, kind) = match value {
        Value::None => (0, 1),
        Value::Text(text) => {
            let text: Vec<u16> = text.encode_utf16().chain([0]).collect();
            block.extend(text.iter().flat_map(|unit| unit.to_le_bytes()));
            (text.len(), 1)
        }
        Value::Binary(data) => {
            block.extend_from_slice(&data);
            (data.len(), 0)
        }
    };
    for child in children {
        align(&mut block);
        block.extend_from_slice(child);
    }
    let length = block.len() as u16;
    block[0..2].copy_from_slice(&length.to_le_bytes());
    block[2..4].copy_from_slice(&(value_length as u16).to_le_bytes());
    block[4..6].copy_from_slice(&(kind as u16).to_le_bytes());
    block
}

/// `VS_VERSIONINFO`: the crate's version as the file and product version
/// (`VS_FIXEDFILEINFO`), and the names Windows shows, in US English.
fn version_info() -> Vec<u8> {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut numbers = version
        .split(['.', '-', '+'])
        .map(|part| part.parse::<u32>().unwrap_or(0));
    let mut next = || numbers.next().unwrap_or(0);
    let (major, minor, patch) = (next(), next(), next());
    let fixed = [
        0xFEEF_04BD,         // dwSignature
        0x0001_0000,         // dwStrucVersion
        major << 16 | minor, // dwFileVersionMS
        patch << 16,         // dwFileVersionLS
        major << 16 | minor, // dwProductVersionMS
        patch << 16,         // dwProductVersionLS
        0x3F,                // dwFileFlagsMask: VS_FFI_FILEFLAGSMASK
        0,                   // dwFileFlags
        0x0004_0004,         // dwFileOS: VOS_NT_WINDOWS32
        1,                   // dwFileType: VFT_APP
        0,                   // dwFileSubtype
        0,                   // dwFileDateMS
        0,                   // dwFileDateLS
    ]
    .map(u32::to_le_bytes)
    .concat();
    let strings: Vec<Vec<u8>> = [
        ("CompanyName", "xinvexo"),
        ("FileDescription", "Egrio"),
        ("FileVersion", version.as_str()),
        ("InternalName", "egrio"),
        ("OriginalFilename", "egrio.exe"),
        ("ProductName", "Egrio"),
        ("ProductVersion", version.as_str()),
    ]
    .map(|(key, text)| version_block(key, Value::Text(text), &[]))
    .into();
    let table = format!("{LANGUAGE_EN_US:04x}{CODE_PAGE_UNICODE:04x}");
    let translation = [LANGUAGE_EN_US, CODE_PAGE_UNICODE]
        .map(u16::to_le_bytes)
        .concat();
    version_block(
        "VS_VERSION_INFO",
        Value::Binary(fixed),
        &[
            version_block(
                "StringFileInfo",
                Value::None,
                &[version_block(&table, Value::None, &strings)],
            ),
            version_block(
                "VarFileInfo",
                Value::None,
                &[version_block(
                    "Translation",
                    Value::Binary(translation),
                    &[],
                )],
            ),
        ],
    )
}

fn linux_resources(manifest_dir: &Path) {
    let sources = manifest_dir.join("linux");
    let target = Path::new(&std::env::var("OUT_DIR").unwrap()).join("egrio.gresource");
    let status = Command::new("glib-compile-resources")
        .arg(format!("--sourcedir={}", sources.display()))
        .arg(format!("--target={}", target.display()))
        .arg(sources.join("egrio.gresource.xml"))
        .status()
        .unwrap_or_else(|error| {
            panic!("run glib-compile-resources (GLib's development files): {error}")
        });
    assert!(status.success(), "glib-compile-resources failed: {status}");
}
