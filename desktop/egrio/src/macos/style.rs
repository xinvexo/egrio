//! How the interface's semantic styles look on macOS: tones as AppKit's
//! semantic colors, text styles as system fonts, icons as SF Symbols. The
//! colors adapt to light, dark and increased contrast on their own.

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_app_kit::{
    NSBezierPath, NSColor, NSFont, NSFontWeightMedium, NSFontWeightRegular, NSFontWeightSemibold,
    NSImage, NSImageResizingMode, NSImageSymbolConfiguration,
};
use objc2_foundation::{NSArray, NSEdgeInsets, NSRect, NSSize, NSString};

use egrio_ui::node::{Icon, TextStyle, Tone};

pub fn color(tone: Tone) -> Retained<NSColor> {
    match tone {
        Tone::Default => NSColor::labelColor(),
        Tone::Muted => NSColor::secondaryLabelColor(),
        Tone::Faint => NSColor::tertiaryLabelColor(),
        Tone::Accent => NSColor::controlAccentColor(),
        Tone::Success => NSColor::systemGreenColor(),
        Tone::Warning => NSColor::systemOrangeColor(),
        Tone::Danger => NSColor::systemRedColor(),
    }
}

pub fn font(style: TextStyle) -> Retained<NSFont> {
    unsafe {
        match style {
            TextStyle::Heading => NSFont::systemFontOfSize_weight(15.0, NSFontWeightSemibold),
            TextStyle::Body => NSFont::systemFontOfSize_weight(13.0, NSFontWeightRegular),
            TextStyle::Caption => NSFont::systemFontOfSize_weight(11.0, NSFontWeightRegular),
            TextStyle::Figure => {
                NSFont::monospacedDigitSystemFontOfSize_weight(17.0, NSFontWeightSemibold)
            }
            TextStyle::Mono => NSFont::monospacedSystemFontOfSize_weight(12.0, NSFontWeightRegular),
        }
    }
}

/// A setting group's title over its surface.
pub fn group_title_font() -> Retained<NSFont> {
    unsafe { NSFont::systemFontOfSize_weight(12.0, NSFontWeightSemibold) }
}

pub fn badge_font() -> Retained<NSFont> {
    unsafe { NSFont::systemFontOfSize_weight(10.5, NSFontWeightMedium) }
}

pub fn numeric_font(size: f64) -> Retained<NSFont> {
    unsafe { NSFont::monospacedDigitSystemFontOfSize_weight(size, NSFontWeightRegular) }
}

/// The SF Symbol for an icon; every name exists on macOS 13.
pub fn symbol_name(icon: Icon) -> &'static str {
    match icon {
        Icon::Activity => "waveform.path.ecg",
        Icon::Nodes => "point.3.connected.trianglepath.dotted",
        Icon::Profiles => "doc.text",
        Icon::Rules => "list.bullet.indent",
        Icon::Connections => "arrow.left.arrow.right",
        Icon::Logs => "terminal",
        Icon::Settings => "gearshape",
        Icon::Download => "arrow.down",
        Icon::Upload => "arrow.up",
        Icon::Clear => "eraser",
        Icon::Close => "xmark",
        Icon::Warning => "exclamationmark.triangle.fill",
        Icon::Messages => "bell",
        Icon::App => "app",
        Icon::Globe => "globe",
        Icon::Wrench => "wrench.and.screwdriver",
        Icon::Add => "plus",
        Icon::Edit => "pencil",
        Icon::Reapply => "arrow.counterclockwise",
        Icon::Delete => "trash",
        Icon::Zap => "bolt",
        Icon::Link => "link",
        Icon::Route => "arrow.triangle.branch",
        Icon::Refresh => "arrow.clockwise",
        Icon::ResetCount => "arrow.uturn.backward",
        Icon::Check => "checkmark",
    }
}

pub fn symbol(icon: Icon) -> Option<Retained<NSImage>> {
    named_symbol(symbol_name(icon))
}

/// An icon's symbol at its usual size, drawn clear: it takes its place in
/// a layout without showing.
pub fn clear_symbol(icon: Icon) -> Option<Retained<NSImage>> {
    let clear = NSColor::clearColor();
    let palette =
        NSImageSymbolConfiguration::configurationWithPaletteColors(&NSArray::from_slice(&[
            &*clear,
        ]));
    symbol(icon)?.imageWithSymbolConfiguration(&palette)
}

pub fn named_symbol(name: &str) -> Option<Retained<NSImage>> {
    NSImage::imageWithSystemSymbolName_accessibilityDescription(&NSString::from_str(name), None)
}

/// A symbol at `point_size`, a template its view tints.
pub fn sized_symbol(name: &str, point_size: f64) -> Option<Retained<NSImage>> {
    let size = NSImageSymbolConfiguration::configurationWithPointSize_weight(point_size, unsafe {
        NSFontWeightRegular
    });
    named_symbol(name)?.imageWithSymbolConfiguration(&size)
}

/// A symbol drawn in a fixed color rather than tinted as a template.
pub fn colored_symbol(name: &str, color: &NSColor, point_size: f64) -> Option<Retained<NSImage>> {
    let image = named_symbol(name)?;
    let palette =
        NSImageSymbolConfiguration::configurationWithPaletteColors(&NSArray::from_slice(&[color]));
    let size = NSImageSymbolConfiguration::configurationWithPointSize_weight(point_size, unsafe {
        NSFontWeightRegular
    });
    let configuration = palette.configurationByApplyingConfiguration(&size);
    image.imageWithSymbolConfiguration(&configuration)
}

/// A mask with rounded corners that stretches to any size, for a visual
/// effect view's `maskImage`.
pub fn rounded_mask(radius: f64) -> Retained<NSImage> {
    let size = NSSize::new(radius * 2.0 + 1.0, radius * 2.0 + 1.0);
    let draw = RcBlock::new(move |rect: NSRect| -> Bool {
        NSColor::blackColor().setFill();
        NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(rect, radius, radius).fill();
        Bool::YES
    });
    let image = NSImage::imageWithSize_flipped_drawingHandler(size, false, &draw);
    image.setCapInsets(NSEdgeInsets {
        top: radius,
        left: radius,
        bottom: radius,
        right: radius,
    });
    image.setResizingMode(NSImageResizingMode::Stretch);
    image
}
