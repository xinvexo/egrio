//! How the interface's semantic styles look in WinUI, and small helpers the
//! widgets share. Tones and text styles become `Style`s whose setters name
//! WinUI theme resources (`{ThemeResource …}`), so a control follows light,
//! dark and high contrast on its own; each style is parsed once with
//! `XamlReader` and cached. Icons are glyphs of the symbol font WinUI picks
//! (`SymbolThemeFontFamily`: Segoe Fluent Icons on Windows 11, Segoe MDL2
//! Assets on Windows 10), chosen among the code points both fonts share
//! ("Segoe Fluent Icons font", "Segoe MDL2 Assets icons").

use std::cell::RefCell;
use std::collections::HashMap;

use windows_core::{IInspectable, Interface, Result};

use egrio_ui::node::{ButtonStyle, Icon, TextStyle, Tone};

use super::bindings::{
    Application, CornerRadius, DataTemplate, FrameworkElement, GridLength, GridUnitType,
    IFrameworkElement, IPropertyValue, PropertyValue, Style, Thickness, XamlReader,
};

const NAMESPACES: &str = "xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' \
     xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'";

thread_local! {
    static STYLES: RefCell<HashMap<String, Style>> = RefCell::new(HashMap::new());
}

/// Parses XAML markup with the presentation namespaces declared on its root;
/// `root` is the element's name and `body` its attributes and content.
pub fn load<T: Interface>(root: &str, attributes: &str, body: &str) -> Result<T> {
    let markup = format!("<{root} {NAMESPACES} {attributes}>{body}</{root}>");
    XamlReader::Load(&markup)?.cast()
}

/// A style for `target` with these setters, parsed once.
pub fn style(target: &str, based_on: Option<&str>, setters: &[(&str, String)]) -> Result<Style> {
    let mut key = format!("{target}|{}", based_on.unwrap_or(""));
    for (property, value) in setters {
        key.push_str(&format!("|{property}={value}"));
    }
    if let Some(style) = STYLES.with(|styles| styles.borrow().get(&key).cloned()) {
        return Ok(style);
    }
    let based_on = based_on
        .map(|base| format!(" BasedOn='{{StaticResource {base}}}'"))
        .unwrap_or_default();
    let body: String = setters
        .iter()
        .map(|(property, value)| format!("<Setter Property='{property}' Value='{value}'/>"))
        .collect();
    let style: Style = load("Style", &format!("TargetType='{target}'{based_on}"), &body)?;
    STYLES.with(|styles| styles.borrow_mut().insert(key, style.clone()));
    Ok(style)
}

/// A resource the application or WinUI defines, such as a named style.
pub fn resource<T: Interface>(name: &str) -> Result<T> {
    let resources = Application::Current()?.Resources()?;
    let map: windows_collections::IMap<IInspectable, IInspectable> = resources.cast()?;
    map.Lookup(&boxed(name)?)?.cast()
}

/// Figures of one width, so a number that changes does not move what is
/// beside it and a column of them lines up (what macOS's monospaced-digit
/// system font gives).
pub fn tabular_figures(block: &super::bindings::TextBlock) -> Result<()> {
    super::bindings::Typography::SetNumeralAlignment(
        block,
        super::bindings::FontNumeralAlignment::Tabular,
    )
}

/// The colour a tone names, for a surface tinted with it.
pub fn tone_color(tone: Tone) -> &'static str {
    match tone {
        Tone::Default | Tone::Muted | Tone::Faint => "TextFillColorSecondary",
        Tone::Accent => "SystemAccentColor",
        Tone::Success => "SystemFillColorSuccess",
        Tone::Warning => "SystemFillColorCaution",
        Tone::Danger => "SystemFillColorCritical",
    }
}

/// How much of the tone's own colour a surface tinted with it shows: faint
/// enough to read text of that colour over, as the macOS badge is.
const TINT: f64 = 0.16;

/// A badge's surface in its tone: the tone's own colour, faint.
pub fn tone_surface(tone: Tone) -> Result<Style> {
    let color = tone_color(tone);
    let key = format!("Border|tint|{color}");
    if let Some(style) = STYLES.with(|styles| styles.borrow().get(&key).cloned()) {
        return Ok(style);
    }
    let style: Style = load(
        "Style",
        "TargetType='Border'",
        &format!(
            "<Setter Property='Background'><Setter.Value>             <SolidColorBrush Color='{{ThemeResource {color}}}' Opacity='{TINT}'/>             </Setter.Value></Setter>"
        ),
    )?;
    STYLES.with(|styles| styles.borrow_mut().insert(key, style.clone()));
    Ok(style)
}

pub fn theme(resource: &str) -> String {
    format!("{{ThemeResource {resource}}}")
}

/// The theme brush a tone names.
pub fn tone_brush(tone: Tone) -> &'static str {
    match tone {
        Tone::Default => "TextFillColorPrimaryBrush",
        Tone::Muted => "TextFillColorSecondaryBrush",
        Tone::Faint => "TextFillColorTertiaryBrush",
        Tone::Accent => "AccentTextFillColorPrimaryBrush",
        Tone::Success => "SystemFillColorSuccessBrush",
        Tone::Warning => "SystemFillColorCautionBrush",
        Tone::Danger => "SystemFillColorCriticalBrush",
    }
}

/// The background a badge of a tone sits on.
/// Size and weight of a text style, on the Windows type ramp (Caption 12,
/// Body 14, Body Strong 14 semibold, Subtitle 20 semibold).
pub fn text_setters(style: TextStyle) -> Vec<(&'static str, String)> {
    match style {
        TextStyle::Heading => vec![("FontSize", "14".into()), ("FontWeight", "SemiBold".into())],
        TextStyle::Body => vec![("FontSize", "14".into())],
        TextStyle::Caption => vec![("FontSize", "12".into())],
        TextStyle::Figure => vec![
            ("FontSize", "20".into()),
            ("FontWeight", "SemiBold".into()),
            ("Typography.NumeralAlignment", "Tabular".into()),
        ],
        TextStyle::Mono => vec![("FontSize", "12".into()), ("FontFamily", MONO_FONTS.into())],
    }
}

/// Cascadia Mono comes with Windows 11; Windows 10 has Consolas.
pub const MONO_FONTS: &str = "Cascadia Mono, Consolas";

pub fn text_style(style: TextStyle, tone: Tone) -> Result<Style> {
    let mut setters = text_setters(style);
    setters.push(("Foreground", theme(tone_brush(tone))));
    self::style("TextBlock", None, &setters)
}

/// A symbol's color; `Default` inherits its control's foreground.
pub fn icon_style(tone: Tone, size: f64) -> Result<Style> {
    let mut setters = vec![("FontSize", size.to_string())];
    if tone != Tone::Default {
        setters.push(("Foreground", theme(tone_brush(tone))));
    }
    style("FontIcon", None, &setters)
}

pub fn button_style(style: ButtonStyle) -> Result<Style> {
    match style {
        ButtonStyle::Primary => resource("AccentButtonStyle"),
        ButtonStyle::Secondary => resource("DefaultButtonStyle"),
        ButtonStyle::Plain => resource("SubtleButtonStyle"),
        ButtonStyle::Destructive => self::style(
            "Button",
            Some("DefaultButtonStyle"),
            &[("Foreground", theme("SystemFillColorCriticalBrush"))],
        ),
    }
}

/// The glyph of the symbol font for an icon (Segoe MDL2 Assets code points,
/// which Segoe Fluent Icons keeps).
pub fn glyph(icon: Icon) -> &'static str {
    match icon {
        Icon::Activity => "\u{E9D9}",    // Diagnostic
        Icon::Nodes => "\u{E968}",       // Network
        Icon::Profiles => "\u{E8A5}",    // Document
        Icon::Rules => "\u{E8FD}",       // BulletedList
        Icon::Connections => "\u{E8AB}", // Switch
        Icon::Logs => "\u{E756}",        // CommandPrompt
        Icon::Settings => "\u{E713}",    // Setting
        Icon::Download => "\u{E896}",    // Download
        Icon::Upload => "\u{E898}",      // Upload
        Icon::Clear => "\u{E75C}",       // EraseTool
        Icon::Close => "\u{E711}",       // Cancel
        Icon::Warning => "\u{E7BA}",     // Warning
        Icon::Messages => "\u{EA8F}",    // Ringer
        Icon::App => "\u{E71D}",         // AllApps
        Icon::Globe => "\u{E774}",       // Globe
        Icon::Wrench => "\u{E90F}",      // Repair
        Icon::Add => "\u{E710}",         // Add
        Icon::Edit => "\u{E70F}",        // Edit
        Icon::Reapply => "\u{E777}",     // UpdateRestore
        Icon::Delete => "\u{E74D}",      // Delete
        Icon::Zap => "\u{E945}",         // LightningBolt
        Icon::Link => "\u{E71B}",        // Link
        Icon::Route => "\u{E8F0}",       // Directions
        Icon::Refresh => "\u{E72C}",     // Refresh
        Icon::ResetCount => "\u{E7A7}",  // Undo
        Icon::Check => "\u{E73E}",       // CheckMark
    }
}

/// A string as an `IInspectable`, for content, tooltips and items.
pub fn boxed(text: &str) -> Result<IInspectable> {
    PropertyValue::CreateString(text)
}

/// The string inside an `IInspectable` made by [`boxed`].
pub fn unboxed(value: &IInspectable) -> Option<String> {
    value.cast::<IPropertyValue>().ok()?.GetString().ok()
}

pub fn thickness(horizontal: f64, vertical: f64) -> Thickness {
    Thickness {
        left: horizontal,
        top: vertical,
        right: horizontal,
        bottom: vertical,
    }
}

pub fn uniform(value: f64) -> Thickness {
    thickness(value, value)
}

pub fn corners(radius: f64) -> CornerRadius {
    CornerRadius {
        top_left: radius,
        top_right: radius,
        bottom_right: radius,
        bottom_left: radius,
    }
}

pub fn auto() -> GridLength {
    GridLength {
        value: 1.0,
        grid_unit_type: GridUnitType::Auto,
    }
}

pub fn star() -> GridLength {
    weighted_star(1.0)
}

/// A share of what is left, in proportion to the other shares: a track
/// that may only shrink takes nearly all of it and is capped at what it
/// needs, so what is left over goes to the ordinary shares beside it.
pub fn weighted_star(weight: f64) -> GridLength {
    GridLength {
        value: weight,
        grid_unit_type: GridUnitType::Star,
    }
}

pub fn pixels(value: f64) -> GridLength {
    GridLength {
        value,
        grid_unit_type: GridUnitType::Pixel,
    }
}

/// A data template whose root is an empty element of `root`, which the
/// list fills itself as items come into view.
pub fn empty_template(root: &str) -> Result<DataTemplate> {
    load("DataTemplate", "", &format!("<{root}/>"))
}

pub fn framework(element: &impl Interface) -> Result<IFrameworkElement> {
    element.cast()
}

pub fn as_element(element: &impl Interface) -> Result<FrameworkElement> {
    element.cast()
}

/// The framework element and UI element interfaces of any WinUI element,
/// whose own default interface does not carry their members.
pub trait Element: Interface {
    fn fe(&self) -> IFrameworkElement {
        self.cast().expect("a WinUI element is a framework element")
    }

    fn ui(&self) -> super::bindings::IUIElement {
        self.cast().expect("a WinUI element is a UI element")
    }

    /// The panel interface of a panel such as `StackPanel` or `Grid`.
    fn panel(&self) -> super::bindings::IPanel {
        self.cast().expect("a WinUI panel")
    }
}

impl<T: Interface> Element for T {}
