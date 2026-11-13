//! How the interface's semantic styles look with libadwaita: text styles
//! and tones as its style classes ("Style Classes" in the libadwaita
//! documentation), colors from its named colors so they follow the light
//! and dark looks, and icons as symbolic icons. Adwaita lacks a few of the
//! symbols the interface names; Egrio carries those itself, compiled into
//! the executable as a resource (`linux/egrio.gresource.xml`).

use gtk::prelude::*;

use egrio_ui::node::{ButtonStyle, Icon, TextStyle, Tone};

/// Egrio's own rules on top of libadwaita's stylesheet: the badge, the
/// status dot, the selected card's edge, the message capsule and its
/// surface, which grows into the message panel and is drawn like a popover,
/// the tiles and their test buttons, and the faint tone, which libadwaita
/// has no class for.
const CSS: &str = "
.egrio-faint { opacity: 0.4; }
.egrio-badge {
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 0.82em;
  font-weight: 600;
  background-color: alpha(currentColor, 0.12);
}
.egrio-dot {
  min-width: 8px;
  min-height: 8px;
  border-radius: 4px;
  background-color: currentColor;
}
.egrio-dot.success { background-color: @success_color; }
.egrio-dot.warning { background-color: @warning_color; }
.egrio-dot.error { background-color: @error_color; }
.egrio-dot.accent { background-color: @accent_color; }
.card.egrio-selected { outline: 2px solid @accent_color; outline-offset: -2px; }
.egrio-drawer {
  background-color: @popover_bg_color;
  border-radius: 13px;
  box-shadow: 0 1px 5px 1px alpha(black, 0), 0 2px 14px 3px alpha(black, 0),
    0 0 0 1px alpha(black, 0.06);
  transition: box-shadow 250ms ease-out;
}
.egrio-drawer.egrio-open {
  box-shadow: 0 1px 5px 1px alpha(black, 0.09), 0 2px 14px 3px alpha(black, 0.05),
    0 0 0 1px alpha(black, 0.06);
}
.egrio-drawer-messages { color: @popover_fg_color; }
button.egrio-capsule {
  min-height: 0;
  min-width: 0;
  padding: 0 9px;
  border-radius: 13px;
  border: none;
  box-shadow: none;
  background-color: transparent;
  color: alpha(@window_fg_color, 0.65);
  transition: background-color 250ms ease-out, color 250ms ease-out;
}
button.egrio-capsule:not(.egrio-open):hover { background-color: alpha(@window_fg_color, 0.07); }
button.egrio-capsule.error { color: @error_color; background-color: alpha(@error_color, 0.14); }
button.egrio-capsule.error:hover { background-color: alpha(@error_color, 0.22); }
button.egrio-capsule.warning { color: @warning_color; background-color: alpha(@warning_color, 0.14); }
button.egrio-capsule.warning:hover { background-color: alpha(@warning_color, 0.22); }
/* Information is the palette's blue: Ubuntu's orange accent would read as
   a warning. */
button.egrio-capsule.accent { color: @blue_3; background-color: alpha(@blue_3, 0.14); }
button.egrio-capsule.accent:hover { background-color: alpha(@blue_3, 0.22); }
button.egrio-capsule .egrio-capsule-text {
  color: @window_fg_color;
  font-weight: 500;
  opacity: 0;
  transition: opacity 250ms ease-out;
}
button.egrio-capsule .egrio-capsule-text.egrio-shown { opacity: 1; }
.egrio-figure { font-size: 1.45em; font-weight: 700; }
.egrio-table { background: none; }
.egrio-table > listview > row { min-height: 0; }
.egrio-table cell { padding: 0 6px; }
.egrio-list { background: none; }
.egrio-drop-above { box-shadow: inset 0 2px @accent_color; }
.egrio-drop-below { box-shadow: inset 0 -2px @accent_color; }
.egrio-list > row { padding: 0 8px; }
gridview.egrio-tiles { background: none; }
gridview.egrio-tiles > child { padding: 5px; background: none; }
gridview.egrio-tiles > child:hover .card.egrio-pressable:not(.egrio-over-test) {
  background-color: alpha(currentColor, 0.08);
}
.card.egrio-dimmed { opacity: 0.55; }
button.egrio-tile-test {
  min-height: 0;
  min-width: 0;
  padding: 2px 4px;
  border-radius: 5px;
  border: none;
  box-shadow: none;
  background: none;
}
spinner.egrio-small { min-width: 12px; min-height: 12px; -gtk-icon-size: 12px; }
button.egrio-tile-test.egrio-testable:hover { background-color: alpha(currentColor, 0.09); }
button.egrio-tile-test.egrio-testable:active { background-color: alpha(currentColor, 0.16); }
";

/// The resource path of Egrio's icons, laid out as the hicolor theme is
/// (`GtkIconTheme`'s resource paths).
const ICONS: &str = "/com/xinvexo/egrio/icons";

/// Adds Egrio's stylesheet, above the theme, and its icons to the display.
pub fn install(display: &gtk::gdk::Display) {
    if let Err(error) = gtk::gio::resources_register_include!("egrio.gresource") {
        log::warn!("register Egrio's icons: {error}");
    }
    gtk::IconTheme::for_display(display).add_resource_path(ICONS);
    let provider = gtk::CssProvider::new();
    provider.load_from_string(CSS);
    gtk::style_context_add_provider_for_display(
        display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

/// libadwaita's class for a tone's color, if it has one.
fn tone_class(tone: Tone) -> Option<&'static str> {
    match tone {
        Tone::Default => None,
        Tone::Muted => Some("dim-label"),
        Tone::Faint => Some("egrio-faint"),
        Tone::Accent => Some("accent"),
        Tone::Success => Some("success"),
        Tone::Warning => Some("warning"),
        Tone::Danger => Some("error"),
    }
}

const TONE_CLASSES: [&str; 6] = [
    "dim-label",
    "egrio-faint",
    "accent",
    "success",
    "warning",
    "error",
];

/// Gives `widget` the color of `tone` in place of the one it had.
pub fn set_tone(widget: &impl IsA<gtk::Widget>, tone: Tone) {
    for class in TONE_CLASSES {
        widget.remove_css_class(class);
    }
    if let Some(class) = tone_class(tone) {
        widget.add_css_class(class);
    }
}

fn text_classes(style: TextStyle) -> &'static [&'static str] {
    match style {
        TextStyle::Heading => &["heading"],
        TextStyle::Body => &["body"],
        TextStyle::Caption => &["caption"],
        TextStyle::Figure => &["egrio-figure", "numeric"],
        TextStyle::Mono => &["monospace", "caption"],
    }
}

const TEXT_CLASSES: [&str; 6] = [
    "heading",
    "body",
    "caption",
    "egrio-figure",
    "numeric",
    "monospace",
];

/// Gives a label, or a widget whose text inherits it, a text style and a
/// tone in place of the ones it had.
pub fn set_text_style(widget: &impl IsA<gtk::Widget>, style: TextStyle, tone: Tone) {
    for class in TEXT_CLASSES {
        widget.remove_css_class(class);
    }
    for class in text_classes(style) {
        widget.add_css_class(class);
    }
    set_tone(widget, tone);
}

/// A label of a style and a tone, starting at the leading edge and cut with
/// an ellipsis when it does not fit, its whole text in its help while cut.
pub fn label(text: &str, style: TextStyle, tone: Tone) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_xalign(0.0);
    label.set_ellipsize(gtk::pango::EllipsizeMode::End);
    label.set_single_line_mode(true);
    set_text_style(&label, style, tone);
    help_when_cut(&label);
    label
}

/// Whether a label shows less than its whole text: cut with an ellipsis
/// where it does not fit (`pango_layout_is_ellipsized`).
pub fn is_cut(label: &gtk::Label) -> bool {
    label.ellipsize() != gtk::pango::EllipsizeMode::None && label.layout().is_ellipsized()
}

/// Gives a label its whole text as its help while it is cut, unless it has
/// help of its own, which then shows instead ("GtkWidget::query-tooltip").
pub fn help_when_cut(label: &gtk::Label) {
    label.set_has_tooltip(true);
    label.connect_query_tooltip(|label, _, _, _, tooltip| {
        if label.tooltip_text().is_some() || !is_cut(label) {
            return false;
        }
        tooltip.set_text(Some(&label.text()));
        true
    });
}

const BUTTON_CLASSES: [&str; 3] = ["suggested-action", "flat", "destructive-action"];

pub fn set_button_style(button: &impl IsA<gtk::Widget>, style: ButtonStyle) {
    for class in BUTTON_CLASSES {
        button.remove_css_class(class);
    }
    match style {
        ButtonStyle::Primary => button.add_css_class("suggested-action"),
        ButtonStyle::Secondary => {}
        ButtonStyle::Plain => button.add_css_class("flat"),
        ButtonStyle::Destructive => button.add_css_class("destructive-action"),
    }
}

/// The symbolic icon for an icon: Adwaita's where it has one with that
/// meaning, Egrio's own (`egrio-…`) otherwise.
pub fn icon_name(icon: Icon) -> &'static str {
    match icon {
        Icon::Activity => "egrio-activity-symbolic",
        Icon::Nodes => "network-workgroup-symbolic",
        Icon::Profiles => "x-office-document-symbolic",
        Icon::Rules => "view-list-bullet-symbolic",
        Icon::Connections => "network-transmit-receive-symbolic",
        Icon::Logs => "utilities-terminal-symbolic",
        Icon::Settings => "emblem-system-symbolic",
        Icon::Download => "egrio-arrow-down-symbolic",
        Icon::Upload => "egrio-arrow-up-symbolic",
        Icon::Clear => "edit-clear-all-symbolic",
        Icon::Close => "window-close-symbolic",
        Icon::Warning => "dialog-warning-symbolic",
        Icon::Messages => "egrio-bell-symbolic",
        Icon::App => "application-x-executable-symbolic",
        Icon::Globe => "egrio-globe-symbolic",
        Icon::Wrench => "egrio-wrench-symbolic",
        Icon::Add => "list-add-symbolic",
        Icon::Edit => "document-edit-symbolic",
        Icon::Reapply => "document-revert-symbolic",
        Icon::Delete => "user-trash-symbolic",
        Icon::Zap => "egrio-bolt-symbolic",
        Icon::Link => "insert-link-symbolic",
        Icon::Route => "egrio-route-symbolic",
        Icon::Refresh => "view-refresh-symbolic",
        Icon::ResetCount => "edit-undo-symbolic",
        Icon::Check => "object-select-symbolic",
    }
}

/// A symbolic icon of a tone at `size` pixels.
pub fn image(icon: Icon, tone: Tone, size: i32) -> gtk::Image {
    let image = gtk::Image::from_icon_name(icon_name(icon));
    image.set_pixel_size(size);
    set_tone(&image, tone);
    image
}
