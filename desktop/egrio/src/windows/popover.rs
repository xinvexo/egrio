//! A button that opens a flyout beside it, holding the popover's one child.
//! The flyout closes when the user clicks elsewhere or presses Esc, which
//! WinUI does itself ("Flyouts").

use windows_core::{Interface, Result};

use egrio_ui::node::{Popover, TextStyle, Tone};

use super::bindings::{
    AutomationProperties, Border, Button, Flyout, FlyoutPlacementMode, FontIcon, IButton,
    IContentControl, IControl, IFlyout, IFlyoutBase, IUIElement, Orientation, StackPanel,
    TextBlock, UIElement, Visibility,
};
use super::xaml::{self, Element};

pub struct PopoverParts {
    pub button: Button,
    icon: FontIcon,
    label: TextBlock,
    host: Border,
    /// What the button opens, which a disabled popover closes.
    flyout: Flyout,
}

impl PopoverParts {
    pub fn new(props: &Popover) -> Result<Self> {
        let button = Button::new()?;
        let content = StackPanel::new()?;
        content.SetOrientation(Orientation::Horizontal)?;
        content.SetSpacing(8.0)?;
        let icon = FontIcon::new()?;
        icon.fe()
            .SetStyle(&xaml::icon_style(Tone::Default, 14.0)?)?;
        let label = super::widgets::label("", TextStyle::Body, Tone::Default)?;
        content
            .panel()
            .Children()?
            .Append(&icon.cast::<UIElement>()?)?;
        content
            .panel()
            .Children()?
            .Append(&label.cast::<UIElement>()?)?;
        button.cast::<IContentControl>()?.SetContent(&content)?;
        let host = Border::new()?;
        host.SetPadding(xaml::uniform(4.0))?;
        let flyout = Flyout::new()?;
        flyout.cast::<IFlyout>()?.SetContent(&host)?;
        flyout
            .cast::<IFlyoutBase>()?
            .SetPlacement(FlyoutPlacementMode::BottomEdgeAlignedRight)?;
        button.cast::<IButton>()?.SetFlyout(&flyout)?;
        let parts = Self {
            button,
            icon,
            label,
            host,
            flyout,
        };
        parts.update(props)?;
        Ok(parts)
    }

    pub fn update(&self, props: &Popover) -> Result<()> {
        self.button
            .cast::<IControl>()?
            .SetIsEnabled(props.enabled)?;
        // A button that can no longer be pressed cannot be left open.
        if !props.enabled {
            self.flyout.cast::<IFlyoutBase>()?.Hide()?;
        }
        self.label.SetText(&props.label)?;
        AutomationProperties::SetName(&self.button, &props.label)?;
        match props.icon {
            Some(icon) => {
                self.icon.SetGlyph(xaml::glyph(icon))?;
                self.icon
                    .cast::<IUIElement>()?
                    .SetVisibility(Visibility::Visible)
            }
            None => self
                .icon
                .cast::<IUIElement>()?
                .SetVisibility(Visibility::Collapsed),
        }
    }

    pub fn set_content(&self, element: &UIElement) -> Result<()> {
        self.host.SetChild(element)
    }

    pub fn clear_content(&self) -> Result<()> {
        self.host.SetChild(None::<&UIElement>)
    }
}
