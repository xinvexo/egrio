//! A dialog's keys: Return presses its default button through a keyboard
//! accelerator, pressed when its key goes down while focus is in the dialog
//! ("Keyboard accelerators"). Esc reaches the cancel button through the
//! dialog itself (`dialog.rs`), which answers Esc before any accelerator.

use windows_core::{Interface, Result};

use egrio_ui::node::ButtonKey;

use super::bindings::{IUIElement, KeyboardAccelerator, VirtualKey, VirtualKeyModifiers};

pub fn accelerator(button: &impl Interface, key: ButtonKey) -> Result<()> {
    if key != ButtonKey::Return {
        return Ok(());
    }
    let accelerator = KeyboardAccelerator::new()?;
    accelerator.SetKey(VirtualKey::Enter)?;
    accelerator.SetModifiers(VirtualKeyModifiers::None)?;
    button
        .cast::<IUIElement>()?
        .KeyboardAccelerators()?
        .Append(&accelerator)
}
