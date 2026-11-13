//! The main window's title bar row. The window's content runs up under the
//! title bar and the system still draws the caption buttons; with no element
//! given to `Window.SetTitleBar`, WinUI's own drag region spans the window's
//! width at the tall title bar's height ("Title bar customization"). The
//! message capsule and the toolbar's controls in that row take pointer input
//! as passthrough regions of the window's non-client input, and the app icon
//! is its icon region, which opens the system menu
//! (`InputNonClientPointerSource.SetRegionRects`). The regions are in
//! physical pixels, so they are set again whenever the row or one of them
//! changes size or the display scale changes; a column as wide as the
//! caption buttons (`AppWindowTitleBar.RightInset`, also in physical pixels)
//! keeps the toolbar clear of them.

use std::cell::RefCell;
use std::rc::Rc;

use windows_core::{EventRevoker, Interface, Result};

use super::bindings::{
    AppWindow, ColumnDefinition, FrameworkElement, Grid, IWindow2, InputNonClientPointerSource,
    NonClientRegionKind, Rect, RectInt32, UIElement, Window,
};
use super::widgets::check;
use super::xaml::{self, Element};

struct Parts {
    app_window: AppWindow,
    source: InputNonClientPointerSource,
    bar: Grid,
    /// The column under the caption buttons.
    caption: ColumnDefinition,
    icon: FrameworkElement,
    interactive: Vec<FrameworkElement>,
}

/// Keeps the window's non-client regions on the title bar's icon and
/// interactive content for as long as it lives.
pub struct Regions {
    _events: Vec<EventRevoker>,
    /// The display scale's registration, made once the bar is in the window.
    _scale: Rc<RefCell<Option<EventRevoker>>>,
}

impl Regions {
    pub fn track(
        window: &Window,
        bar: &Grid,
        caption: &ColumnDefinition,
        icon: &FrameworkElement,
        interactive: &[FrameworkElement],
    ) -> Result<Self> {
        let app_window = window.cast::<IWindow2>()?.AppWindow()?;
        let source = InputNonClientPointerSource::GetForWindowId(app_window.Id()?)?;
        let parts = Rc::new(Parts {
            app_window,
            source,
            bar: bar.clone(),
            caption: caption.clone(),
            icon: icon.clone(),
            interactive: interactive.to_vec(),
        });
        let refresh = {
            let parts = parts.clone();
            move || check(parts.refresh(), "set the title bar's regions")
        };
        let scale = Rc::new(RefCell::new(None));
        let loaded = {
            let refresh = refresh.clone();
            let scale = scale.clone();
            bar.fe().Loaded(move |_, _| {
                refresh();
                // The scale changes when the window moves to another display.
                if scale.borrow().is_none() {
                    if let Ok(root) = parts.bar.ui().XamlRoot() {
                        let refresh = refresh.clone();
                        *scale.borrow_mut() = root.Changed(move |_, _| refresh()).ok();
                    }
                }
            })?
        };
        let mut events = vec![loaded];
        {
            let refresh = refresh.clone();
            events.push(bar.fe().SizeChanged(move |_, _| refresh())?);
        }
        for element in interactive {
            let refresh = refresh.clone();
            events.push(element.SizeChanged(move |_, _| refresh())?);
        }
        Ok(Self {
            _events: events,
            _scale: scale,
        })
    }
}

impl Parts {
    fn refresh(&self) -> Result<()> {
        // Not in the window yet: loading it refreshes.
        let Ok(root) = self.bar.ui().XamlRoot() else {
            return Ok(());
        };
        let scale = root.RasterizationScale()?;
        let inset = self.app_window.TitleBar()?.RightInset()?;
        self.caption
            .SetWidth(xaml::pixels(f64::from(inset) / scale))?;
        for (kind, elements) in [
            (
                NonClientRegionKind::Passthrough,
                self.interactive.as_slice(),
            ),
            (NonClientRegionKind::Icon, std::slice::from_ref(&self.icon)),
        ] {
            let mut rects = Vec::new();
            for element in elements {
                rects.extend(bounds(element, scale)?);
            }
            if rects.is_empty() {
                self.source.ClearRegionRects(kind)?;
            } else {
                self.source.SetRegionRects(kind, &rects)?;
            }
        }
        Ok(())
    }
}

/// An element's bounds in the window in physical pixels, while it has a size.
fn bounds(element: &FrameworkElement, scale: f64) -> Result<Option<RectInt32>> {
    let (width, height) = (element.ActualWidth()?, element.ActualHeight()?);
    if width <= 0.0 || height <= 0.0 {
        return Ok(None);
    }
    let rect = element
        .ui()
        .TransformToVisual(None::<&UIElement>)?
        .TransformBounds(Rect {
            x: 0.0,
            y: 0.0,
            width: width as f32,
            height: height as f32,
        })?;
    let pixels = |value: f32| (f64::from(value) * scale).round() as i32;
    Ok(Some(RectInt32 {
        x: pixels(rect.x),
        y: pixels(rect.y),
        width: pixels(rect.width),
        height: pixels(rect.height),
    }))
}
