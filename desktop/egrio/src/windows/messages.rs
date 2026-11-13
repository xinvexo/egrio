//! The message capsule after the page title in the title bar, always there:
//! a small capsule with the bell and the number of messages, which keep one
//! glyph, size and place in every state, so nothing jumps. Its surface is the
//! message panel's (`window.rs`), which lies under the title bar's row at the
//! capsule's size while the panel is closed, so the capsule heads the panel,
//! which grows out of it and shrinks back into it as one surface. With unread
//! messages the capsule stays expanded into the free space before the
//! switches, tinted by the most severe of them (the info bar's background
//! brushes, as badges use) and showing the newest one cut to one line, until
//! they are read. A click, Enter or Space opens or closes the panel. The
//! button draws nothing of its own but a subtle button's surface under the
//! pointer, and only while the panel is closed, so the open panel's head is
//! never a band apart. Its width, tint and text move over a few frames of a
//! dispatcher timer, only into the free space.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

use windows_core::{EventRevoker, Interface, Result};

use egrio_ui::backend::{MessagesButton, ToolbarAction, UiEvent, DRAWER_WIDTH};
use egrio_ui::messages::Level;
use egrio_ui::node::{Icon, TextStyle, Tone};

use super::bindings::{
    AutomationProperties, Border, Button, ColumnDefinition, DispatcherQueue, DispatcherQueueTimer,
    FontIcon, FrameworkElement, Grid, HorizontalAlignment, IButtonBase, IContentControl, IControl,
    IPanel, Size, TextBlock, Thickness, ToolTipService, UIElement, VerticalAlignment,
};
use super::widgets::{check, label, Post};
use super::xaml::{self, Element};

/// The capsule's height, which is also the open panel's head.
pub const HEIGHT: f64 = 30.0;
/// The capsule's ends, the bell's width and the gaps inside it.
const PADDING: f64 = 10.0;
const BELL: f64 = 16.0;
const GAP: f64 = 6.0;
/// The least space left between the capsule and the switches.
const CLEARANCE: f64 = 16.0;
pub const DURATION: Duration = Duration::from_millis(250);
/// About one frame at 60 Hz.
pub const FRAME: i64 = 15;

/// How far along a move is after `progress` of its time: easing out, so the
/// capsule and its panel come to rest softly.
pub fn ease(progress: f64) -> f64 {
    1.0 - (1.0 - progress).powi(3)
}

/// What moves: the capsule's width and its tint's and text's opacity.
type Look = [f64; 3];

/// Where the capsule is going.
struct Motion {
    from: Look,
    to: Look,
    started: Instant,
}

struct State {
    button: Button,
    /// The subtle button's surface under the pointer.
    hover: Border,
    /// Unread messages' tint, which fades.
    tint: Border,
    bell: FontIcon,
    count: TextBlock,
    text: TextBlock,
    shown: RefCell<Option<MessagesButton>>,
    look: Cell<Look>,
    motion: RefCell<Option<Motion>>,
    timer: DispatcherQueueTimer,
    /// The pointer came over the capsule since the panel last opened or
    /// closed under it.
    hovered: Cell<bool>,
    /// How wide the capsule may grow before it comes near the switches.
    room: RefCell<Option<Box<dyn Fn() -> Option<f64>>>>,
    /// Gives the panel the capsule's width in the same frame, so their
    /// edges never part.
    widened: RefCell<Option<Box<dyn Fn(f64)>>>,
}

pub struct Capsule {
    state: Rc<State>,
    _events: Vec<EventRevoker>,
}

impl Capsule {
    pub fn new(post: Post) -> Result<Self> {
        // A button with no surface of its own and no pointer states, over
        // the panel's surface; the capsule draws the pointer's itself.
        let button: Button = xaml::load(
            "Button",
            "Background='Transparent' BorderThickness='0' Padding='0' \
             HorizontalContentAlignment='Stretch' VerticalContentAlignment='Stretch'",
            "<Button.Template><ControlTemplate TargetType='Button'>\
             <ContentPresenter Background='{TemplateBinding Background}' \
             CornerRadius='{TemplateBinding CornerRadius}' \
             Padding='{TemplateBinding Padding}' Content='{TemplateBinding Content}' \
             HorizontalContentAlignment='{TemplateBinding HorizontalContentAlignment}' \
             VerticalContentAlignment='{TemplateBinding VerticalContentAlignment}' \
             AutomationProperties.AccessibilityView='Raw'/>\
             </ControlTemplate></Button.Template>",
        )?;
        let control = button.cast::<IControl>()?;
        control.SetCornerRadius(xaml::corners(HEIGHT / 2.0))?;
        button.fe().SetHeight(HEIGHT)?;
        button.fe().SetMinWidth(0.0)?;
        button
            .fe()
            .SetVerticalAlignment(VerticalAlignment::Center)?;
        let compact = PADDING * 2.0 + BELL;
        button.fe().SetWidth(compact)?;

        let hover = Border::new()?;
        hover.SetCornerRadius(xaml::corners(HEIGHT / 2.0))?;
        let stack = Grid::new()?;
        let tint = Border::new()?;
        tint.SetCornerRadius(xaml::corners(HEIGHT / 2.0))?;
        tint.ui().SetOpacity(0.0)?;
        let line = Grid::new()?;
        line.SetPadding(Thickness {
            left: PADDING,
            top: 0.0,
            right: PADDING,
            bottom: 0.0,
        })?;
        for length in [xaml::pixels(BELL), xaml::auto(), xaml::star()] {
            let column = ColumnDefinition::new()?;
            column.SetWidth(length)?;
            line.ColumnDefinitions()?.Append(&column)?;
        }
        // One glyph, one size and place, whatever the capsule shows.
        let bell = FontIcon::new()?;
        bell.SetGlyph(xaml::glyph(Icon::Messages))?;
        bell.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
        bell.fe()
            .SetHorizontalAlignment(HorizontalAlignment::Center)?;
        let count = label("", TextStyle::Body, Tone::Muted)?;
        // A count that changes does not move the capsule's edge.
        xaml::tabular_figures(&count)?;
        count.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
        Grid::SetColumn(&count, 1)?;
        let text = label("", TextStyle::Body, Tone::Default)?;
        text.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
        text.fe().SetMargin(Thickness {
            left: GAP,
            top: 0.0,
            right: 0.0,
            bottom: 0.0,
        })?;
        text.ui().SetOpacity(0.0)?;
        Grid::SetColumn(&text, 2)?;
        for part in [
            bell.cast::<UIElement>()?,
            count.cast::<UIElement>()?,
            text.cast::<UIElement>()?,
        ] {
            line.cast::<IPanel>()?.Children()?.Append(&part)?;
        }
        stack
            .cast::<IPanel>()?
            .Children()?
            .Append(&tint.cast::<UIElement>()?)?;
        stack
            .cast::<IPanel>()?
            .Children()?
            .Append(&line.cast::<UIElement>()?)?;
        hover.SetChild(&stack)?;
        button.cast::<IContentControl>()?.SetContent(&hover)?;

        let timer = DispatcherQueue::GetForCurrentThread()?.CreateTimer()?;
        timer.SetInterval(windows_time::TimeSpan::from_millis(FRAME))?;
        timer.SetIsRepeating(true)?;
        let state = Rc::new(State {
            button: button.clone(),
            hover,
            tint,
            bell,
            count,
            text,
            shown: RefCell::new(None),
            look: Cell::new([compact, 0.0, 0.0]),
            motion: RefCell::new(None),
            timer: timer.clone(),
            hovered: Cell::new(false),
            room: RefCell::new(None),
            widened: RefCell::new(None),
        });
        let mut events = Vec::new();
        {
            let state = Rc::downgrade(&state);
            events.push(timer.Tick(move |_, _| {
                if let Some(state) = state.upgrade() {
                    state.step();
                }
            })?);
        }
        for entered in [true, false] {
            let state = Rc::downgrade(&state);
            let handler = move |_: windows_core::Ref<windows_core::IInspectable>,
                                _: windows_core::Ref<super::bindings::PointerRoutedEventArgs>| {
                if let Some(state) = state.upgrade() {
                    state.hovered.set(entered);
                    check(state.paint_hover(), "show the pointer over the capsule");
                }
            };
            events.push(if entered {
                button.ui().PointerEntered(handler)?
            } else {
                button.ui().PointerExited(handler)?
            });
        }
        events.push(
            button
                .cast::<IButtonBase>()?
                .Click(move |_, _| post(UiEvent::Toolbar(ToolbarAction::Messages)))?,
        );
        Ok(Self {
            state,
            _events: events,
        })
    }

    pub fn element(&self) -> FrameworkElement {
        self.state
            .button
            .cast()
            .expect("a button is a framework element")
    }

    /// Bounds the capsule's growth: `room` answers how wide it may get,
    /// once the window has laid it and the switches out.
    pub fn set_room(&self, room: impl Fn() -> Option<f64> + 'static) {
        *self.state.room.borrow_mut() = Some(Box::new(room));
    }

    /// Its width now, which moves while it widens or narrows.
    pub fn width(&self) -> f64 {
        self.state.look.get()[0].round()
    }

    /// Calls `widened` with the capsule's width each time it changes, in
    /// the frame it changes.
    pub fn on_width(&self, widened: impl Fn(f64) + 'static) {
        *self.state.widened.borrow_mut() = Some(Box::new(widened));
    }

    /// The open panel's width: the widest the capsule gets in the room it
    /// has.
    pub fn open_width(&self) -> f64 {
        let compact = self.state.compact_width().unwrap_or(PADDING * 2.0 + BELL);
        DRAWER_WIDTH.min(self.state.room_from(compact)).ceil()
    }

    /// Fits the capsule to the space it has, after the window changed size.
    pub fn fit(&self) {
        check(self.state.refresh(false), "fit the message capsule");
    }

    pub fn update(&self, shown: &MessagesButton) -> Result<()> {
        let toggled = match self.state.shown.borrow().as_ref() {
            Some(old) if old == shown => return Ok(()),
            Some(old) => old.open != shown.open,
            None => false,
        };
        // The panel opening or closing under the pointer leaves the
        // pointer's surface off until it comes over the capsule again.
        if toggled {
            self.state.hovered.set(false);
        }
        *self.state.shown.borrow_mut() = Some(shown.clone());
        self.state.refresh(true)
    }
}

/// Unread messages' tone while the panel is closed.
fn alert(shown: &MessagesButton) -> Option<Tone> {
    if shown.open || shown.preview.is_none() {
        return None;
    }
    Some(match shown.level {
        Some(Level::Error) => Tone::Danger,
        Some(Level::Warning) => Tone::Warning,
        Some(Level::Info) | None => Tone::Accent,
    })
}

impl State {
    fn room_from(&self, compact: f64) -> f64 {
        self.room
            .borrow()
            .as_ref()
            .and_then(|room| room())
            .map_or(f64::INFINITY, |room| room.max(compact))
    }

    /// The capsule with the bell and the count alone; the count's width
    /// takes in the gap before it, its margin.
    fn compact_width(&self) -> Result<f64> {
        let counted = self
            .shown
            .borrow()
            .as_ref()
            .is_some_and(|shown| shown.count > 0);
        let count_width = if counted {
            natural_width(&self.count)?
        } else {
            0.0
        };
        Ok(PADDING * 2.0 + BELL + count_width)
    }

    /// The subtle button's surface under the pointer, while the panel is
    /// closed and no unread message tints the capsule.
    fn paint_hover(&self) -> Result<()> {
        let shown = self.shown.borrow();
        let hovered = self.hovered.get()
            && shown
                .as_ref()
                .is_some_and(|shown| !shown.open && alert(shown).is_none());
        self.hover.fe().SetStyle(&xaml::style(
            "Border",
            None,
            &[(
                "Background",
                if hovered {
                    xaml::theme("SubtleFillColorSecondaryBrush")
                } else {
                    "Transparent".into()
                },
            )],
        )?)
    }

    /// Lays the capsule out for what it shows, moving it there when
    /// `animate`.
    fn refresh(&self, animate: bool) -> Result<()> {
        let Some(shown) = self.shown.borrow().clone() else {
            return Ok(());
        };
        let alert = alert(&shown);
        let tone = alert.unwrap_or(Tone::Muted);
        self.bell.fe().SetStyle(&xaml::icon_style(tone, 14.0)?)?;
        self.count
            .fe()
            .SetStyle(&xaml::text_style(TextStyle::Body, tone)?)?;
        self.count.SetText(&if shown.count > 0 {
            shown.count.to_string()
        } else {
            String::new()
        })?;
        self.count.fe().SetMargin(Thickness {
            left: if shown.count > 0 { GAP } else { 0.0 },
            top: 0.0,
            right: 0.0,
            bottom: 0.0,
        })?;
        // A cleared tint and text keep their color and words while they
        // fade out.
        let preview = shown.preview.as_ref().filter(|_| alert.is_some());
        if let Some(alert) = alert {
            self.tint.fe().SetStyle(&xaml::tone_surface(alert)?)?;
        }
        if let Some(preview) = preview {
            self.text.SetText(&preview.text)?;
        }
        self.paint_hover()?;
        let help = preview.map_or(shown.label.as_str(), |preview| preview.help.as_str());
        ToolTipService::SetToolTip(&self.button, &xaml::boxed(help)?)?;
        let mut name = vec![shown.label.clone()];
        if shown.count > 0 {
            name.push(shown.count.to_string());
        }
        name.extend(preview.map(|preview| preview.text.clone()));
        AutomationProperties::SetName(&self.button, &name.join(", "))?;

        let compact = self.compact_width()?;
        let room = self.room_from(compact);
        let width = if shown.open {
            DRAWER_WIDTH.min(room)
        } else if preview.is_some() {
            (compact + natural_width(&self.text)? + 2.0).min(room)
        } else {
            compact
        }
        .ceil();
        let shows = if alert.is_some() { 1.0 } else { 0.0 };
        self.move_to([width, shows, shows], animate)
    }

    fn move_to(&self, look: Look, animate: bool) -> Result<()> {
        let target = self.motion.borrow().as_ref().map(|motion| motion.to);
        if target.unwrap_or(self.look.get()) == look {
            return Ok(());
        }
        if !animate {
            *self.motion.borrow_mut() = None;
            self.timer.Stop()?;
            return self.show(look);
        }
        *self.motion.borrow_mut() = Some(Motion {
            from: self.look.get(),
            to: look,
            started: Instant::now(),
        });
        self.timer.Start()
    }

    /// One frame of the capsule's motion.
    fn step(&self) {
        let Some((from, to, started)) = self
            .motion
            .borrow()
            .as_ref()
            .map(|motion| (motion.from, motion.to, motion.started))
        else {
            check(self.timer.Stop(), "stop the capsule's motion");
            return;
        };
        let progress = (started.elapsed().as_secs_f64() / DURATION.as_secs_f64()).min(1.0);
        let eased = ease(progress);
        let look = std::array::from_fn(|index| from[index] + (to[index] - from[index]) * eased);
        check(self.show(look), "move the message capsule");
        if progress >= 1.0 {
            *self.motion.borrow_mut() = None;
            check(self.timer.Stop(), "stop the capsule's motion");
        }
    }

    fn show(&self, look: Look) -> Result<()> {
        self.look.set(look);
        let [width, tint, text] = look;
        self.button.fe().SetWidth(width.round())?;
        if let Some(widened) = self.widened.borrow().as_ref() {
            widened(width.round());
        }
        self.tint.ui().SetOpacity(tint)?;
        self.text.ui().SetOpacity(text)
    }
}

/// A text's width on one line with its margin, whatever room it has now.
fn natural_width(block: &TextBlock) -> Result<f64> {
    block.ui().Measure(Size {
        width: f32::INFINITY,
        height: f32::INFINITY,
    })?;
    Ok(f64::from(block.ui().DesiredSize()?.width))
}

/// How wide the capsule may grow: from its leading edge to `trailing`'s,
/// less the clearance, once both are laid out.
pub fn room_before(capsule: &FrameworkElement, trailing: &FrameworkElement) -> Option<f64> {
    let start = left_edge(capsule)?;
    let end = left_edge(trailing)?;
    (end > start).then(|| end - start - CLEARANCE)
}

fn left_edge(element: &FrameworkElement) -> Option<f64> {
    if element.ActualWidth().ok()? <= 0.0 {
        return None;
    }
    let bounds = element
        .ui()
        .TransformToVisual(None::<&UIElement>)
        .ok()?
        .TransformBounds(super::bindings::Rect {
            x: 0.0,
            y: 0.0,
            width: 1.0,
            height: 1.0,
        })
        .ok()?;
    Some(f64::from(bounds.x))
}
