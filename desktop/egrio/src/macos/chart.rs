//! The traffic chart's view: it strokes and fills the chart's paths, which
//! come in a 100 × 100 box, stretched to its bounds. It redraws only when a
//! new chart arrives, once per point.

use std::cell::RefCell;

use objc2::rc::Retained;
use objc2::runtime::NSObjectProtocol;
use objc2::{define_class, msg_send, DeclaredClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAccessibility, NSBezierPath, NSColor, NSLineCapStyle, NSLineJoinStyle, NSView,
};
use objc2_foundation::{NSPoint, NSRect, NSString};

use egrio_ui::node::{Chart, Path, PathCommand};

pub struct ChartIvars {
    chart: RefCell<Chart>,
}

define_class!(
    #[unsafe(super(NSView))]
    #[name = "EgrioChartView"]
    #[thread_kind = MainThreadOnly]
    #[ivars = ChartIvars]
    pub struct ChartView;

    unsafe impl NSObjectProtocol for ChartView {}

    impl ChartView {
        #[unsafe(method(isFlipped))]
        fn is_flipped(&self) -> bool {
            true
        }

        #[unsafe(method(drawRect:))]
        fn draw_rect(&self, _dirty: NSRect) {
            let bounds = self.bounds();
            // Paths run past the edges so the wave enters and leaves smoothly.
            NSBezierPath::clipRect(bounds);
            let chart = self.ivars().chart.borrow();
            // Soft guides under the wave.
            let guide = NSColor::separatorColor();
            guide.setStroke();
            for y in [28.0, 56.0, 84.0] {
                let line = NSBezierPath::bezierPath();
                let y = bounds.size.height * y / 100.0;
                line.moveToPoint(NSPoint { x: 0.0, y });
                line.lineToPoint(NSPoint { x: bounds.size.width, y });
                line.setLineWidth(0.75);
                let pattern = [1.5, 3.0];
                unsafe { line.setLineDash_count_phase(pattern.as_ptr(), 2, 0.0) };
                line.stroke();
            }
            let accent = NSColor::controlAccentColor();
            let green = NSColor::systemGreenColor();
            fill(&chart.download_area, bounds, &accent.colorWithAlphaComponent(0.12));
            fill(&chart.upload_area, bounds, &green.colorWithAlphaComponent(0.10));
            stroke(&chart.download_line, bounds, &accent);
            stroke(&chart.upload_line, bounds, &green);
        }
    }
);

impl ChartView {
    pub fn new(mtm: MainThreadMarker, chart: Chart) -> Retained<Self> {
        let description = chart.description.clone();
        let this = Self::alloc(mtm).set_ivars(ChartIvars {
            chart: RefCell::new(chart),
        });
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        this.setAccessibilityLabel(Some(&NSString::from_str(&description)));
        this
    }

    pub fn set_chart(&self, chart: Chart) {
        self.setAccessibilityLabel(Some(&NSString::from_str(&chart.description)));
        *self.ivars().chart.borrow_mut() = chart;
        self.setNeedsDisplay(true);
    }
}

fn bezier(path: &Path, bounds: NSRect) -> Option<Retained<NSBezierPath>> {
    if path.0.is_empty() {
        return None;
    }
    let scale = |(x, y): (f64, f64)| NSPoint {
        x: bounds.size.width * x / 100.0,
        y: bounds.size.height * y / 100.0,
    };
    let bezier = NSBezierPath::bezierPath();
    for command in &path.0 {
        match *command {
            PathCommand::Move(x, y) => bezier.moveToPoint(scale((x, y))),
            PathCommand::Line(x, y) => bezier.lineToPoint(scale((x, y))),
            PathCommand::Curve {
                control1,
                control2,
                to,
            } => bezier.curveToPoint_controlPoint1_controlPoint2(
                scale(to),
                scale(control1),
                scale(control2),
            ),
            PathCommand::Close => bezier.closePath(),
        }
    }
    Some(bezier)
}

fn fill(path: &Path, bounds: NSRect, color: &NSColor) {
    if let Some(bezier) = bezier(path, bounds) {
        color.setFill();
        bezier.fill();
    }
}

fn stroke(path: &Path, bounds: NSRect, color: &NSColor) {
    if let Some(bezier) = bezier(path, bounds) {
        color.setStroke();
        bezier.setLineWidth(1.75);
        bezier.setLineCapStyle(NSLineCapStyle::Round);
        bezier.setLineJoinStyle(NSLineJoinStyle::Round);
        bezier.stroke();
    }
}
