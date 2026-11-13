//! The traffic chart: the chart's paths, which come in a 100 × 100 box,
//! stretched to a `GtkDrawingArea` and drawn with cairo over dashed guides;
//! each area takes its line's color at a fraction of its strength. The
//! colors come from two pens, empty widgets with libadwaita's `accent` and
//! `success` classes, so the chart follows the light and dark looks.

use std::cell::RefCell;
use std::rc::Rc;

use gtk::cairo;
use gtk::prelude::*;

use egrio_ui::node::{Chart, Path, PathCommand};

/// Guides across the chart, in its 100-high box.
const GUIDES: [f64; 3] = [28.0, 56.0, 84.0];
const LINE_WIDTH: f64 = 1.75;
/// How strongly an area takes its line's color.
const AREA_ALPHA: f64 = 0.14;

pub struct ChartView {
    root: gtk::Overlay,
    area: gtk::DrawingArea,
    chart: Rc<RefCell<Chart>>,
}

fn pen(class: &str) -> gtk::Box {
    let pen = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    pen.add_css_class(class);
    pen.set_can_target(false);
    pen.set_halign(gtk::Align::Start);
    pen.set_valign(gtk::Align::Start);
    pen
}

impl ChartView {
    pub fn new(chart: Chart) -> Self {
        let area = gtk::DrawingArea::new();
        area.set_hexpand(true);
        area.set_vexpand(true);
        let download = pen("accent");
        let upload = pen("success");
        let root = gtk::Overlay::new();
        root.set_child(Some(&area));
        root.add_overlay(&download);
        root.add_overlay(&upload);
        let chart = Rc::new(RefCell::new(chart));
        {
            let chart = chart.clone();
            area.set_draw_func(move |area, context, width, height| {
                let colors = Colors {
                    download: download.color(),
                    upload: upload.color(),
                    guide: area.color(),
                };
                draw(
                    context,
                    f64::from(width),
                    f64::from(height),
                    &chart.borrow(),
                    &colors,
                );
            });
        }
        let view = Self { root, area, chart };
        view.describe();
        view
    }

    pub fn widget(&self) -> gtk::Widget {
        self.root.clone().upcast()
    }

    pub fn set_chart(&self, chart: Chart) {
        *self.chart.borrow_mut() = chart;
        self.describe();
        self.area.queue_draw();
    }

    /// What the chart shows, for assistive technologies.
    fn describe(&self) {
        self.area
            .update_property(&[gtk::accessible::Property::Label(
                &self.chart.borrow().description,
            )]);
    }
}

struct Colors {
    download: gtk::gdk::RGBA,
    upload: gtk::gdk::RGBA,
    guide: gtk::gdk::RGBA,
}

fn source(context: &cairo::Context, color: &gtk::gdk::RGBA, alpha: f64) {
    context.set_source_rgba(
        f64::from(color.red()),
        f64::from(color.green()),
        f64::from(color.blue()),
        f64::from(color.alpha()) * alpha,
    );
}

fn draw(context: &cairo::Context, width: f64, height: f64, chart: &Chart, colors: &Colors) {
    if width <= 0.0 || height <= 0.0 {
        return;
    }
    context.set_line_width(0.75);
    context.set_dash(&[2.0, 4.0], 0.0);
    source(context, &colors.guide, 0.18);
    for guide in GUIDES {
        let y = (height * guide / 100.0).round() + 0.5;
        context.move_to(0.0, y);
        context.line_to(width, y);
    }
    let _ = context.stroke();
    context.set_dash(&[], 0.0);
    for (path, color) in [
        (&chart.download_area, &colors.download),
        (&chart.upload_area, &colors.upload),
    ] {
        trace(context, path, width, height);
        source(context, color, AREA_ALPHA);
        let _ = context.fill();
    }
    context.set_line_width(LINE_WIDTH);
    context.set_line_join(cairo::LineJoin::Round);
    context.set_line_cap(cairo::LineCap::Round);
    for (path, color) in [
        (&chart.download_line, &colors.download),
        (&chart.upload_line, &colors.upload),
    ] {
        trace(context, path, width, height);
        source(context, color, 1.0);
        let _ = context.stroke();
    }
}

/// `path` stretched from its 100 × 100 box to the size, as the current path.
fn trace(context: &cairo::Context, path: &Path, width: f64, height: f64) {
    let point = |(x, y): (f64, f64)| (width * x / 100.0, height * y / 100.0);
    context.new_path();
    for command in &path.0 {
        match *command {
            PathCommand::Move(x, y) => {
                let (x, y) = point((x, y));
                context.move_to(x, y);
            }
            PathCommand::Line(x, y) => {
                let (x, y) = point((x, y));
                context.line_to(x, y);
            }
            PathCommand::Curve {
                control1,
                control2,
                to,
            } => {
                let (a, b, c) = (point(control1), point(control2), point(to));
                context.curve_to(a.0, a.1, b.0, b.1, c.0, c.1);
            }
            PathCommand::Close => context.close_path(),
        }
    }
}
