//! The traffic chart: the chart's paths, which come in a 100 × 100 box, as
//! `Path` shapes scaled to the element's size, with dashed guides under the
//! wave. Each new chart (once per point) or new size rebuilds the four
//! geometries from path markup ("Move and draw commands syntax").

use std::cell::RefCell;
use std::fmt::Write;
use std::rc::Rc;

use windows_core::{EventRevoker, Interface, Result, HSTRING};

use egrio_ui::node::{Chart, Path, PathCommand};

use super::bindings::{
    FrameworkElement, Geometry, Grid, IPanel, IShape, PenLineCap, PenLineJoin, Rect,
    RectangleGeometry, TypeKind, TypeName, UIElement, XamlBindingHelper,
};
use super::xaml::{self, Element};

/// Guides across the chart, in its 100-high box.
const GUIDES: [f64; 3] = [28.0, 56.0, 84.0];

struct Shapes {
    download_area: super::bindings::Path,
    upload_area: super::bindings::Path,
    download_line: super::bindings::Path,
    upload_line: super::bindings::Path,
    guides: Vec<super::bindings::Path>,
}

pub struct ChartView {
    grid: Grid,
    chart: Rc<RefCell<Chart>>,
    shapes: Rc<Shapes>,
    _resized: EventRevoker,
}

fn shape(brush: &str, fill: bool) -> Result<super::bindings::Path> {
    let path = super::bindings::Path::new()?;
    let (property, thickness) = if fill {
        ("Fill", 0.0)
    } else {
        ("Stroke", 1.75)
    };
    path.fe().SetStyle(&xaml::style(
        "Path",
        None,
        &[
            (property, xaml::theme(brush)),
            // A fill takes the stroke's color at a fraction of its strength.
            ("Opacity", if fill { "0.14".into() } else { "1".into() }),
        ],
    )?)?;
    let shape = path.cast::<IShape>()?;
    shape.SetStrokeThickness(thickness)?;
    shape.SetStrokeLineJoin(PenLineJoin::Round)?;
    shape.SetStrokeStartLineCap(PenLineCap::Round)?;
    shape.SetStrokeEndLineCap(PenLineCap::Round)?;
    Ok(path)
}

impl ChartView {
    pub fn new(chart: Chart) -> Result<Self> {
        let grid = Grid::new()?;
        grid.fe().SetStyle(&xaml::style(
            "Grid",
            None,
            &[("Background", "Transparent".into())],
        )?)?;
        // The paths run past the edges so the wave enters and leaves
        // smoothly, so the chart draws only inside its own box.
        let clip = RectangleGeometry::new()?;
        grid.ui().SetClip(&clip)?;
        let guide_style = xaml::style(
            "Path",
            None,
            &[
                ("Stroke", xaml::theme("DividerStrokeColorDefaultBrush")),
                ("StrokeThickness", "0.75".into()),
                ("StrokeDashArray", "2 4".into()),
            ],
        )?;
        let guides = GUIDES
            .iter()
            .map(|_| {
                let guide = super::bindings::Path::new()?;
                guide.fe().SetStyle(&guide_style)?;
                Ok(guide)
            })
            .collect::<Result<Vec<_>>>()?;
        let shapes = Rc::new(Shapes {
            download_area: shape("AccentFillColorDefaultBrush", true)?,
            upload_area: shape("SystemFillColorSuccessBrush", true)?,
            download_line: shape("AccentFillColorDefaultBrush", false)?,
            upload_line: shape("SystemFillColorSuccessBrush", false)?,
            guides,
        });
        let children = grid.cast::<IPanel>()?.Children()?;
        for path in shapes.guides.iter().chain([
            &shapes.download_area,
            &shapes.upload_area,
            &shapes.download_line,
            &shapes.upload_line,
        ]) {
            children.Append(&path.cast::<UIElement>()?)?;
        }
        super::bindings::AutomationProperties::SetName(&grid, &chart.description)?;
        let chart = Rc::new(RefCell::new(chart));
        let resized = {
            let chart = chart.clone();
            let shapes = shapes.clone();
            xaml::framework(&grid)?.SizeChanged(move |_, args| {
                if let Some(size) = args.ok().ok().and_then(|args| args.NewSize().ok()) {
                    let size = (f64::from(size.width), f64::from(size.height));
                    super::widgets::check(
                        clip.SetRect(Rect {
                            x: 0.0,
                            y: 0.0,
                            width: size.0 as f32,
                            height: size.1 as f32,
                        }),
                        "clip the chart",
                    );
                    super::widgets::check(draw(&shapes, &chart.borrow(), size), "draw the chart");
                }
            })?
        };
        Ok(Self {
            grid,
            chart,
            shapes,
            _resized: resized,
        })
    }

    pub fn element(&self) -> FrameworkElement {
        self.grid.cast().expect("a grid is a framework element")
    }

    pub fn set_chart(&self, chart: Chart) -> Result<()> {
        // What it shows, for assistive technology.
        super::bindings::AutomationProperties::SetName(&self.grid, &chart.description)?;
        *self.chart.borrow_mut() = chart;
        let framework = xaml::framework(&self.grid)?;
        let size = (framework.ActualWidth()?, framework.ActualHeight()?);
        draw(&self.shapes, &self.chart.borrow(), size)
    }
}

fn draw(shapes: &Shapes, chart: &Chart, (width, height): (f64, f64)) -> Result<()> {
    if width <= 0.0 || height <= 0.0 {
        return Ok(());
    }
    for (guide, y) in shapes.guides.iter().zip(GUIDES) {
        let y = height * y / 100.0;
        guide.SetData(&geometry(&format!("M 0,{y:.1} L {width:.1},{y:.1}"))?)?;
    }
    for (path, data) in [
        (&shapes.download_area, &chart.download_area),
        (&shapes.upload_area, &chart.upload_area),
        (&shapes.download_line, &chart.download_line),
        (&shapes.upload_line, &chart.upload_line),
    ] {
        path.SetData(&geometry(&markup(data, width, height))?)?;
    }
    Ok(())
}

fn type_name(name: &str) -> TypeName {
    TypeName {
        name: HSTRING::from(name),
        kind: TypeKind::Metadata,
    }
}

fn geometry(markup: &str) -> Result<Geometry> {
    XamlBindingHelper::ConvertValue(
        &type_name("Microsoft.UI.Xaml.Media.Geometry"),
        &xaml::boxed(markup)?,
    )?
    .cast()
}

/// Path markup for `path` stretched from its 100 × 100 box to the size.
fn markup(path: &Path, width: f64, height: f64) -> String {
    let point = |(x, y): (f64, f64)| (width * x / 100.0, height * y / 100.0);
    let mut out = String::new();
    for command in &path.0 {
        match *command {
            PathCommand::Move(x, y) => {
                let (x, y) = point((x, y));
                let _ = write!(out, "M {x:.2},{y:.2} ");
            }
            PathCommand::Line(x, y) => {
                let (x, y) = point((x, y));
                let _ = write!(out, "L {x:.2},{y:.2} ");
            }
            PathCommand::Curve {
                control1,
                control2,
                to,
            } => {
                let (a, b, c) = (point(control1), point(control2), point(to));
                let _ = write!(
                    out,
                    "C {:.2},{:.2} {:.2},{:.2} {:.2},{:.2} ",
                    a.0, a.1, b.0, b.1, c.0, c.1
                );
            }
            PathCommand::Close => out.push_str("Z "),
        }
    }
    if out.is_empty() {
        // An empty geometry, so the shape draws nothing.
        out.push_str("M 0,0");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_scales_the_box_to_the_size() {
        let path = Path(vec![
            PathCommand::Move(0.0, 100.0),
            PathCommand::Line(50.0, 50.0),
            PathCommand::Close,
        ]);
        assert_eq!(markup(&path, 200.0, 40.0), "M 0.00,40.00 L 100.00,20.00 Z ");
    }
}
