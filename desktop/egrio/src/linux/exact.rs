//! A widget holding one child at an exact width, height or both, where the
//! interface fixes them. GTK gives a widget at least its size request and
//! up to its natural size, so a request alone only sets the least; this
//! widget reports the fixed size as both (`GtkWidgetClass.measure`).

use std::cell::Cell;

use gtk::glib;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct ExactSize {
        pub width: Cell<Option<i32>>,
        pub height: Cell<Option<i32>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ExactSize {
        const NAME: &'static str = "EgrioExactSize";
        type Type = super::ExactSize;
        type ParentType = gtk::Widget;
    }

    impl ObjectImpl for ExactSize {
        fn dispose(&self) {
            while let Some(child) = self.obj().first_child() {
                child.unparent();
            }
        }
    }

    impl WidgetImpl for ExactSize {
        fn request_mode(&self) -> gtk::SizeRequestMode {
            self.obj()
                .first_child()
                .map_or(gtk::SizeRequestMode::ConstantSize, |child| {
                    child.request_mode()
                })
        }

        fn measure(&self, orientation: gtk::Orientation, for_size: i32) -> (i32, i32, i32, i32) {
            let (fixed, across) = match orientation {
                gtk::Orientation::Horizontal => (self.width.get(), self.height.get()),
                _ => (self.height.get(), self.width.get()),
            };
            if let Some(size) = fixed {
                return (size, size, -1, -1);
            }
            let for_size = if for_size < 0 {
                across.unwrap_or(-1)
            } else {
                for_size
            };
            match self.obj().first_child() {
                Some(child) => {
                    let (minimum, natural, _, _) = child.measure(orientation, for_size);
                    (minimum, natural, -1, -1)
                }
                None => (0, 0, -1, -1),
            }
        }

        fn size_allocate(&self, width: i32, height: i32, baseline: i32) {
            let Some(child) = self.obj().first_child() else {
                return;
            };
            // Never below what the child needs: a fixed size smaller than
            // its content lets it overflow rather than draw it squeezed.
            let (least_width, ..) = child.measure(gtk::Orientation::Horizontal, -1);
            let width = width.max(least_width);
            let (least_height, ..) = child.measure(gtk::Orientation::Vertical, width);
            child.allocate(width, height.max(least_height), baseline, None);
        }
    }
}

glib::wrapper! {
    pub struct ExactSize(ObjectSubclass<imp::ExactSize>)
        @extends gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl ExactSize {
    pub fn new(child: &impl IsA<gtk::Widget>) -> Self {
        let exact: Self = glib::Object::new();
        child.set_parent(&exact);
        exact
    }

    /// The fixed width and height, in logical pixels; `None` follows the child.
    pub fn set_size(&self, width: Option<f64>, height: Option<f64>) {
        let imp = self.imp();
        let round = |value: Option<f64>| value.map(|value| value.round() as i32);
        if imp.width.replace(round(width)) != round(width)
            || imp.height.replace(round(height)) != round(height)
        {
            self.queue_resize();
        }
    }
}
