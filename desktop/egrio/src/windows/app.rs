//! The WinUI application object. WinUI needs one `Application` per process,
//! created inside `Application::Start`'s callback; Egrio composes it (the
//! WinRT aggregation an app's `App` class uses in XAML projects) to receive
//! `OnLaunched` and to give XAML the WinUI controls' type information
//! through `IXamlMetadataProvider`, which the generated code of a XAML
//! project would provide. The controls' theme resources come from
//! `XamlControlsResources`, merged into the application's resources as
//! `App.xaml` does, with Egrio's overrides of them merged after it.

use std::cell::RefCell;

use windows_core::{implement, Interface, Ref, Result, HSTRING};

use super::bindings::{
    Application, DispatcherShutdownMode, IApplication3, IApplicationOverrides,
    IApplicationOverrides_Impl, IXamlMetadataProvider, IXamlMetadataProvider_Impl, IXamlType,
    LaunchActivatedEventArgs, ResourceDictionary, TypeName, XamlControlsResources,
    XamlControlsXamlMetaDataProvider, XmlnsDefinition,
};

#[implement(IApplicationOverrides, IXamlMetadataProvider)]
struct EgrioApplication {
    provider: RefCell<Option<IXamlMetadataProvider>>,
    launched: RefCell<Option<Box<dyn FnOnce()>>>,
}

impl EgrioApplication {
    fn provider(&self) -> Result<IXamlMetadataProvider> {
        if let Some(provider) = self.provider.borrow().as_ref() {
            return Ok(provider.clone());
        }
        let provider: IXamlMetadataProvider = XamlControlsXamlMetaDataProvider::new()?.cast()?;
        *self.provider.borrow_mut() = Some(provider.clone());
        Ok(provider)
    }
}

impl IApplicationOverrides_Impl for EgrioApplication_Impl {
    fn OnLaunched(&self, _args: Ref<LaunchActivatedEventArgs>) -> Result<()> {
        if let Some(launched) = self.launched.borrow_mut().take() {
            launched();
        }
        Ok(())
    }
}

impl IXamlMetadataProvider_Impl for EgrioApplication_Impl {
    fn GetXamlType(&self, r#type: &TypeName) -> Result<IXamlType> {
        self.provider()?.GetXamlType(r#type)
    }

    fn GetXamlTypeByFullName(&self, full_name: &HSTRING) -> Result<IXamlType> {
        self.provider()?
            .GetXamlTypeByFullName(&full_name.to_string_lossy())
    }

    fn GetXmlnsDefinitions(&self) -> Result<windows_core::Array<XmlnsDefinition>> {
        self.provider()?.GetXmlnsDefinitions()
    }
}

thread_local! {
    static APPLICATION: RefCell<Option<Application>> = const { RefCell::new(None) };
}

/// Runs WinUI on this thread until the application exits; `launched` runs
/// once the application is ready for windows.
pub fn run(launched: impl FnOnce() + 'static) -> Result<()> {
    let launched: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(Some(Box::new(launched)));
    Application::Start(&super::bindings::ApplicationInitializationCallback::new(
        move |_| {
            let Some(launched) = launched.borrow_mut().take() else {
                return;
            };
            let created = Application::compose(EgrioApplication {
                provider: RefCell::new(None),
                launched: RefCell::new(Some(Box::new(move || {
                    if let Err(error) = prepare() {
                        log::error!("WinUI resources: {error}");
                    }
                    launched();
                }))),
            });
            match created {
                Ok(application) => APPLICATION.with(|slot| *slot.borrow_mut() = Some(application)),
                Err(error) => log::error!("create the WinUI application: {error}"),
            }
        },
    ))
}

/// The theme resources Egrio sets over the controls' own: the page lies on
/// the window's backdrop beside the sidebar, as on macOS, not on the raised
/// layer a left navigation pane gives its content
/// (`NavigationView_themeresources.xaml`), and while a list's row is dragged
/// the other rows keep their size rather than shrinking to 95% (the list
/// items' `ListViewItemReorderTargetThemeScale`).
const OVERRIDES: &str = "\
    <SolidColorBrush x:Key='NavigationViewContentBackground' Color='Transparent'/>\
    <Thickness x:Key='NavigationViewContentGridBorderThickness'>0</Thickness>\
    <CornerRadius x:Key='NavigationViewContentGridCornerRadius'>0</CornerRadius>\
    <x:Double x:Key='ListViewItemReorderTargetThemeScale'>1</x:Double>";

/// The controls' resources, and an application that ends only when told,
/// not when its last window closes: the tray keeps the app running.
fn prepare() -> Result<()> {
    let application = Application::Current()?;
    let merged = application.Resources()?.MergedDictionaries()?;
    let resources: ResourceDictionary = XamlControlsResources::new()?.cast()?;
    merged.Append(&resources)?;
    // A later merged dictionary's keys win over an earlier one's.
    merged.Append(&super::xaml::load::<ResourceDictionary>(
        "ResourceDictionary",
        "",
        OVERRIDES,
    )?)?;
    application
        .cast::<IApplication3>()?
        .SetDispatcherShutdownMode(DispatcherShutdownMode::OnExplicitShutdown)
}

/// Ends the application's message loop; `run` then returns.
pub fn exit() {
    if let Err(error) = Application::Current().and_then(|application| application.Exit()) {
        log::error!("exit the WinUI application: {error}");
        std::process::exit(0);
    }
}
