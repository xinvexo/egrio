windows_core::link!("user32.dll" "system" fn AppendMenuW(hmenu : HMENU, uflags : u32, uidnewitem : usize, lpnewitem : windows_core::PCWSTR) -> windows_core::BOOL);
windows_core::link!("ole32.dll" "system" fn CoInitializeEx(pvreserved : *const core::ffi::c_void, dwcoinit : u32) -> windows_core::HRESULT);
windows_core::link!("kernel32.dll" "system" fn ConnectNamedPipe(hnamedpipe : HANDLE, lpoverlapped : *mut OVERLAPPED) -> windows_core::BOOL);
windows_core::link!("advapi32.dll" "system" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(stringsecuritydescriptor : windows_core::PCWSTR, stringsdrevision : u32, securitydescriptor : *mut PSECURITY_DESCRIPTOR, securitydescriptorsize : *mut u32) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn CreateIconFromResourceEx(presbits : *const u8, dwressize : u32, ficon : windows_core::BOOL, dwver : u32, cxdesired : i32, cydesired : i32, flags : u32) -> HICON);
windows_core::link!("kernel32.dll" "system" fn CreateNamedPipeW(lpname : windows_core::PCWSTR, dwopenmode : u32, dwpipemode : u32, nmaxinstances : u32, noutbuffersize : u32, ninbuffersize : u32, ndefaulttimeout : u32, lpsecurityattributes : *const SECURITY_ATTRIBUTES) -> HANDLE);
windows_core::link!("user32.dll" "system" fn CreatePopupMenu() -> HMENU);
windows_core::link!("api-ms-win-shcore-stream-winrt-l1-1-0.dll" "system" fn CreateRandomAccessStreamOverStream(stream : *mut core::ffi::c_void, options : BSOS_OPTIONS, riid : *const windows_core::GUID, ppv : *mut *mut core::ffi::c_void) -> windows_core::HRESULT);
windows_core::link!("user32.dll" "system" fn CreateWindowExW(dwexstyle : u32, lpclassname : windows_core::PCWSTR, lpwindowname : windows_core::PCWSTR, dwstyle : u32, x : i32, y : i32, nwidth : i32, nheight : i32, hwndparent : HWND, hmenu : HMENU, hinstance : HINSTANCE, lpparam : *const core::ffi::c_void) -> HWND);
windows_core::link!("user32.dll" "system" fn DefWindowProcW(hwnd : HWND, msg : u32, wparam : WPARAM, lparam : LPARAM) -> LRESULT);
windows_core::link!("user32.dll" "system" fn DestroyIcon(hicon : HICON) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn DestroyMenu(hmenu : HMENU) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn DestroyWindow(hwnd : HWND) -> windows_core::BOOL);
windows_core::link!("kernel32.dll" "system" fn DisconnectNamedPipe(hnamedpipe : HANDLE) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn DispatchMessageW(lpmsg : *const MSG) -> LRESULT);
windows_core::link!("user32.dll" "system" fn GetCursorPos(lppoint : *mut POINT) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn GetDpiForSystem() -> u32);
windows_core::link!("user32.dll" "system" fn GetDpiForWindow(hwnd : HWND) -> u32);
windows_core::link!("user32.dll" "system" fn GetMenuItemCount(hmenu : HMENU) -> i32);
windows_core::link!("user32.dll" "system" fn GetMenuItemID(hmenu : HMENU, npos : i32) -> u32);
windows_core::link!("user32.dll" "system" fn GetMenuItemInfoW(hmenu : HMENU, item : u32, fbyposition : windows_core::BOOL, lpmii : *mut MENUITEMINFOW) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn GetMenuStringW(hmenu : HMENU, uiditem : u32, lpstring : windows_core::PWSTR, cchmax : i32, flags : u32) -> i32);
windows_core::link!("kernel32.dll" "system" fn GetModuleHandleW(lpmodulename : windows_core::PCWSTR) -> HMODULE);
windows_core::link!("kernel32.dll" "system" fn GetProcAddress(hmodule : HMODULE, lpprocname : windows_core::PCSTR) -> FARPROC);
windows_core::link!("user32.dll" "system" fn GetSubMenu(hmenu : HMENU, npos : i32) -> HMENU);
windows_core::link!("user32.dll" "system" fn GetSystemMetrics(nindex : i32) -> i32);
windows_core::link!("user32.dll" "system" fn GetSystemMetricsForDpi(nindex : i32, dpi : u32) -> i32);
windows_core::link!("user32.dll" "system" fn GetWindowPlacement(hwnd : HWND, lpwndpl : *mut WINDOWPLACEMENT) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn IsIconic(hwnd : HWND) -> windows_core::BOOL);
windows_core::link!("kernel32.dll" "system" fn LoadLibraryExW(lplibfilename : windows_core::PCWSTR, hfile : HANDLE, dwflags : u32) -> HMODULE);
windows_core::link!("kernel32.dll" "system" fn LocalFree(hmem : HLOCAL) -> HLOCAL);
windows_core::link!("user32.dll" "system" fn LookupIconIdFromDirectoryEx(presbits : *const u8, ficon : windows_core::BOOL, cxdesired : i32, cydesired : i32, flags : u32) -> i32);
windows_core::link!("user32.dll" "system" fn MessageBoxW(hwnd : HWND, lptext : windows_core::PCWSTR, lpcaption : windows_core::PCWSTR, utype : u32) -> i32);
windows_core::link!("user32.dll" "system" fn MsgWaitForMultipleObjects(ncount : u32, phandles : *const HANDLE, fwaitall : windows_core::BOOL, dwmilliseconds : u32, dwwakemask : u32) -> u32);
windows_core::link!("user32.dll" "system" fn PeekMessageW(lpmsg : *mut MSG, hwnd : HWND, wmsgfiltermin : u32, wmsgfiltermax : u32, wremovemsg : u32) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn PostMessageW(hwnd : HWND, msg : u32, wparam : WPARAM, lparam : LPARAM) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn RegisterClassExW(param0 : *const WNDCLASSEXW) -> ATOM);
windows_core::link!("user32.dll" "system" fn RegisterWindowMessageW(lpstring : windows_core::PCWSTR) -> u32);
windows_core::link!("shlwapi.dll" "system" fn SHCreateMemStream(pinit : *const u8, cbinit : u32) -> Option < IStream >);
windows_core::link!("user32.dll" "system" fn SendMessageW(hwnd : HWND, msg : u32, wparam : WPARAM, lparam : LPARAM) -> LRESULT);
windows_core::link!("user32.dll" "system" fn SetForegroundWindow(hwnd : HWND) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn SetMenuItemInfoW(hmenu : HMENU, item : u32, fbypositon : windows_core::BOOL, lpmii : *const MENUITEMINFOW) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn SetProcessDpiAwarenessContext(value : DPI_AWARENESS_CONTEXT) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn SetWindowPlacement(hwnd : HWND, lpwndpl : *const WINDOWPLACEMENT) -> windows_core::BOOL);
windows_core::link!("shell32.dll" "system" fn ShellExecuteW(hwnd : HWND, lpoperation : windows_core::PCWSTR, lpfile : windows_core::PCWSTR, lpparameters : windows_core::PCWSTR, lpdirectory : windows_core::PCWSTR, nshowcmd : i32) -> HINSTANCE);
windows_core::link!("shell32.dll" "system" fn Shell_NotifyIconW(dwmessage : u32, lpdata : *const NOTIFYICONDATAW) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn ShowWindow(hwnd : HWND, ncmdshow : i32) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn TrackPopupMenuEx(hmenu : HMENU, uflags : u32, x : i32, y : i32, hwnd : HWND, lptpm : *const TPMPARAMS) -> windows_core::BOOL);
windows_core::link!("user32.dll" "system" fn TranslateMessage(lpmsg : *const MSG) -> windows_core::BOOL);
windows_core::link!("winmm.dll" "system" fn timeBeginPeriod(uperiod : u32) -> MMRESULT);
pub type ATOM = u16;
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppActivationArguments(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    AppActivationArguments,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for AppActivationArguments {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IAppActivationArguments>();
}
unsafe impl windows_core::Interface for AppActivationArguments {
    type Vtable = <IAppActivationArguments as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IAppActivationArguments as windows_core::Interface>::IID;
}
impl core::ops::Deref for AppActivationArguments {
    type Target = IAppActivationArguments;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for AppActivationArguments {
    const NAME: &'static str = "Microsoft.Windows.AppLifecycle.AppActivationArguments";
}
unsafe impl Send for AppActivationArguments {}
unsafe impl Sync for AppActivationArguments {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppInstance(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    AppInstance,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl AppInstance {
    pub fn GetCurrent() -> windows_core::Result<Self> {
        Self::IAppInstanceStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).GetCurrent)(
                windows_core::Interface::as_raw(this),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    pub fn FindOrRegisterForKey(key: &str) -> windows_core::Result<Self> {
        Self::IAppInstanceStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).FindOrRegisterForKey)(
                windows_core::Interface::as_raw(this),
                core::mem::transmute_copy(&windows_core::HSTRING::from(key)),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IAppInstanceStatics<R, F: FnOnce(&IAppInstanceStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<AppInstance, IAppInstanceStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for AppInstance {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IAppInstance>();
}
unsafe impl windows_core::Interface for AppInstance {
    type Vtable = <IAppInstance as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IAppInstance as windows_core::Interface>::IID;
}
impl core::ops::Deref for AppInstance {
    type Target = IAppInstance;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for AppInstance {
    const NAME: &'static str = "Microsoft.Windows.AppLifecycle.AppInstance";
}
unsafe impl Send for AppInstance {}
unsafe impl Sync for AppInstance {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppWindow(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    AppWindow,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for AppWindow {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IAppWindow>();
}
unsafe impl windows_core::Interface for AppWindow {
    type Vtable = <IAppWindow as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IAppWindow as windows_core::Interface>::IID;
}
impl core::ops::Deref for AppWindow {
    type Target = IAppWindow;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for AppWindow {
    const NAME: &'static str = "Microsoft.UI.Windowing.AppWindow";
}
unsafe impl Send for AppWindow {}
unsafe impl Sync for AppWindow {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppWindowClosingEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    AppWindowClosingEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for AppWindowClosingEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IAppWindowClosingEventArgs>();
}
unsafe impl windows_core::Interface for AppWindowClosingEventArgs {
    type Vtable = <IAppWindowClosingEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IAppWindowClosingEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for AppWindowClosingEventArgs {
    type Target = IAppWindowClosingEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for AppWindowClosingEventArgs {
    const NAME: &'static str = "Microsoft.UI.Windowing.AppWindowClosingEventArgs";
}
unsafe impl Send for AppWindowClosingEventArgs {}
unsafe impl Sync for AppWindowClosingEventArgs {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppWindowPresenter(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    AppWindowPresenter,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for AppWindowPresenter {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IAppWindowPresenter>();
}
unsafe impl windows_core::Interface for AppWindowPresenter {
    type Vtable = <IAppWindowPresenter as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IAppWindowPresenter as windows_core::Interface>::IID;
}
impl core::ops::Deref for AppWindowPresenter {
    type Target = IAppWindowPresenter;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for AppWindowPresenter {
    const NAME: &'static str = "Microsoft.UI.Windowing.AppWindowPresenter";
}
unsafe impl Send for AppWindowPresenter {}
unsafe impl Sync for AppWindowPresenter {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppWindowTitleBar(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    AppWindowTitleBar,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for AppWindowTitleBar {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IAppWindowTitleBar>();
}
unsafe impl windows_core::Interface for AppWindowTitleBar {
    type Vtable = <IAppWindowTitleBar as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IAppWindowTitleBar as windows_core::Interface>::IID;
}
impl core::ops::Deref for AppWindowTitleBar {
    type Target = IAppWindowTitleBar;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for AppWindowTitleBar {
    const NAME: &'static str = "Microsoft.UI.Windowing.AppWindowTitleBar";
}
unsafe impl Send for AppWindowTitleBar {}
unsafe impl Sync for AppWindowTitleBar {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Application(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    Application,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl Application {
    pub fn compose<T>(compose: T) -> windows_core::Result<Self>
    where
        T: windows_core::Compose,
    {
        Self::IApplicationFactory(|this| unsafe {
            let (derived__, base__) = windows_core::Compose::compose(compose);
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::mem::transmute_copy(&derived__),
                base__ as *mut _ as _,
                &mut result__,
            )
            .ok()?;
            let _ = &derived__;
            windows_core::imp::Type::from_abi(result__)
        })
    }
    pub fn Current() -> windows_core::Result<Self> {
        Self::IApplicationStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).Current)(
                windows_core::Interface::as_raw(this),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    pub fn Start<P0>(callback: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<ApplicationInitializationCallback>,
    {
        Self::IApplicationStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).Start)(
                windows_core::Interface::as_raw(this),
                callback.param().abi(),
            )
            .ok()
        })
    }
    fn IApplicationFactory<R, F: FnOnce(&IApplicationFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Application, IApplicationFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
    fn IApplicationStatics<R, F: FnOnce(&IApplicationStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Application, IApplicationStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Application {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IApplication>();
}
unsafe impl windows_core::Interface for Application {
    type Vtable = <IApplication as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IApplication as windows_core::Interface>::IID;
}
impl core::ops::Deref for Application {
    type Target = IApplication;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Application {
    const NAME: &'static str = "Microsoft.UI.Xaml.Application";
}
unsafe impl Send for Application {}
unsafe impl Sync for Application {}
windows_core::imp::define_interface!(
    ApplicationInitializationCallback,
    ApplicationInitializationCallback_Vtbl,
    0xd8eef1c9_1234_56f1_9963_45dd9c80a661
);
impl windows_core::RuntimeType for ApplicationInitializationCallback {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ApplicationInitializationCallback {
    pub fn new<F: Fn(windows_core::Ref<ApplicationInitializationCallbackParams>) + 'static>(
        invoke: F,
    ) -> Self {
        let com = windows_core::imp::DelegateBox::<Self, F>::new(
            &ApplicationInitializationCallbackBox::<F>::VTABLE,
            invoke,
        );
        unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
    }
}
#[repr(C)]
pub struct ApplicationInitializationCallback_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        p: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
struct ApplicationInitializationCallbackBox<
    F: Fn(windows_core::Ref<ApplicationInitializationCallbackParams>) + 'static,
>(core::marker::PhantomData<(fn() -> F,)>);
impl<F: Fn(windows_core::Ref<ApplicationInitializationCallbackParams>) + 'static>
    ApplicationInitializationCallbackBox<F>
{
    const VTABLE: ApplicationInitializationCallback_Vtbl = ApplicationInitializationCallback_Vtbl {
        base__:
            windows_core::IUnknown_Vtbl {
                QueryInterface: windows_core::imp::DelegateBox::<
                    ApplicationInitializationCallback,
                    F,
                >::QueryInterface,
                AddRef:
                    windows_core::imp::DelegateBox::<ApplicationInitializationCallback, F>::AddRef,
                Release:
                    windows_core::imp::DelegateBox::<ApplicationInitializationCallback, F>::Release,
            },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        p: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<ApplicationInitializationCallback, F>);
            (this.invoke)(core::mem::transmute_copy(&p));
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationInitializationCallbackParams(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ApplicationInitializationCallbackParams,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for ApplicationInitializationCallbackParams {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::for_class::<
        Self,
        IApplicationInitializationCallbackParams,
    >();
}
unsafe impl windows_core::Interface for ApplicationInitializationCallbackParams {
    type Vtable = <IApplicationInitializationCallbackParams as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <IApplicationInitializationCallbackParams as windows_core::Interface>::IID;
}
impl core::ops::Deref for ApplicationInitializationCallbackParams {
    type Target = IApplicationInitializationCallbackParams;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ApplicationInitializationCallbackParams {
    const NAME: &'static str = "Microsoft.UI.Xaml.ApplicationInitializationCallbackParams";
}
unsafe impl Send for ApplicationInitializationCallbackParams {}
unsafe impl Sync for ApplicationInitializationCallbackParams {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplicationTheme(pub i32);
impl ApplicationTheme {
    pub const Light: Self = Self(0);
    pub const Dark: Self = Self(1);
}
impl windows_core::imp::TypeKind for ApplicationTheme {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for ApplicationTheme {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.ApplicationTheme;i4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationProperties(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    AutomationProperties,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl AutomationProperties {
    pub fn SetName<P0>(element: P0, value: &str) -> windows_core::Result<()>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::IAutomationPropertiesStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetName)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                core::mem::transmute_copy(&windows_core::HSTRING::from(value)),
            )
            .ok()
        })
    }
    fn IAutomationPropertiesStatics<
        R,
        F: FnOnce(&IAutomationPropertiesStatics) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            AutomationProperties,
            IAutomationPropertiesStatics,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for AutomationProperties {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IAutomationProperties>();
}
unsafe impl windows_core::Interface for AutomationProperties {
    type Vtable = <IAutomationProperties as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IAutomationProperties as windows_core::Interface>::IID;
}
impl core::ops::Deref for AutomationProperties {
    type Target = IAutomationProperties;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for AutomationProperties {
    const NAME: &'static str = "Microsoft.UI.Xaml.Automation.AutomationProperties";
}
unsafe impl Send for AutomationProperties {}
unsafe impl Sync for AutomationProperties {}
pub const BSOS_DEFAULT: BSOS_OPTIONS = 0;
pub type BSOS_OPTIONS = i32;
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitmapImage(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    BitmapImage,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(BitmapImage, BitmapSource, ImageSource, DependencyObject);
impl BitmapImage {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            BitmapImage,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for BitmapImage {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IBitmapImage>();
}
unsafe impl windows_core::Interface for BitmapImage {
    type Vtable = <IBitmapImage as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IBitmapImage as windows_core::Interface>::IID;
}
impl core::ops::Deref for BitmapImage {
    type Target = IBitmapImage;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for BitmapImage {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.Imaging.BitmapImage";
}
unsafe impl Send for BitmapImage {}
unsafe impl Sync for BitmapImage {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitmapSource(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    BitmapSource,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(BitmapSource, ImageSource, DependencyObject);
impl windows_core::RuntimeType for BitmapSource {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IBitmapSource>();
}
unsafe impl windows_core::Interface for BitmapSource {
    type Vtable = <IBitmapSource as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IBitmapSource as windows_core::Interface>::IID;
}
impl core::ops::Deref for BitmapSource {
    type Target = IBitmapSource;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for BitmapSource {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.Imaging.BitmapSource";
}
unsafe impl Send for BitmapSource {}
unsafe impl Sync for BitmapSource {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Border(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Border, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Border, FrameworkElement, UIElement, DependencyObject);
impl Border {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Border, windows_core::imp::IGenericFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Border {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IBorder>();
}
unsafe impl windows_core::Interface for Border {
    type Vtable = <IBorder as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IBorder as windows_core::Interface>::IID;
}
impl core::ops::Deref for Border {
    type Target = IBorder;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Border {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Border";
}
unsafe impl Send for Border {}
unsafe impl Sync for Border {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Brush(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Brush, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Brush, DependencyObject);
impl windows_core::RuntimeType for Brush {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IBrush>();
}
unsafe impl windows_core::Interface for Brush {
    type Vtable = <IBrush as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IBrush as windows_core::Interface>::IID;
}
impl core::ops::Deref for Brush {
    type Target = IBrush;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Brush {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.Brush";
}
unsafe impl Send for Brush {}
unsafe impl Sync for Brush {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Button(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Button, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(
    Button,
    ButtonBase,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl Button {
    pub fn new() -> windows_core::Result<Self> {
        Self::IButtonFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IButtonFactory<R, F: FnOnce(&IButtonFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Button, IButtonFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Button {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IButton>();
}
unsafe impl windows_core::Interface for Button {
    type Vtable = <IButton as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IButton as windows_core::Interface>::IID;
}
impl core::ops::Deref for Button {
    type Target = IButton;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Button {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Button";
}
unsafe impl Send for Button {}
unsafe impl Sync for Button {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ButtonBase(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ButtonBase,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ButtonBase,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for ButtonBase {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IButtonBase>();
}
unsafe impl windows_core::Interface for ButtonBase {
    type Vtable = <IButtonBase as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IButtonBase as windows_core::Interface>::IID;
}
impl core::ops::Deref for ButtonBase {
    type Target = IButtonBase;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ButtonBase {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Primitives.ButtonBase";
}
unsafe impl Send for ButtonBase {}
unsafe impl Sync for ButtonBase {}
pub type COINIT = i32;
pub const COINIT_APARTMENTTHREADED: COINIT = 2;
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Canvas(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Canvas, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(
    Canvas,
    Panel,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl Canvas {
    pub fn new() -> windows_core::Result<Self> {
        Self::ICanvasFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn ICanvasFactory<R, F: FnOnce(&ICanvasFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Canvas, ICanvasFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Canvas {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ICanvas>();
}
unsafe impl windows_core::Interface for Canvas {
    type Vtable = <ICanvas as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ICanvas as windows_core::Interface>::IID;
}
impl core::ops::Deref for Canvas {
    type Target = ICanvas;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Canvas {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Canvas";
}
unsafe impl Send for Canvas {}
unsafe impl Sync for Canvas {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Color {
    pub a: u8,
    pub r: u8,
    pub g: u8,
    pub b: u8,
}
impl windows_core::imp::TypeKind for Color {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for Color {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"struct(Windows.UI.Color;u1;u1;u1;u1)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnDefinition(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ColumnDefinition,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(ColumnDefinition, DependencyObject);
impl ColumnDefinition {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            ColumnDefinition,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for ColumnDefinition {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IColumnDefinition>();
}
unsafe impl windows_core::Interface for ColumnDefinition {
    type Vtable = <IColumnDefinition as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IColumnDefinition as windows_core::Interface>::IID;
}
impl core::ops::Deref for ColumnDefinition {
    type Target = IColumnDefinition;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ColumnDefinition {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ColumnDefinition";
}
unsafe impl Send for ColumnDefinition {}
unsafe impl Sync for ColumnDefinition {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnDefinitionCollection(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ColumnDefinitionCollection,
    windows_core::IUnknown,
    windows_core::IInspectable,
    windows_collections::IVector<ColumnDefinition>
);
impl windows_core::RuntimeType for ColumnDefinitionCollection {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::for_class::<
        Self,
        windows_collections::IVector<ColumnDefinition>,
    >();
}
unsafe impl windows_core::Interface for ColumnDefinitionCollection {
    type Vtable =
        <windows_collections::IVector<ColumnDefinition> as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <windows_collections::IVector<ColumnDefinition> as windows_core::Interface>::IID;
}
impl core::ops::Deref for ColumnDefinitionCollection {
    type Target = windows_collections::IVector<ColumnDefinition>;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ColumnDefinitionCollection {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ColumnDefinitionCollection";
}
unsafe impl Send for ColumnDefinitionCollection {}
unsafe impl Sync for ColumnDefinitionCollection {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComboBox(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ComboBox,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ComboBox,
    Selector,
    ItemsControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl ComboBox {
    pub fn new() -> windows_core::Result<Self> {
        Self::IComboBoxFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IComboBoxFactory<R, F: FnOnce(&IComboBoxFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<ComboBox, IComboBoxFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for ComboBox {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IComboBox>();
}
unsafe impl windows_core::Interface for ComboBox {
    type Vtable = <IComboBox as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IComboBox as windows_core::Interface>::IID;
}
impl core::ops::Deref for ComboBox {
    type Target = IComboBox;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ComboBox {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ComboBox";
}
unsafe impl Send for ComboBox {}
unsafe impl Sync for ComboBox {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerContentChangingEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ContainerContentChangingEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for ContainerContentChangingEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IContainerContentChangingEventArgs>();
}
unsafe impl windows_core::Interface for ContainerContentChangingEventArgs {
    type Vtable = <IContainerContentChangingEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <IContainerContentChangingEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for ContainerContentChangingEventArgs {
    type Target = IContainerContentChangingEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ContainerContentChangingEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ContainerContentChangingEventArgs";
}
unsafe impl Send for ContainerContentChangingEventArgs {}
unsafe impl Sync for ContainerContentChangingEventArgs {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentControl(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ContentControl,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for ContentControl {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IContentControl>();
}
unsafe impl windows_core::Interface for ContentControl {
    type Vtable = <IContentControl as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IContentControl as windows_core::Interface>::IID;
}
impl core::ops::Deref for ContentControl {
    type Target = IContentControl;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ContentControl {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ContentControl";
}
unsafe impl Send for ContentControl {}
unsafe impl Sync for ContentControl {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentDialog(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ContentDialog,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ContentDialog,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl ContentDialog {
    pub fn new() -> windows_core::Result<Self> {
        Self::IContentDialogFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IContentDialogFactory<R, F: FnOnce(&IContentDialogFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<ContentDialog, IContentDialogFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for ContentDialog {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IContentDialog>();
}
unsafe impl windows_core::Interface for ContentDialog {
    type Vtable = <IContentDialog as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IContentDialog as windows_core::Interface>::IID;
}
impl core::ops::Deref for ContentDialog {
    type Target = IContentDialog;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ContentDialog {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ContentDialog";
}
unsafe impl Send for ContentDialog {}
unsafe impl Sync for ContentDialog {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentDialogClosingEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ContentDialogClosingEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for ContentDialogClosingEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IContentDialogClosingEventArgs>();
}
unsafe impl windows_core::Interface for ContentDialogClosingEventArgs {
    type Vtable = <IContentDialogClosingEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <IContentDialogClosingEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for ContentDialogClosingEventArgs {
    type Target = IContentDialogClosingEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ContentDialogClosingEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ContentDialogClosingEventArgs";
}
unsafe impl Send for ContentDialogClosingEventArgs {}
unsafe impl Sync for ContentDialogClosingEventArgs {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContentDialogResult(pub i32);
impl ContentDialogResult {
    pub const None: Self = Self(0);
    pub const Primary: Self = Self(1);
    pub const Secondary: Self = Self(2);
}
impl windows_core::imp::TypeKind for ContentDialogResult {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for ContentDialogResult {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.Controls.ContentDialogResult;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Control(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    Control,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(Control, FrameworkElement, UIElement, DependencyObject);
impl windows_core::RuntimeType for Control {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IControl>();
}
unsafe impl windows_core::Interface for Control {
    type Vtable = <IControl as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IControl as windows_core::Interface>::IID;
}
impl core::ops::Deref for Control {
    type Target = IControl;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Control {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Control";
}
unsafe impl Send for Control {}
unsafe impl Sync for Control {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CornerRadius {
    pub top_left: f64,
    pub top_right: f64,
    pub bottom_right: f64,
    pub bottom_left: f64,
}
impl windows_core::imp::TypeKind for CornerRadius {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for CornerRadius {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"struct(Microsoft.UI.Xaml.CornerRadius;f8;f8;f8;f8)",
    );
}
pub struct CryptographicBuffer;
impl CryptographicBuffer {
    pub fn CopyToByteArray<P0>(
        buffer: P0,
        value: &mut windows_core::Array<u8>,
    ) -> windows_core::Result<()>
    where
        P0: windows_core::Param<IBuffer>,
    {
        Self::ICryptographicBufferStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).CopyToByteArray)(
                windows_core::Interface::as_raw(this),
                buffer.param().abi(),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        })
    }
    fn ICryptographicBufferStatics<
        R,
        F: FnOnce(&ICryptographicBufferStatics) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            CryptographicBuffer,
            ICryptographicBufferStatics,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeName for CryptographicBuffer {
    const NAME: &'static str = "Windows.Security.Cryptography.CryptographicBuffer";
}
pub type DPI_AWARENESS_CONTEXT = *mut core::ffi::c_void;
pub const DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2: DPI_AWARENESS_CONTEXT = -4 as _;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DataPackageOperation(pub u32);
impl DataPackageOperation {
    pub const None: Self = Self(0);
    pub const Move: Self = Self(2);
}
impl windows_core::imp::TypeKind for DataPackageOperation {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for DataPackageOperation {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Windows.ApplicationModel.DataTransfer.DataPackageOperation;u4)",
    );
}
impl DataPackageOperation {
    pub const fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}
impl core::ops::BitOr for DataPackageOperation {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl core::ops::BitAnd for DataPackageOperation {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}
impl core::ops::BitOrAssign for DataPackageOperation {
    fn bitor_assign(&mut self, other: Self) {
        self.0.bitor_assign(other.0);
    }
}
impl core::ops::BitAndAssign for DataPackageOperation {
    fn bitand_assign(&mut self, other: Self) {
        self.0.bitand_assign(other.0);
    }
}
impl core::ops::Not for DataPackageOperation {
    type Output = Self;
    fn not(self) -> Self {
        Self(self.0.not())
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataTemplate(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    DataTemplate,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(DataTemplate, FrameworkTemplate, DependencyObject);
impl windows_core::RuntimeType for DataTemplate {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IDataTemplate>();
}
unsafe impl windows_core::Interface for DataTemplate {
    type Vtable = <IDataTemplate as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IDataTemplate as windows_core::Interface>::IID;
}
impl core::ops::Deref for DataTemplate {
    type Target = IDataTemplate;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for DataTemplate {
    const NAME: &'static str = "Microsoft.UI.Xaml.DataTemplate";
}
unsafe impl Send for DataTemplate {}
unsafe impl Sync for DataTemplate {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyObject(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    DependencyObject,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for DependencyObject {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IDependencyObject>();
}
unsafe impl windows_core::Interface for DependencyObject {
    type Vtable = <IDependencyObject as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IDependencyObject as windows_core::Interface>::IID;
}
impl core::ops::Deref for DependencyObject {
    type Target = IDependencyObject;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for DependencyObject {
    const NAME: &'static str = "Microsoft.UI.Xaml.DependencyObject";
}
unsafe impl Send for DependencyObject {}
unsafe impl Sync for DependencyObject {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatcherQueue(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    DispatcherQueue,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl DispatcherQueue {
    pub fn GetForCurrentThread() -> windows_core::Result<Self> {
        Self::IDispatcherQueueStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).GetForCurrentThread)(
                windows_core::Interface::as_raw(this),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IDispatcherQueueStatics<
        R,
        F: FnOnce(&IDispatcherQueueStatics) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<DispatcherQueue, IDispatcherQueueStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for DispatcherQueue {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IDispatcherQueue>();
}
unsafe impl windows_core::Interface for DispatcherQueue {
    type Vtable = <IDispatcherQueue as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IDispatcherQueue as windows_core::Interface>::IID;
}
impl core::ops::Deref for DispatcherQueue {
    type Target = IDispatcherQueue;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for DispatcherQueue {
    const NAME: &'static str = "Microsoft.UI.Dispatching.DispatcherQueue";
}
unsafe impl Send for DispatcherQueue {}
unsafe impl Sync for DispatcherQueue {}
windows_core::imp::define_interface!(
    DispatcherQueueHandler,
    DispatcherQueueHandler_Vtbl,
    0x2e0872a9_4e29_5f14_b688_fb96d5f9d5f8
);
impl windows_core::RuntimeType for DispatcherQueueHandler {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl DispatcherQueueHandler {
    pub fn new<F: Fn() + 'static>(invoke: F) -> Self {
        let com = windows_core::imp::DelegateBox::<Self, F>::new(
            &DispatcherQueueHandlerBox::<F>::VTABLE,
            invoke,
        );
        unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
    }
}
#[repr(C)]
pub struct DispatcherQueueHandler_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(this: *mut core::ffi::c_void) -> windows_core::HRESULT,
}
struct DispatcherQueueHandlerBox<F: Fn() + 'static>(core::marker::PhantomData<(fn() -> F,)>);
impl<F: Fn() + 'static> DispatcherQueueHandlerBox<F> {
    const VTABLE: DispatcherQueueHandler_Vtbl = DispatcherQueueHandler_Vtbl {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface:
                windows_core::imp::DelegateBox::<DispatcherQueueHandler, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<DispatcherQueueHandler, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<DispatcherQueueHandler, F>::Release,
        },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(this: *mut core::ffi::c_void) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<DispatcherQueueHandler, F>);
            (this.invoke)();
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatcherQueuePriority(pub i32);
impl DispatcherQueuePriority {
    pub const Low: Self = Self(-10);
    pub const Normal: Self = Self(0);
    pub const High: Self = Self(10);
}
impl windows_core::imp::TypeKind for DispatcherQueuePriority {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for DispatcherQueuePriority {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Dispatching.DispatcherQueuePriority;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatcherQueueTimer(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    DispatcherQueueTimer,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for DispatcherQueueTimer {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IDispatcherQueueTimer>();
}
unsafe impl windows_core::Interface for DispatcherQueueTimer {
    type Vtable = <IDispatcherQueueTimer as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IDispatcherQueueTimer as windows_core::Interface>::IID;
}
impl core::ops::Deref for DispatcherQueueTimer {
    type Target = IDispatcherQueueTimer;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for DispatcherQueueTimer {
    const NAME: &'static str = "Microsoft.UI.Dispatching.DispatcherQueueTimer";
}
unsafe impl Send for DispatcherQueueTimer {}
unsafe impl Sync for DispatcherQueueTimer {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatcherShutdownMode(pub i32);
impl DispatcherShutdownMode {
    pub const OnExplicitShutdown: Self = Self(1);
}
impl windows_core::imp::TypeKind for DispatcherShutdownMode {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for DispatcherShutdownMode {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.DispatcherShutdownMode;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayArea(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    DisplayArea,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl DisplayArea {
    pub fn GetFromWindowId(
        windowid: WindowId,
        displayareafallback: DisplayAreaFallback,
    ) -> windows_core::Result<Self> {
        Self::IDisplayAreaStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).GetFromWindowId)(
                windows_core::Interface::as_raw(this),
                windowid,
                displayareafallback,
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IDisplayAreaStatics<R, F: FnOnce(&IDisplayAreaStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<DisplayArea, IDisplayAreaStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for DisplayArea {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IDisplayArea>();
}
unsafe impl windows_core::Interface for DisplayArea {
    type Vtable = <IDisplayArea as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IDisplayArea as windows_core::Interface>::IID;
}
impl core::ops::Deref for DisplayArea {
    type Target = IDisplayArea;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for DisplayArea {
    const NAME: &'static str = "Microsoft.UI.Windowing.DisplayArea";
}
unsafe impl Send for DisplayArea {}
unsafe impl Sync for DisplayArea {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DisplayAreaFallback(pub i32);
impl DisplayAreaFallback {
    pub const Primary: Self = Self(1);
    pub const Nearest: Self = Self(2);
}
impl windows_core::imp::TypeKind for DisplayAreaFallback {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for DisplayAreaFallback {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Windowing.DisplayAreaFallback;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleCollection(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    DoubleCollection,
    windows_core::IUnknown,
    windows_core::IInspectable,
    windows_collections::IVector<f64>
);
impl windows_core::RuntimeType for DoubleCollection {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, windows_collections::IVector<f64>>();
}
unsafe impl windows_core::Interface for DoubleCollection {
    type Vtable = <windows_collections::IVector<f64> as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <windows_collections::IVector<f64> as windows_core::Interface>::IID;
}
impl core::ops::Deref for DoubleCollection {
    type Target = windows_collections::IVector<f64>;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for DoubleCollection {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.DoubleCollection";
}
unsafe impl Send for DoubleCollection {}
unsafe impl Sync for DoubleCollection {}
windows_core::imp::define_interface!(
    DoubleTappedEventHandler,
    DoubleTappedEventHandler_Vtbl,
    0xf7a501b9_e277_5611_87b0_0e0607622183
);
impl windows_core::RuntimeType for DoubleTappedEventHandler {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct DoubleTappedEventHandler_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
struct DoubleTappedEventHandlerBox<
    F: Fn(
            windows_core::Ref<windows_core::IInspectable>,
            windows_core::Ref<DoubleTappedRoutedEventArgs>,
        ) + 'static,
>(core::marker::PhantomData<(fn() -> F,)>);
impl<
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<DoubleTappedRoutedEventArgs>,
            ) + 'static,
    > DoubleTappedEventHandlerBox<F>
{
    const VTABLE: DoubleTappedEventHandler_Vtbl = DoubleTappedEventHandler_Vtbl {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface:
                windows_core::imp::DelegateBox::<DoubleTappedEventHandler, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<DoubleTappedEventHandler, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<DoubleTappedEventHandler, F>::Release,
        },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<DoubleTappedEventHandler, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&e),
            );
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleTappedRoutedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    DoubleTappedRoutedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(DoubleTappedRoutedEventArgs, RoutedEventArgs);
impl windows_core::RuntimeType for DoubleTappedRoutedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IDoubleTappedRoutedEventArgs>();
}
unsafe impl windows_core::Interface for DoubleTappedRoutedEventArgs {
    type Vtable = <IDoubleTappedRoutedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IDoubleTappedRoutedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for DoubleTappedRoutedEventArgs {
    type Target = IDoubleTappedRoutedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for DoubleTappedRoutedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Input.DoubleTappedRoutedEventArgs";
}
unsafe impl Send for DoubleTappedRoutedEventArgs {}
unsafe impl Sync for DoubleTappedRoutedEventArgs {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DragItemsCompletedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    DragItemsCompletedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for DragItemsCompletedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IDragItemsCompletedEventArgs>();
}
unsafe impl windows_core::Interface for DragItemsCompletedEventArgs {
    type Vtable = <IDragItemsCompletedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IDragItemsCompletedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for DragItemsCompletedEventArgs {
    type Target = IDragItemsCompletedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for DragItemsCompletedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.DragItemsCompletedEventArgs";
}
unsafe impl Send for DragItemsCompletedEventArgs {}
unsafe impl Sync for DragItemsCompletedEventArgs {}
pub const ERROR_PIPE_CONNECTED: i32 = 535;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ElementTheme(pub i32);
impl ElementTheme {
    pub const Default: Self = Self(0);
    pub const Light: Self = Self(1);
    pub const Dark: Self = Self(2);
}
impl windows_core::imp::TypeKind for ElementTheme {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for ElementTheme {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.ElementTheme;i4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventHandler<T>(windows_core::IUnknown, core::marker::PhantomData<T>)
where
    T: windows_core::RuntimeType + 'static;
unsafe impl<T: windows_core::RuntimeType + 'static> windows_core::Interface for EventHandler<T> {
    type Vtable = EventHandler_Vtbl<T>;
    const IID: windows_core::GUID =
        windows_core::GUID::from_signature(<Self as windows_core::RuntimeType>::SIGNATURE);
}
impl<T: windows_core::RuntimeType + 'static> windows_core::RuntimeType for EventHandler<T> {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::new()
        .push_slice(b"pinterface({9de1c535-6ae1-11e0-84e1-18a905bcc53f}")
        .push_slice(b";")
        .push_other(T::SIGNATURE)
        .push_slice(b")");
}
#[repr(C)]
pub struct EventHandler_Vtbl<T>
where
    T: windows_core::RuntimeType + 'static,
{
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        args: windows_core::imp::AbiType<T>,
    ) -> windows_core::HRESULT,
    T: core::marker::PhantomData<T>,
}
struct EventHandlerBox<
    T,
    F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<T>) + 'static,
>(core::marker::PhantomData<(T, fn() -> F)>)
where
    T: windows_core::RuntimeType + 'static;
impl<
        T: windows_core::RuntimeType + 'static,
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<T>) + 'static,
    > EventHandlerBox<T, F>
{
    const VTABLE: EventHandler_Vtbl<T> = EventHandler_Vtbl::<T> {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface: windows_core::imp::DelegateBox::<EventHandler<T>, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<EventHandler<T>, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<EventHandler<T>, F>::Release,
        },
        Invoke: Self::Invoke,
        T: core::marker::PhantomData::<T>,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        args: windows_core::imp::AbiType<T>,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<EventHandler<T>, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&args),
            );
            windows_core::HRESULT(0)
        }
    }
}
pub type FARPROC = Option<unsafe extern "system" fn() -> isize>;
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOpenPicker(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    FileOpenPicker,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl FileOpenPicker {
    pub fn CreateInstance(windowid: WindowId) -> windows_core::Result<Self> {
        Self::IFileOpenPickerFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                windowid,
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IFileOpenPickerFactory<R, F: FnOnce(&IFileOpenPickerFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<FileOpenPicker, IFileOpenPickerFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for FileOpenPicker {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IFileOpenPicker>();
}
unsafe impl windows_core::Interface for FileOpenPicker {
    type Vtable = <IFileOpenPicker as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IFileOpenPicker as windows_core::Interface>::IID;
}
impl core::ops::Deref for FileOpenPicker {
    type Target = IFileOpenPicker;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for FileOpenPicker {
    const NAME: &'static str = "Microsoft.Windows.Storage.Pickers.FileOpenPicker";
}
unsafe impl Send for FileOpenPicker {}
unsafe impl Sync for FileOpenPicker {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Flyout(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Flyout, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Flyout, FlyoutBase, DependencyObject);
impl Flyout {
    pub fn new() -> windows_core::Result<Self> {
        Self::IFlyoutFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IFlyoutFactory<R, F: FnOnce(&IFlyoutFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Flyout, IFlyoutFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Flyout {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IFlyout>();
}
unsafe impl windows_core::Interface for Flyout {
    type Vtable = <IFlyout as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IFlyout as windows_core::Interface>::IID;
}
impl core::ops::Deref for Flyout {
    type Target = IFlyout;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Flyout {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Flyout";
}
unsafe impl Send for Flyout {}
unsafe impl Sync for Flyout {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlyoutBase(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    FlyoutBase,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(FlyoutBase, DependencyObject);
impl windows_core::RuntimeType for FlyoutBase {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IFlyoutBase>();
}
unsafe impl windows_core::Interface for FlyoutBase {
    type Vtable = <IFlyoutBase as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IFlyoutBase as windows_core::Interface>::IID;
}
impl core::ops::Deref for FlyoutBase {
    type Target = IFlyoutBase;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for FlyoutBase {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Primitives.FlyoutBase";
}
unsafe impl Send for FlyoutBase {}
unsafe impl Sync for FlyoutBase {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FlyoutPlacementMode(pub i32);
impl FlyoutPlacementMode {
    pub const Bottom: Self = Self(1);
    pub const BottomEdgeAlignedLeft: Self = Self(7);
    pub const BottomEdgeAlignedRight: Self = Self(8);
}
impl windows_core::imp::TypeKind for FlyoutPlacementMode {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for FlyoutPlacementMode {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.Controls.Primitives.FlyoutPlacementMode;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusManager(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    FocusManager,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl FocusManager {
    pub fn FindFirstFocusableElement<P0>(searchscope: P0) -> windows_core::Result<DependencyObject>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::IFocusManagerStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).FindFirstFocusableElement)(
                windows_core::Interface::as_raw(this),
                searchscope.param().abi(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IFocusManagerStatics<R, F: FnOnce(&IFocusManagerStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<FocusManager, IFocusManagerStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for FocusManager {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IFocusManager>();
}
unsafe impl windows_core::Interface for FocusManager {
    type Vtable = <IFocusManager as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IFocusManager as windows_core::Interface>::IID;
}
impl core::ops::Deref for FocusManager {
    type Target = IFocusManager;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for FocusManager {
    const NAME: &'static str = "Microsoft.UI.Xaml.Input.FocusManager";
}
unsafe impl Send for FocusManager {}
unsafe impl Sync for FocusManager {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FocusState(pub i32);
impl FocusState {
    pub const Pointer: Self = Self(1);
    pub const Keyboard: Self = Self(2);
    pub const Programmatic: Self = Self(3);
}
impl windows_core::imp::TypeKind for FocusState {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for FocusState {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.FocusState;i4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FontFamily(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    FontFamily,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl FontFamily {
    pub fn CreateInstanceWithName(familyname: &str) -> windows_core::Result<Self> {
        Self::IFontFamilyFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstanceWithName)(
                windows_core::Interface::as_raw(this),
                core::mem::transmute_copy(&windows_core::HSTRING::from(familyname)),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IFontFamilyFactory<R, F: FnOnce(&IFontFamilyFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<FontFamily, IFontFamilyFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for FontFamily {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IFontFamily>();
}
unsafe impl windows_core::Interface for FontFamily {
    type Vtable = <IFontFamily as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IFontFamily as windows_core::Interface>::IID;
}
impl core::ops::Deref for FontFamily {
    type Target = IFontFamily;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for FontFamily {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.FontFamily";
}
unsafe impl Send for FontFamily {}
unsafe impl Sync for FontFamily {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FontIcon(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    FontIcon,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    FontIcon,
    IconElement,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl FontIcon {
    pub fn new() -> windows_core::Result<Self> {
        Self::IFontIconFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IFontIconFactory<R, F: FnOnce(&IFontIconFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<FontIcon, IFontIconFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for FontIcon {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IFontIcon>();
}
unsafe impl windows_core::Interface for FontIcon {
    type Vtable = <IFontIcon as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IFontIcon as windows_core::Interface>::IID;
}
impl core::ops::Deref for FontIcon {
    type Target = IFontIcon;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for FontIcon {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.FontIcon";
}
unsafe impl Send for FontIcon {}
unsafe impl Sync for FontIcon {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FontNumeralAlignment(pub i32);
impl FontNumeralAlignment {
    pub const Tabular: Self = Self(2);
}
impl windows_core::imp::TypeKind for FontNumeralAlignment {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for FontNumeralAlignment {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.FontNumeralAlignment;i4)",
    );
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FontWeight {
    pub weight: u16,
}
impl windows_core::imp::TypeKind for FontWeight {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for FontWeight {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"struct(Windows.UI.Text.FontWeight;u2)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameworkElement(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    FrameworkElement,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(FrameworkElement, UIElement, DependencyObject);
impl windows_core::RuntimeType for FrameworkElement {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IFrameworkElement>();
}
unsafe impl windows_core::Interface for FrameworkElement {
    type Vtable = <IFrameworkElement as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IFrameworkElement as windows_core::Interface>::IID;
}
impl core::ops::Deref for FrameworkElement {
    type Target = IFrameworkElement;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for FrameworkElement {
    const NAME: &'static str = "Microsoft.UI.Xaml.FrameworkElement";
}
unsafe impl Send for FrameworkElement {}
unsafe impl Sync for FrameworkElement {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameworkTemplate(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    FrameworkTemplate,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(FrameworkTemplate, DependencyObject);
impl windows_core::RuntimeType for FrameworkTemplate {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IFrameworkTemplate>();
}
unsafe impl windows_core::Interface for FrameworkTemplate {
    type Vtable = <IFrameworkTemplate as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IFrameworkTemplate as windows_core::Interface>::IID;
}
impl core::ops::Deref for FrameworkTemplate {
    type Target = IFrameworkTemplate;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for FrameworkTemplate {
    const NAME: &'static str = "Microsoft.UI.Xaml.FrameworkTemplate";
}
unsafe impl Send for FrameworkTemplate {}
unsafe impl Sync for FrameworkTemplate {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralTransform(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    GeneralTransform,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(GeneralTransform, DependencyObject);
impl windows_core::RuntimeType for GeneralTransform {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IGeneralTransform>();
}
unsafe impl windows_core::Interface for GeneralTransform {
    type Vtable = <IGeneralTransform as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IGeneralTransform as windows_core::Interface>::IID;
}
impl core::ops::Deref for GeneralTransform {
    type Target = IGeneralTransform;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for GeneralTransform {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.GeneralTransform";
}
unsafe impl Send for GeneralTransform {}
unsafe impl Sync for GeneralTransform {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Geometry(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    Geometry,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(Geometry, DependencyObject);
impl windows_core::RuntimeType for Geometry {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IGeometry>();
}
unsafe impl windows_core::Interface for Geometry {
    type Vtable = <IGeometry as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IGeometry as windows_core::Interface>::IID;
}
impl core::ops::Deref for Geometry {
    type Target = IGeometry;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Geometry {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.Geometry";
}
unsafe impl Send for Geometry {}
unsafe impl Sync for Geometry {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grid(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Grid, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Grid, Panel, FrameworkElement, UIElement, DependencyObject);
impl Grid {
    pub fn new() -> windows_core::Result<Self> {
        Self::IGridFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    pub fn SetRow<P0>(element: P0, value: i32) -> windows_core::Result<()>
    where
        P0: windows_core::Param<FrameworkElement>,
    {
        Self::IGridStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetRow)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                value,
            )
            .ok()
        })
    }
    pub fn SetColumn<P0>(element: P0, value: i32) -> windows_core::Result<()>
    where
        P0: windows_core::Param<FrameworkElement>,
    {
        Self::IGridStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetColumn)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                value,
            )
            .ok()
        })
    }
    pub fn SetRowSpan<P0>(element: P0, value: i32) -> windows_core::Result<()>
    where
        P0: windows_core::Param<FrameworkElement>,
    {
        Self::IGridStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetRowSpan)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                value,
            )
            .ok()
        })
    }
    pub fn SetColumnSpan<P0>(element: P0, value: i32) -> windows_core::Result<()>
    where
        P0: windows_core::Param<FrameworkElement>,
    {
        Self::IGridStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetColumnSpan)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                value,
            )
            .ok()
        })
    }
    fn IGridFactory<R, F: FnOnce(&IGridFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Grid, IGridFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
    fn IGridStatics<R, F: FnOnce(&IGridStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Grid, IGridStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Grid {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IGrid>();
}
unsafe impl windows_core::Interface for Grid {
    type Vtable = <IGrid as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IGrid as windows_core::Interface>::IID;
}
impl core::ops::Deref for Grid {
    type Target = IGrid;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Grid {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Grid";
}
unsafe impl Send for Grid {}
unsafe impl Sync for Grid {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GridLength {
    pub value: f64,
    pub grid_unit_type: GridUnitType,
}
impl windows_core::imp::TypeKind for GridLength {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for GridLength {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"struct(Microsoft.UI.Xaml.GridLength;f8;enum(Microsoft.UI.Xaml.GridUnitType;i4))",
    );
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GridUnitType(pub i32);
impl GridUnitType {
    pub const Auto: Self = Self(0);
    pub const Pixel: Self = Self(1);
    pub const Star: Self = Self(2);
}
impl windows_core::imp::TypeKind for GridUnitType {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for GridUnitType {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.GridUnitType;i4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GridView(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    GridView,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    GridView,
    ListViewBase,
    Selector,
    ItemsControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl GridView {
    pub fn new() -> windows_core::Result<Self> {
        Self::IGridViewFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IGridViewFactory<R, F: FnOnce(&IGridViewFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<GridView, IGridViewFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for GridView {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IGridView>();
}
unsafe impl windows_core::Interface for GridView {
    type Vtable = <IGridView as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IGridView as windows_core::Interface>::IID;
}
impl core::ops::Deref for GridView {
    type Target = IGridView;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for GridView {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.GridView";
}
unsafe impl Send for GridView {}
unsafe impl Sync for GridView {}
pub type HANDLE = *mut core::ffi::c_void;
pub type HBITMAP = *mut core::ffi::c_void;
pub type HBRUSH = *mut core::ffi::c_void;
pub type HCURSOR = HICON;
pub type HICON = *mut core::ffi::c_void;
pub type HINSTANCE = *mut core::ffi::c_void;
pub type HLOCAL = HANDLE;
pub type HMENU = *mut core::ffi::c_void;
pub type HMODULE = HINSTANCE;
pub type HWND = *mut core::ffi::c_void;
pub const HWND_MESSAGE: HWND = -3 as _;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HorizontalAlignment(pub i32);
impl HorizontalAlignment {
    pub const Left: Self = Self(0);
    pub const Center: Self = Self(1);
    pub const Right: Self = Self(2);
    pub const Stretch: Self = Self(3);
}
impl windows_core::imp::TypeKind for HorizontalAlignment {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for HorizontalAlignment {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.HorizontalAlignment;i4)",
    );
}
windows_core::imp::define_interface!(
    IAppActivationArguments,
    IAppActivationArguments_Vtbl,
    0x14f99eaf_1580_5062_bdc8_d5d1c31138fb
);
impl windows_core::RuntimeType for IAppActivationArguments {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IAppActivationArguments_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IAppInstance,
    IAppInstance_Vtbl,
    0x75766ae4_0239_5a26_b9da_d5bfc75a4866
);
impl windows_core::RuntimeType for IAppInstance {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IAppInstance {
    pub fn RedirectActivationToAsync<P0>(
        &self,
        args: P0,
    ) -> windows_core::Result<windows_future::IAsyncAction>
    where
        P0: windows_core::Param<AppActivationArguments>,
    {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).RedirectActivationToAsync)(
                windows_core::Interface::as_raw(self),
                args.param().abi(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn GetActivatedEventArgs(&self) -> windows_core::Result<AppActivationArguments> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetActivatedEventArgs)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn Activated<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<AppActivationArguments>,
            ) + 'static,
    {
        let handler: EventHandler<AppActivationArguments> = {
            let com =
                windows_core::imp::DelegateBox::<EventHandler<AppActivationArguments>, F>::new(
                    &EventHandlerBox::<AppActivationArguments, F>::VTABLE,
                    handler,
                );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Activated)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveActivated,
            ))
        }
    }
    pub fn IsCurrent(&self) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).IsCurrent)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IAppInstance_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    UnregisterKey: usize,
    pub RedirectActivationToAsync: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub GetActivatedEventArgs: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub Activated: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveActivated:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    Key: usize,
    pub IsCurrent:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IAppInstanceStatics,
    IAppInstanceStatics_Vtbl,
    0x4f414b25_8330_5a9b_bbc1_8229d479649d
);
impl windows_core::RuntimeType for IAppInstanceStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IAppInstanceStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub GetCurrent: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    GetInstances: usize,
    pub FindOrRegisterForKey: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IAppWindow,
    IAppWindow_Vtbl,
    0xcfa788b3_643b_5c5e_ad4e_321d48a82acd
);
impl windows_core::RuntimeType for IAppWindow {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IAppWindow {
    pub fn Id(&self) -> windows_core::Result<WindowId> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Id)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn IsVisible(&self) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).IsVisible)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn Position(&self) -> windows_core::Result<PointInt32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Position)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn Presenter(&self) -> windows_core::Result<AppWindowPresenter> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Presenter)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn Size(&self) -> windows_core::Result<SizeInt32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Size)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn TitleBar(&self) -> windows_core::Result<AppWindowTitleBar> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).TitleBar)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn Hide(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Hide)(windows_core::Interface::as_raw(self)).ok()
        }
    }
    pub fn Move(&self, position: PointInt32) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Move)(
                windows_core::Interface::as_raw(self),
                position,
            )
            .ok()
        }
    }
    pub fn Resize(&self, size: SizeInt32) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Resize)(
                windows_core::Interface::as_raw(self),
                size,
            )
            .ok()
        }
    }
    pub fn Show(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Show)(windows_core::Interface::as_raw(self)).ok()
        }
    }
    pub fn Closing<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<AppWindow>, windows_core::Ref<AppWindowClosingEventArgs>) + 'static,
    {
        let handler: TypedEventHandler<AppWindow, AppWindowClosingEventArgs> = {
            let com = windows_core::imp::DelegateBox::<
                TypedEventHandler<AppWindow, AppWindowClosingEventArgs>,
                F,
            >::new(
                &TypedEventHandlerBox::<AppWindow, AppWindowClosingEventArgs, F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Closing)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveClosing,
            ))
        }
    }
}
#[repr(C)]
pub struct IAppWindow_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Id:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut WindowId) -> windows_core::HRESULT,
    IsShownInSwitchers: usize,
    SetIsShownInSwitchers: usize,
    pub IsVisible:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut bool) -> windows_core::HRESULT,
    OwnerWindowId: usize,
    pub Position:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut PointInt32) -> windows_core::HRESULT,
    pub Presenter: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub Size:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut SizeInt32) -> windows_core::HRESULT,
    Title: usize,
    SetTitle: usize,
    pub TitleBar: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    Destroy: usize,
    pub Hide: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
    pub Move:
        unsafe extern "system" fn(*mut core::ffi::c_void, PointInt32) -> windows_core::HRESULT,
    MoveAndResize: usize,
    MoveAndResizeRelativeToDisplayArea: usize,
    pub Resize:
        unsafe extern "system" fn(*mut core::ffi::c_void, SizeInt32) -> windows_core::HRESULT,
    SetIcon: usize,
    SetIconWithIconId: usize,
    SetPresenter: usize,
    SetPresenterByKind: usize,
    pub Show: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
    ShowWithActivation: usize,
    Changed: usize,
    RemoveChanged: usize,
    pub Closing: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveClosing:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IAppWindow2,
    IAppWindow2_Vtbl,
    0x6cd41292_794c_5cac_8961_210d012c6ebc
);
impl windows_core::RuntimeType for IAppWindow2 {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IAppWindow2 {
    pub fn ClientSize(&self) -> windows_core::Result<SizeInt32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ClientSize)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IAppWindow2_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub ClientSize:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut SizeInt32) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IAppWindowClosingEventArgs,
    IAppWindowClosingEventArgs_Vtbl,
    0x0e09d90b_2261_590b_9ad1_8504991d8754
);
impl windows_core::RuntimeType for IAppWindowClosingEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IAppWindowClosingEventArgs {
    pub fn SetCancel(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetCancel)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IAppWindowClosingEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Cancel: usize,
    pub SetCancel: unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IAppWindowPresenter,
    IAppWindowPresenter_Vtbl,
    0xbc3042c2_c6c6_5632_8989_ff0ec6d3b40d
);
impl windows_core::RuntimeType for IAppWindowPresenter {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IAppWindowPresenter_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IAppWindowTitleBar,
    IAppWindowTitleBar_Vtbl,
    0x5574efa2_c91c_5700_a363_539c71a7aaf4
);
impl windows_core::RuntimeType for IAppWindowTitleBar {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IAppWindowTitleBar {
    pub fn SetButtonBackgroundColor(&self, value: Option<Color>) -> windows_core::Result<()> {
        let value__ = value.map(<windows_reference::IReference<Color> as From<_>>::from);
        unsafe {
            (windows_core::Interface::vtable(self).SetButtonBackgroundColor)(
                windows_core::Interface::as_raw(self),
                windows_core::Param::param(value__.as_ref()).abi(),
            )
            .ok()
        }
    }
    pub fn SetButtonInactiveBackgroundColor(
        &self,
        value: Option<Color>,
    ) -> windows_core::Result<()> {
        let value__ = value.map(<windows_reference::IReference<Color> as From<_>>::from);
        unsafe {
            (windows_core::Interface::vtable(self).SetButtonInactiveBackgroundColor)(
                windows_core::Interface::as_raw(self),
                windows_core::Param::param(value__.as_ref()).abi(),
            )
            .ok()
        }
    }
    pub fn Height(&self) -> windows_core::Result<i32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Height)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn LeftInset(&self) -> windows_core::Result<i32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).LeftInset)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn RightInset(&self) -> windows_core::Result<i32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).RightInset)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IAppWindowTitleBar_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    BackgroundColor: usize,
    SetBackgroundColor: usize,
    ButtonBackgroundColor: usize,
    pub SetButtonBackgroundColor: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    ButtonForegroundColor: usize,
    SetButtonForegroundColor: usize,
    ButtonHoverBackgroundColor: usize,
    SetButtonHoverBackgroundColor: usize,
    ButtonHoverForegroundColor: usize,
    SetButtonHoverForegroundColor: usize,
    ButtonInactiveBackgroundColor: usize,
    pub SetButtonInactiveBackgroundColor: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    ButtonInactiveForegroundColor: usize,
    SetButtonInactiveForegroundColor: usize,
    ButtonPressedBackgroundColor: usize,
    SetButtonPressedBackgroundColor: usize,
    ButtonPressedForegroundColor: usize,
    SetButtonPressedForegroundColor: usize,
    ExtendsContentIntoTitleBar: usize,
    SetExtendsContentIntoTitleBar: usize,
    ForegroundColor: usize,
    SetForegroundColor: usize,
    pub Height:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> windows_core::HRESULT,
    IconShowOptions: usize,
    SetIconShowOptions: usize,
    InactiveBackgroundColor: usize,
    SetInactiveBackgroundColor: usize,
    InactiveForegroundColor: usize,
    SetInactiveForegroundColor: usize,
    pub LeftInset:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> windows_core::HRESULT,
    pub RightInset:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IAppWindowTitleBar2,
    IAppWindowTitleBar2_Vtbl,
    0x86faed38_748a_5b4b_9ccf_3ba0496c9041
);
impl windows_core::RuntimeType for IAppWindowTitleBar2 {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IAppWindowTitleBar2 {
    pub fn SetPreferredHeightOption(
        &self,
        value: TitleBarHeightOption,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetPreferredHeightOption)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IAppWindowTitleBar2_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    PreferredHeightOption: usize,
    pub SetPreferredHeightOption: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        TitleBarHeightOption,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IAppWindowTitleBar3,
    IAppWindowTitleBar3_Vtbl,
    0x07146e74_0410_5597_aba7_1af276d2ae07
);
impl windows_core::RuntimeType for IAppWindowTitleBar3 {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IAppWindowTitleBar3 {
    pub fn SetPreferredTheme(&self, value: TitleBarTheme) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetPreferredTheme)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IAppWindowTitleBar3_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    PreferredTheme: usize,
    pub SetPreferredTheme:
        unsafe extern "system" fn(*mut core::ffi::c_void, TitleBarTheme) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IApplication,
    IApplication_Vtbl,
    0x06a8f4e7_1146_55af_820d_ebd55643b021
);
impl windows_core::RuntimeType for IApplication {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IApplication {
    pub fn Resources(&self) -> windows_core::Result<ResourceDictionary> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Resources)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetRequestedTheme(&self, value: ApplicationTheme) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetRequestedTheme)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn Exit(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Exit)(windows_core::Interface::as_raw(self)).ok()
        }
    }
}
#[repr(C)]
pub struct IApplication_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Resources: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    SetResources: usize,
    DebugSettings: usize,
    RequestedTheme: usize,
    pub SetRequestedTheme: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        ApplicationTheme,
    ) -> windows_core::HRESULT,
    FocusVisualKind: usize,
    SetFocusVisualKind: usize,
    HighContrastAdjustment: usize,
    SetHighContrastAdjustment: usize,
    UnhandledException: usize,
    RemoveUnhandledException: usize,
    pub Exit: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IApplication3,
    IApplication3_Vtbl,
    0xbe941595_61fe_5b36_a3d3_962a647d7c6f
);
impl windows_core::RuntimeType for IApplication3 {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IApplication3 {
    pub fn SetDispatcherShutdownMode(
        &self,
        value: DispatcherShutdownMode,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetDispatcherShutdownMode)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IApplication3_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    DispatcherShutdownMode: usize,
    pub SetDispatcherShutdownMode: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        DispatcherShutdownMode,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IApplicationFactory,
    IApplicationFactory_Vtbl,
    0x9fd96657_5294_5a65_a1db_4fea143597da
);
impl windows_core::RuntimeType for IApplicationFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IApplicationFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IApplicationInitializationCallbackParams,
    IApplicationInitializationCallbackParams_Vtbl,
    0x1b1906ea_5b7b_5876_81ab_7c2281ac3d20
);
impl windows_core::RuntimeType for IApplicationInitializationCallbackParams {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IApplicationInitializationCallbackParams_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IApplicationOverrides,
    IApplicationOverrides_Vtbl,
    0xa33e81ef_c665_503b_8827_d27ef1720a06
);
impl windows_core::RuntimeType for IApplicationOverrides {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
    const NAME: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"Microsoft.UI.Xaml.IApplicationOverrides");
}
impl windows_core::RuntimeName for IApplicationOverrides {
    const NAME: &'static str = "Microsoft.UI.Xaml.IApplicationOverrides";
}
pub trait IApplicationOverrides_Impl: windows_core::IUnknownImpl {
    fn OnLaunched(
        &self,
        args: windows_core::Ref<LaunchActivatedEventArgs>,
    ) -> windows_core::Result<()>;
}
impl IApplicationOverrides_Vtbl {
    pub const fn new<Identity: IApplicationOverrides_Impl, const OFFSET: isize>() -> Self {
        unsafe extern "system" fn OnLaunched<
            Identity: IApplicationOverrides_Impl,
            const OFFSET: isize,
        >(
            this: *mut core::ffi::c_void,
            args: *mut core::ffi::c_void,
        ) -> windows_core::HRESULT {
            unsafe {
                let this: &Identity =
                    &*((this as *const *const ()).offset(OFFSET) as *const Identity);
                IApplicationOverrides_Impl::OnLaunched(this, core::mem::transmute_copy(&args))
                    .into()
            }
        }
        Self {
            base__: windows_core::IInspectable_Vtbl::new::<Identity, IApplicationOverrides, OFFSET>(
            ),
            OnLaunched: OnLaunched::<Identity, OFFSET>,
        }
    }
    pub fn matches(iid: &windows_core::GUID) -> bool {
        iid == &<IApplicationOverrides as windows_core::Interface>::IID
    }
}
#[repr(C)]
pub struct IApplicationOverrides_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub OnLaunched: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IApplicationStatics,
    IApplicationStatics_Vtbl,
    0x4e0d09f5_4358_512c_a987_503b52848e95
);
impl windows_core::RuntimeType for IApplicationStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IApplicationStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Current: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub Start: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IAutomationProperties,
    IAutomationProperties_Vtbl,
    0x525c6a71_dd8a_52a0_977b_db1b02f8e896
);
impl windows_core::RuntimeType for IAutomationProperties {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IAutomationProperties_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IAutomationPropertiesStatics,
    IAutomationPropertiesStatics_Vtbl,
    0xb1e3e0f3_112f_5966_87dc_7862d4ad50e5
);
impl windows_core::RuntimeType for IAutomationPropertiesStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IAutomationPropertiesStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    AcceleratorKeyProperty: usize,
    GetAcceleratorKey: usize,
    SetAcceleratorKey: usize,
    AccessKeyProperty: usize,
    GetAccessKey: usize,
    SetAccessKey: usize,
    AutomationIdProperty: usize,
    GetAutomationId: usize,
    SetAutomationId: usize,
    HelpTextProperty: usize,
    GetHelpText: usize,
    SetHelpText: usize,
    IsRequiredForFormProperty: usize,
    GetIsRequiredForForm: usize,
    SetIsRequiredForForm: usize,
    ItemStatusProperty: usize,
    GetItemStatus: usize,
    SetItemStatus: usize,
    ItemTypeProperty: usize,
    GetItemType: usize,
    SetItemType: usize,
    LabeledByProperty: usize,
    GetLabeledBy: usize,
    SetLabeledBy: usize,
    NameProperty: usize,
    GetName: usize,
    pub SetName: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IBitmapImage,
    IBitmapImage_Vtbl,
    0x5cc29916_a411_5bc2_a3c5_a00d99a59da8
);
impl windows_core::RuntimeType for IBitmapImage {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IBitmapImage {
    pub fn SetDecodePixelWidth(&self, value: i32) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetDecodePixelWidth)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IBitmapImage_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    CreateOptions: usize,
    SetCreateOptions: usize,
    UriSource: usize,
    SetUriSource: usize,
    DecodePixelWidth: usize,
    pub SetDecodePixelWidth:
        unsafe extern "system" fn(*mut core::ffi::c_void, i32) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IBitmapSource,
    IBitmapSource_Vtbl,
    0x8424269d_9b82_534f_8fea_af5b5ef96bf2
);
impl windows_core::RuntimeType for IBitmapSource {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IBitmapSource {
    pub fn SetSource<P0>(&self, streamsource: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<IRandomAccessStream>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetSource)(
                windows_core::Interface::as_raw(self),
                streamsource.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IBitmapSource_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    PixelWidth: usize,
    PixelHeight: usize,
    pub SetSource: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IBorder,
    IBorder_Vtbl,
    0x1ca13b47_ff5c_5abc_a411_a177df9482a9
);
impl windows_core::RuntimeType for IBorder {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IBorder {
    pub fn SetBorderBrush<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Brush>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetBorderBrush)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetBorderThickness(&self, value: Thickness) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetBorderThickness)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetBackground<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Brush>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetBackground)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetCornerRadius(&self, value: CornerRadius) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetCornerRadius)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn Padding(&self) -> windows_core::Result<Thickness> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Padding)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn SetPadding(&self, value: Thickness) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetPadding)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn Child(&self) -> windows_core::Result<UIElement> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Child)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetChild<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<UIElement>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetChild)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IBorder_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    BorderBrush: usize,
    pub SetBorderBrush: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    BorderThickness: usize,
    pub SetBorderThickness:
        unsafe extern "system" fn(*mut core::ffi::c_void, Thickness) -> windows_core::HRESULT,
    Background: usize,
    pub SetBackground: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    BackgroundSizing: usize,
    SetBackgroundSizing: usize,
    CornerRadius: usize,
    pub SetCornerRadius:
        unsafe extern "system" fn(*mut core::ffi::c_void, CornerRadius) -> windows_core::HRESULT,
    pub Padding:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut Thickness) -> windows_core::HRESULT,
    pub SetPadding:
        unsafe extern "system" fn(*mut core::ffi::c_void, Thickness) -> windows_core::HRESULT,
    pub Child: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetChild: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(IBrush, IBrush_Vtbl, 0x2de3cb83_1329_5679_88f8_c822bc5442cb);
impl windows_core::RuntimeType for IBrush {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IBrush_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IBuffer,
    IBuffer_Vtbl,
    0x905a0fe0_bc53_11df_8c49_001e4fc686da
);
impl windows_core::RuntimeType for IBuffer {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
windows_core::imp::interface_hierarchy!(
    IBuffer,
    windows_core::IUnknown,
    windows_core::IInspectable
);
#[repr(C)]
pub struct IBuffer_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IButton,
    IButton_Vtbl,
    0x216c183d_d07a_5aa5_b8a4_0300a2683e87
);
impl windows_core::RuntimeType for IButton {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IButton {
    pub fn SetFlyout<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<FlyoutBase>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetFlyout)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IButton_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Flyout: usize,
    pub SetFlyout: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IButtonBase,
    IButtonBase_Vtbl,
    0x65714269_2473_5327_a652_0ea6bce7f403
);
impl windows_core::RuntimeType for IButtonBase {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IButtonBase {
    pub fn Click<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<RoutedEventArgs>)
            + 'static,
    {
        let handler: RoutedEventHandler = {
            let com = windows_core::imp::DelegateBox::<RoutedEventHandler, F>::new(
                &RoutedEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Click)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveClick,
            ))
        }
    }
}
#[repr(C)]
pub struct IButtonBase_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    ClickMode: usize,
    SetClickMode: usize,
    IsPointerOver: usize,
    IsPressed: usize,
    Command: usize,
    SetCommand: usize,
    CommandParameter: usize,
    SetCommandParameter: usize,
    pub Click: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveClick:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IButtonFactory,
    IButtonFactory_Vtbl,
    0xfe393422_d91c_57b1_9a9c_2c7e3f41f77c
);
impl windows_core::RuntimeType for IButtonFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IButtonFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
pub const ICON_BIG: i32 = 1;
pub const ICON_SMALL: i32 = 0;
windows_core::imp::define_interface!(
    ICanvas,
    ICanvas_Vtbl,
    0x457ba139_1146_51d2_807e_d9d65c927060
);
impl windows_core::RuntimeType for ICanvas {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ICanvas_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    ICanvasFactory,
    ICanvasFactory_Vtbl,
    0x374c5050_3481_5557_9948_804c0b8eea89
);
impl windows_core::RuntimeType for ICanvasFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ICanvasFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IColumnDefinition,
    IColumnDefinition_Vtbl,
    0x454cea14_87ec_5890_bb62_f1d82a94758e
);
impl windows_core::RuntimeType for IColumnDefinition {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IColumnDefinition {
    pub fn SetWidth(&self, value: GridLength) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetWidth)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetMaxWidth(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetMaxWidth)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetMinWidth(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetMinWidth)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IColumnDefinition_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Width: usize,
    pub SetWidth:
        unsafe extern "system" fn(*mut core::ffi::c_void, GridLength) -> windows_core::HRESULT,
    MaxWidth: usize,
    pub SetMaxWidth:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    MinWidth: usize,
    pub SetMinWidth:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IComboBox,
    IComboBox_Vtbl,
    0xc77da58b_4fd7_51e0_a431_f84658a83e9e
);
impl windows_core::RuntimeType for IComboBox {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IComboBox_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IComboBoxFactory,
    IComboBoxFactory_Vtbl,
    0x71c1014b_acdf_5c03_b5ed_02871caaeb6b
);
impl windows_core::RuntimeType for IComboBoxFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IComboBoxFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IContainerContentChangingEventArgs,
    IContainerContentChangingEventArgs_Vtbl,
    0xf4c8c937_b070_53ce_a76c_074ee5750a71
);
impl windows_core::RuntimeType for IContainerContentChangingEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IContainerContentChangingEventArgs {
    pub fn ItemContainer(&self) -> windows_core::Result<SelectorItem> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ItemContainer)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn InRecycleQueue(&self) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).InRecycleQueue)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn ItemIndex(&self) -> windows_core::Result<i32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ItemIndex)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn Item(&self) -> windows_core::Result<windows_core::IInspectable> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Item)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetHandled(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetHandled)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IContainerContentChangingEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub ItemContainer: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub InRecycleQueue:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut bool) -> windows_core::HRESULT,
    pub ItemIndex:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> windows_core::HRESULT,
    pub Item: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    Phase: usize,
    Handled: usize,
    pub SetHandled:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IContentControl,
    IContentControl_Vtbl,
    0x07e81761_11b2_52ae_8f8b_4d53d2b5900a
);
impl windows_core::RuntimeType for IContentControl {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IContentControl {
    pub fn Content(&self) -> windows_core::Result<windows_core::IInspectable> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Content)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetContent<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<windows_core::IInspectable>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetContent)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn ContentTemplateRoot(&self) -> windows_core::Result<UIElement> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ContentTemplateRoot)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IContentControl_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Content: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetContent: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    ContentTemplate: usize,
    SetContentTemplate: usize,
    ContentTemplateSelector: usize,
    SetContentTemplateSelector: usize,
    ContentTransitions: usize,
    SetContentTransitions: usize,
    pub ContentTemplateRoot: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IContentDialog,
    IContentDialog_Vtbl,
    0xac2145a3_4a32_5305_a81d_47509515bfce
);
impl windows_core::RuntimeType for IContentDialog {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IContentDialog {
    pub fn Closing<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<ContentDialog>, windows_core::Ref<ContentDialogClosingEventArgs>)
            + 'static,
    {
        let handler: TypedEventHandler<ContentDialog, ContentDialogClosingEventArgs> = {
            let com = windows_core::imp::DelegateBox::<
                TypedEventHandler<ContentDialog, ContentDialogClosingEventArgs>,
                F,
            >::new(
                &TypedEventHandlerBox::<ContentDialog, ContentDialogClosingEventArgs, F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Closing)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveClosing,
            ))
        }
    }
    pub fn Hide(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Hide)(windows_core::Interface::as_raw(self)).ok()
        }
    }
    pub fn ShowAsync(
        &self,
    ) -> windows_core::Result<windows_future::IAsyncOperation<ContentDialogResult>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ShowAsync)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IContentDialog_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Title: usize,
    SetTitle: usize,
    TitleTemplate: usize,
    SetTitleTemplate: usize,
    FullSizeDesired: usize,
    SetFullSizeDesired: usize,
    PrimaryButtonText: usize,
    SetPrimaryButtonText: usize,
    SecondaryButtonText: usize,
    SetSecondaryButtonText: usize,
    CloseButtonText: usize,
    SetCloseButtonText: usize,
    PrimaryButtonCommand: usize,
    SetPrimaryButtonCommand: usize,
    SecondaryButtonCommand: usize,
    SetSecondaryButtonCommand: usize,
    CloseButtonCommand: usize,
    SetCloseButtonCommand: usize,
    PrimaryButtonCommandParameter: usize,
    SetPrimaryButtonCommandParameter: usize,
    SecondaryButtonCommandParameter: usize,
    SetSecondaryButtonCommandParameter: usize,
    CloseButtonCommandParameter: usize,
    SetCloseButtonCommandParameter: usize,
    IsPrimaryButtonEnabled: usize,
    SetIsPrimaryButtonEnabled: usize,
    IsSecondaryButtonEnabled: usize,
    SetIsSecondaryButtonEnabled: usize,
    PrimaryButtonStyle: usize,
    SetPrimaryButtonStyle: usize,
    SecondaryButtonStyle: usize,
    SetSecondaryButtonStyle: usize,
    CloseButtonStyle: usize,
    SetCloseButtonStyle: usize,
    DefaultButton: usize,
    SetDefaultButton: usize,
    pub Closing: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveClosing:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    Closed: usize,
    RemoveClosed: usize,
    Opened: usize,
    RemoveOpened: usize,
    PrimaryButtonClick: usize,
    RemovePrimaryButtonClick: usize,
    SecondaryButtonClick: usize,
    RemoveSecondaryButtonClick: usize,
    CloseButtonClick: usize,
    RemoveCloseButtonClick: usize,
    pub Hide: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
    pub ShowAsync: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IContentDialogClosingEventArgs,
    IContentDialogClosingEventArgs_Vtbl,
    0x12782103_3b80_511c_9128_12cb8cdac444
);
impl windows_core::RuntimeType for IContentDialogClosingEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IContentDialogClosingEventArgs {
    pub fn SetCancel(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetCancel)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IContentDialogClosingEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Result: usize,
    Cancel: usize,
    pub SetCancel: unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IContentDialogFactory,
    IContentDialogFactory_Vtbl,
    0xa05b3ad7_c60e_545a_9ee4_f098220ed816
);
impl windows_core::RuntimeType for IContentDialogFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IContentDialogFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IControl,
    IControl_Vtbl,
    0x857d6e8a_d45a_5c69_a99c_bf6a5c54fb38
);
impl windows_core::RuntimeType for IControl {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IControl {
    pub fn SetFontSize(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetFontSize)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetForeground<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Brush>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetForeground)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetIsEnabled(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsEnabled)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetPadding(&self, value: Thickness) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetPadding)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetHorizontalContentAlignment(
        &self,
        value: HorizontalAlignment,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetHorizontalContentAlignment)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetBackground<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Brush>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetBackground)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetBorderThickness(&self, value: Thickness) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetBorderThickness)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetCornerRadius(&self, value: CornerRadius) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetCornerRadius)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IControl_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    IsFocusEngagementEnabled: usize,
    SetIsFocusEngagementEnabled: usize,
    IsFocusEngaged: usize,
    SetIsFocusEngaged: usize,
    RequiresPointer: usize,
    SetRequiresPointer: usize,
    FontSize: usize,
    pub SetFontSize:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    FontFamily: usize,
    SetFontFamily: usize,
    FontWeight: usize,
    SetFontWeight: usize,
    FontStyle: usize,
    SetFontStyle: usize,
    FontStretch: usize,
    SetFontStretch: usize,
    CharacterSpacing: usize,
    SetCharacterSpacing: usize,
    Foreground: usize,
    pub SetForeground: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    IsTextScaleFactorEnabled: usize,
    SetIsTextScaleFactorEnabled: usize,
    IsEnabled: usize,
    pub SetIsEnabled:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    TabNavigation: usize,
    SetTabNavigation: usize,
    Template: usize,
    SetTemplate: usize,
    Padding: usize,
    pub SetPadding:
        unsafe extern "system" fn(*mut core::ffi::c_void, Thickness) -> windows_core::HRESULT,
    HorizontalContentAlignment: usize,
    pub SetHorizontalContentAlignment: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        HorizontalAlignment,
    ) -> windows_core::HRESULT,
    VerticalContentAlignment: usize,
    SetVerticalContentAlignment: usize,
    Background: usize,
    pub SetBackground: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    BackgroundSizing: usize,
    SetBackgroundSizing: usize,
    BorderThickness: usize,
    pub SetBorderThickness:
        unsafe extern "system" fn(*mut core::ffi::c_void, Thickness) -> windows_core::HRESULT,
    BorderBrush: usize,
    SetBorderBrush: usize,
    DefaultStyleResourceUri: usize,
    SetDefaultStyleResourceUri: usize,
    ElementSoundMode: usize,
    SetElementSoundMode: usize,
    CornerRadius: usize,
    pub SetCornerRadius:
        unsafe extern "system" fn(*mut core::ffi::c_void, CornerRadius) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ICryptographicBufferStatics,
    ICryptographicBufferStatics_Vtbl,
    0x320b7e22_3cb0_4cdf_8663_1d28910065eb
);
impl windows_core::RuntimeType for ICryptographicBufferStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ICryptographicBufferStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Compare: usize,
    GenerateRandom: usize,
    GenerateRandomNumber: usize,
    CreateFromByteArray: usize,
    pub CopyToByteArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut u8,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IDataTemplate,
    IDataTemplate_Vtbl,
    0x08fa70fa_ee75_5e92_a101_f52d0e1e9fab
);
impl windows_core::RuntimeType for IDataTemplate {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IDataTemplate_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IDependencyObject,
    IDependencyObject_Vtbl,
    0xe7beaee7_160e_50f7_8789_d63463f979fa
);
impl windows_core::RuntimeType for IDependencyObject {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IDependencyObject_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IDispatcherQueue,
    IDispatcherQueue_Vtbl,
    0xf6ebf8fa_be1c_5bf6_a467_73da28738ae8
);
impl windows_core::RuntimeType for IDispatcherQueue {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IDispatcherQueue {
    pub fn CreateTimer(&self) -> windows_core::Result<DispatcherQueueTimer> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).CreateTimer)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn TryEnqueueWithPriority<P1>(
        &self,
        priority: DispatcherQueuePriority,
        callback: P1,
    ) -> windows_core::Result<bool>
    where
        P1: windows_core::Param<DispatcherQueueHandler>,
    {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).TryEnqueueWithPriority)(
                windows_core::Interface::as_raw(self),
                priority,
                callback.param().abi(),
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IDispatcherQueue_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateTimer: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    TryEnqueue: usize,
    pub TryEnqueueWithPriority: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        DispatcherQueuePriority,
        *mut core::ffi::c_void,
        *mut bool,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IDispatcherQueueStatics,
    IDispatcherQueueStatics_Vtbl,
    0xcd3382ea_a455_5124_b63a_ca40d34ca23c
);
impl windows_core::RuntimeType for IDispatcherQueueStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IDispatcherQueueStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub GetForCurrentThread: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IDispatcherQueueTimer,
    IDispatcherQueueTimer_Vtbl,
    0xad4d63fd_88fe_541f_ac11_bf2dc1ed2ce5
);
impl windows_core::RuntimeType for IDispatcherQueueTimer {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IDispatcherQueueTimer {
    pub fn SetInterval(&self, value: windows_time::TimeSpan) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetInterval)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetIsRepeating(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsRepeating)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn Start(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Start)(windows_core::Interface::as_raw(self))
                .ok()
        }
    }
    pub fn Stop(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Stop)(windows_core::Interface::as_raw(self)).ok()
        }
    }
    pub fn Tick<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<DispatcherQueueTimer>,
                windows_core::Ref<windows_core::IInspectable>,
            ) + 'static,
    {
        let handler: TypedEventHandler<DispatcherQueueTimer, windows_core::IInspectable> = {
            let com = windows_core::imp::DelegateBox::< TypedEventHandler < DispatcherQueueTimer , windows_core::IInspectable > , F >::new (& TypedEventHandlerBox::< DispatcherQueueTimer , windows_core::IInspectable , F >::VTABLE , handler) ;
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Tick)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveTick,
            ))
        }
    }
}
#[repr(C)]
pub struct IDispatcherQueueTimer_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Interval: usize,
    pub SetInterval: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        windows_time::TimeSpan,
    ) -> windows_core::HRESULT,
    IsRunning: usize,
    IsRepeating: usize,
    pub SetIsRepeating:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    pub Start: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
    pub Stop: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
    pub Tick: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveTick: unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IDisplayArea,
    IDisplayArea_Vtbl,
    0x5c7e0537_b621_5579_bcae_a84aa8746167
);
impl windows_core::RuntimeType for IDisplayArea {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IDisplayArea {
    pub fn WorkArea(&self) -> windows_core::Result<RectInt32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).WorkArea)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IDisplayArea_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    DisplayId: usize,
    IsPrimary: usize,
    OuterBounds: usize,
    pub WorkArea:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut RectInt32) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IDisplayAreaStatics,
    IDisplayAreaStatics_Vtbl,
    0x02ab4926_211e_5d49_8e4b_2af193daed09
);
impl windows_core::RuntimeType for IDisplayAreaStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IDisplayAreaStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Primary: usize,
    CreateWatcher: usize,
    FindAll: usize,
    pub GetFromWindowId: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        WindowId,
        DisplayAreaFallback,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IDoubleTappedRoutedEventArgs,
    IDoubleTappedRoutedEventArgs_Vtbl,
    0x32b9549d_11d8_53a5_a953_02409537a11f
);
impl windows_core::RuntimeType for IDoubleTappedRoutedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IDoubleTappedRoutedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IDragItemsCompletedEventArgs,
    IDragItemsCompletedEventArgs_Vtbl,
    0xc0138552_f467_5c3e_8af4_593607762844
);
impl windows_core::RuntimeType for IDragItemsCompletedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IDragItemsCompletedEventArgs {
    pub fn Items(
        &self,
    ) -> windows_core::Result<windows_collections::IVectorView<windows_core::IInspectable>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Items)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn DropResult(&self) -> windows_core::Result<DataPackageOperation> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).DropResult)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IDragItemsCompletedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Items: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub DropResult: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut DataPackageOperation,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFileOpenPicker,
    IFileOpenPicker_Vtbl,
    0x9d00f175_c783_51bd_8c93_fb63695d3abc
);
impl windows_core::RuntimeType for IFileOpenPicker {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IFileOpenPicker {
    pub fn FileTypeFilter(
        &self,
    ) -> windows_core::Result<windows_collections::IVector<windows_core::HSTRING>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).FileTypeFilter)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn PickSingleFileAsync(
        &self,
    ) -> windows_core::Result<windows_future::IAsyncOperation<PickFileResult>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).PickSingleFileAsync)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IFileOpenPicker_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    ViewMode: usize,
    SetViewMode: usize,
    SuggestedStartLocation: usize,
    SetSuggestedStartLocation: usize,
    CommitButtonText: usize,
    SetCommitButtonText: usize,
    pub FileTypeFilter: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub PickSingleFileAsync: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFileOpenPickerFactory,
    IFileOpenPickerFactory_Vtbl,
    0x315e86d7_d7a2_5d81_b379_7af78207b1af
);
impl windows_core::RuntimeType for IFileOpenPickerFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IFileOpenPickerFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        WindowId,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFlyout,
    IFlyout_Vtbl,
    0xd4a1eb7d_59b8_5df9_87c3_bd5e3856923f
);
impl windows_core::RuntimeType for IFlyout {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IFlyout {
    pub fn SetContent<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<UIElement>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetContent)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IFlyout_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Content: usize,
    pub SetContent: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFlyoutBase,
    IFlyoutBase_Vtbl,
    0xbb6603bf_744d_5c31_a87d_744394634d77
);
impl windows_core::RuntimeType for IFlyoutBase {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IFlyoutBase {
    pub fn SetPlacement(&self, value: FlyoutPlacementMode) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetPlacement)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn Hide(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Hide)(windows_core::Interface::as_raw(self)).ok()
        }
    }
}
#[repr(C)]
pub struct IFlyoutBase_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Placement: usize,
    pub SetPlacement: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        FlyoutPlacementMode,
    ) -> windows_core::HRESULT,
    Target: usize,
    AllowFocusOnInteraction: usize,
    SetAllowFocusOnInteraction: usize,
    LightDismissOverlayMode: usize,
    SetLightDismissOverlayMode: usize,
    AllowFocusWhenDisabled: usize,
    SetAllowFocusWhenDisabled: usize,
    ShowMode: usize,
    SetShowMode: usize,
    InputDevicePrefersPrimaryCommands: usize,
    AreOpenCloseAnimationsEnabled: usize,
    SetAreOpenCloseAnimationsEnabled: usize,
    ShouldConstrainToRootBounds: usize,
    SetShouldConstrainToRootBounds: usize,
    IsConstrainedToRootBounds: usize,
    ElementSoundMode: usize,
    SetElementSoundMode: usize,
    OverlayInputPassThroughElement: usize,
    SetOverlayInputPassThroughElement: usize,
    IsOpen: usize,
    XamlRoot: usize,
    SetXamlRoot: usize,
    Opened: usize,
    RemoveOpened: usize,
    Closed: usize,
    RemoveClosed: usize,
    Opening: usize,
    RemoveOpening: usize,
    Closing: usize,
    RemoveClosing: usize,
    ShowAt: usize,
    ShowAtWithOptions: usize,
    pub Hide: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFlyoutFactory,
    IFlyoutFactory_Vtbl,
    0xfd19002e_66b3_5656_b49c_b2aca11e9602
);
impl windows_core::RuntimeType for IFlyoutFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IFlyoutFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFocusManager,
    IFocusManager_Vtbl,
    0x9fd07bc5_d2d4_53fe_a31a_846de8b7a257
);
impl windows_core::RuntimeType for IFocusManager {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IFocusManager_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IFocusManagerStatics,
    IFocusManagerStatics_Vtbl,
    0xe73dce04_e23a_5fb3_96ab_7df04c51dff2
);
impl windows_core::RuntimeType for IFocusManagerStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IFocusManagerStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    GotFocus: usize,
    RemoveGotFocus: usize,
    LostFocus: usize,
    RemoveLostFocus: usize,
    GettingFocus: usize,
    RemoveGettingFocus: usize,
    LosingFocus: usize,
    RemoveLosingFocus: usize,
    TryFocusAsync: usize,
    TryMoveFocusAsync: usize,
    TryMoveFocusWithOptionsAsync: usize,
    TryMoveFocusWithOptions: usize,
    FindNextElement: usize,
    pub FindFirstFocusableElement: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFontFamily,
    IFontFamily_Vtbl,
    0x18fa5bc1_7294_527c_bb02_b213e0b3a2a3
);
impl windows_core::RuntimeType for IFontFamily {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IFontFamily_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IFontFamilyFactory,
    IFontFamilyFactory_Vtbl,
    0x61b88a77_d0f9_5e9e_8c28_eda01fede22e
);
impl windows_core::RuntimeType for IFontFamilyFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IFontFamilyFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstanceWithName: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFontIcon,
    IFontIcon_Vtbl,
    0x6eba5ed9_d233_5f5e_91a8_f5134292658a
);
impl windows_core::RuntimeType for IFontIcon {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IFontIcon {
    pub fn SetGlyph(&self, value: &str) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetGlyph)(
                windows_core::Interface::as_raw(self),
                core::mem::transmute_copy(&windows_core::HSTRING::from(value)),
            )
            .ok()
        }
    }
    pub fn SetFontSize(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetFontSize)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetFontFamily<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<FontFamily>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetFontFamily)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IFontIcon_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Glyph: usize,
    pub SetGlyph: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    FontSize: usize,
    pub SetFontSize:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    FontFamily: usize,
    pub SetFontFamily: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFontIconFactory,
    IFontIconFactory_Vtbl,
    0xaa9a24fe_bef8_564a_b200_694cd6f6ba4e
);
impl windows_core::RuntimeType for IFontIconFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IFontIconFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFrameworkElement,
    IFrameworkElement_Vtbl,
    0xfe08f13d_dc6a_5495_ad44_c2d8d21863b0
);
impl windows_core::RuntimeType for IFrameworkElement {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IFrameworkElement {
    pub fn Tag(&self) -> windows_core::Result<windows_core::IInspectable> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Tag)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetTag<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<windows_core::IInspectable>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetTag)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn ActualWidth(&self) -> windows_core::Result<f64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ActualWidth)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn ActualHeight(&self) -> windows_core::Result<f64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ActualHeight)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn Width(&self) -> windows_core::Result<f64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Width)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn SetWidth(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetWidth)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetHeight(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetHeight)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetMinWidth(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetMinWidth)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetMaxWidth(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetMaxWidth)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetMinHeight(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetMinHeight)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn MaxHeight(&self) -> windows_core::Result<f64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).MaxHeight)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn SetMaxHeight(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetMaxHeight)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetHorizontalAlignment(&self, value: HorizontalAlignment) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetHorizontalAlignment)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetVerticalAlignment(&self, value: VerticalAlignment) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetVerticalAlignment)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetMargin(&self, value: Thickness) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetMargin)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetStyle<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Style>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetStyle)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn Parent(&self) -> windows_core::Result<DependencyObject> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Parent)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetRequestedTheme(&self, value: ElementTheme) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetRequestedTheme)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn Loaded<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<RoutedEventArgs>)
            + 'static,
    {
        let handler: RoutedEventHandler = {
            let com = windows_core::imp::DelegateBox::<RoutedEventHandler, F>::new(
                &RoutedEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Loaded)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveLoaded,
            ))
        }
    }
    pub fn SizeChanged<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<SizeChangedEventArgs>,
            ) + 'static,
    {
        let handler: SizeChangedEventHandler = {
            let com = windows_core::imp::DelegateBox::<SizeChangedEventHandler, F>::new(
                &SizeChangedEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).SizeChanged)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveSizeChanged,
            ))
        }
    }
}
#[repr(C)]
pub struct IFrameworkElement_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Triggers: usize,
    Resources: usize,
    SetResources: usize,
    pub Tag: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetTag: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    Language: usize,
    SetLanguage: usize,
    pub ActualWidth:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut f64) -> windows_core::HRESULT,
    pub ActualHeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut f64) -> windows_core::HRESULT,
    pub Width: unsafe extern "system" fn(*mut core::ffi::c_void, *mut f64) -> windows_core::HRESULT,
    pub SetWidth: unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    Height: usize,
    pub SetHeight: unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    MinWidth: usize,
    pub SetMinWidth:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    MaxWidth: usize,
    pub SetMaxWidth:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    MinHeight: usize,
    pub SetMinHeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    pub MaxHeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut f64) -> windows_core::HRESULT,
    pub SetMaxHeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    HorizontalAlignment: usize,
    pub SetHorizontalAlignment: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        HorizontalAlignment,
    ) -> windows_core::HRESULT,
    VerticalAlignment: usize,
    pub SetVerticalAlignment: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        VerticalAlignment,
    ) -> windows_core::HRESULT,
    Margin: usize,
    pub SetMargin:
        unsafe extern "system" fn(*mut core::ffi::c_void, Thickness) -> windows_core::HRESULT,
    Name: usize,
    SetName: usize,
    BaseUri: usize,
    DataContext: usize,
    SetDataContext: usize,
    AllowFocusOnInteraction: usize,
    SetAllowFocusOnInteraction: usize,
    FocusVisualMargin: usize,
    SetFocusVisualMargin: usize,
    FocusVisualSecondaryThickness: usize,
    SetFocusVisualSecondaryThickness: usize,
    FocusVisualPrimaryThickness: usize,
    SetFocusVisualPrimaryThickness: usize,
    FocusVisualSecondaryBrush: usize,
    SetFocusVisualSecondaryBrush: usize,
    FocusVisualPrimaryBrush: usize,
    SetFocusVisualPrimaryBrush: usize,
    AllowFocusWhenDisabled: usize,
    SetAllowFocusWhenDisabled: usize,
    Style: usize,
    pub SetStyle: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub Parent: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    FlowDirection: usize,
    SetFlowDirection: usize,
    RequestedTheme: usize,
    pub SetRequestedTheme:
        unsafe extern "system" fn(*mut core::ffi::c_void, ElementTheme) -> windows_core::HRESULT,
    IsLoaded: usize,
    ActualTheme: usize,
    pub Loaded: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveLoaded:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    Unloaded: usize,
    RemoveUnloaded: usize,
    DataContextChanged: usize,
    RemoveDataContextChanged: usize,
    pub SizeChanged: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveSizeChanged:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IFrameworkTemplate,
    IFrameworkTemplate_Vtbl,
    0x0084c7c2_de48_5b0b_8a5a_e4fb76b7f7d1
);
impl windows_core::RuntimeType for IFrameworkTemplate {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IFrameworkTemplate_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IGeneralTransform,
    IGeneralTransform_Vtbl,
    0x04eedeeb_31e5_54c0_ae3f_8bd06645d339
);
impl windows_core::RuntimeType for IGeneralTransform {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IGeneralTransform {
    pub fn TransformBounds(&self, rect: Rect) -> windows_core::Result<Rect> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).TransformBounds)(
                windows_core::Interface::as_raw(self),
                rect,
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IGeneralTransform_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Inverse: usize,
    TransformPoint: usize,
    TryTransform: usize,
    pub TransformBounds:
        unsafe extern "system" fn(*mut core::ffi::c_void, Rect, *mut Rect) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IGeometry,
    IGeometry_Vtbl,
    0xdc102dcc_3be2_5414_8599_94b6e76ef39b
);
impl windows_core::RuntimeType for IGeometry {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IGeometry_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(IGrid, IGrid_Vtbl, 0xc4496219_9014_58a1_b4ad_c5044913a5bb);
impl windows_core::RuntimeType for IGrid {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IGrid {
    pub fn RowDefinitions(&self) -> windows_core::Result<RowDefinitionCollection> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).RowDefinitions)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn ColumnDefinitions(&self) -> windows_core::Result<ColumnDefinitionCollection> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ColumnDefinitions)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetBorderBrush<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Brush>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetBorderBrush)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetBorderThickness(&self, value: Thickness) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetBorderThickness)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetCornerRadius(&self, value: CornerRadius) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetCornerRadius)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetPadding(&self, value: Thickness) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetPadding)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetRowSpacing(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetRowSpacing)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetColumnSpacing(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetColumnSpacing)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IGrid_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub RowDefinitions: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub ColumnDefinitions: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    BackgroundSizing: usize,
    SetBackgroundSizing: usize,
    BorderBrush: usize,
    pub SetBorderBrush: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    BorderThickness: usize,
    pub SetBorderThickness:
        unsafe extern "system" fn(*mut core::ffi::c_void, Thickness) -> windows_core::HRESULT,
    CornerRadius: usize,
    pub SetCornerRadius:
        unsafe extern "system" fn(*mut core::ffi::c_void, CornerRadius) -> windows_core::HRESULT,
    Padding: usize,
    pub SetPadding:
        unsafe extern "system" fn(*mut core::ffi::c_void, Thickness) -> windows_core::HRESULT,
    RowSpacing: usize,
    pub SetRowSpacing:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    ColumnSpacing: usize,
    pub SetColumnSpacing:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IGridFactory,
    IGridFactory_Vtbl,
    0xb16bf561_fc6c_57c6_8ebc_0b06ce4513aa
);
impl windows_core::RuntimeType for IGridFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IGridFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IGridStatics,
    IGridStatics_Vtbl,
    0xef9cf81d_a431_50f4_abf5_3023fe447704
);
impl windows_core::RuntimeType for IGridStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IGridStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    BackgroundSizingProperty: usize,
    BorderBrushProperty: usize,
    BorderThicknessProperty: usize,
    CornerRadiusProperty: usize,
    PaddingProperty: usize,
    RowSpacingProperty: usize,
    ColumnSpacingProperty: usize,
    RowProperty: usize,
    GetRow: usize,
    pub SetRow: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        i32,
    ) -> windows_core::HRESULT,
    ColumnProperty: usize,
    GetColumn: usize,
    pub SetColumn: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        i32,
    ) -> windows_core::HRESULT,
    RowSpanProperty: usize,
    GetRowSpan: usize,
    pub SetRowSpan: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        i32,
    ) -> windows_core::HRESULT,
    ColumnSpanProperty: usize,
    GetColumnSpan: usize,
    pub SetColumnSpan: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        i32,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IGridView,
    IGridView_Vtbl,
    0xd495f2fa_594d_5170_b1e8_8629a179f9fb
);
impl windows_core::RuntimeType for IGridView {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IGridView_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IGridViewFactory,
    IGridViewFactory_Vtbl,
    0x892947ea_6b86_5f17_a9b8_2121b2251271
);
impl windows_core::RuntimeType for IGridViewFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IGridViewFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IIconElement,
    IIconElement_Vtbl,
    0x18f69350_279e_50ea_8d23_138e717ed939
);
impl windows_core::RuntimeType for IIconElement {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IIconElement_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(IImage, IImage_Vtbl, 0x220d3d8d_66de_53a1_a215_ba9c165565ab);
impl windows_core::RuntimeType for IImage {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IImage {
    pub fn SetSource<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<ImageSource>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetSource)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IImage_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Source: usize,
    pub SetSource: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IImageSource,
    IImageSource_Vtbl,
    0x6c2038f6_d6d5_55e9_9b9e_082f12dbff60
);
impl windows_core::RuntimeType for IImageSource {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IImageSource_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IInputNonClientPointerSource,
    IInputNonClientPointerSource_Vtbl,
    0x471732b4_3d07_5104_b192_ebacf71e86df
);
impl windows_core::RuntimeType for IInputNonClientPointerSource {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IInputNonClientPointerSource {
    pub fn ClearRegionRects(&self, region: NonClientRegionKind) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).ClearRegionRects)(
                windows_core::Interface::as_raw(self),
                region,
            )
            .ok()
        }
    }
    pub fn SetRegionRects(
        &self,
        region: NonClientRegionKind,
        rects: &[RectInt32],
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetRegionRects)(
                windows_core::Interface::as_raw(self),
                region,
                rects.len().try_into().unwrap(),
                rects.as_ptr(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IInputNonClientPointerSource_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    DispatcherQueue: usize,
    ClearAllRegionRects: usize,
    pub ClearRegionRects: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        NonClientRegionKind,
    ) -> windows_core::HRESULT,
    GetRegionRects: usize,
    pub SetRegionRects: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        NonClientRegionKind,
        u32,
        *const RectInt32,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IInputNonClientPointerSourceStatics,
    IInputNonClientPointerSourceStatics_Vtbl,
    0x7d0b775c_1903_5dc7_bd2f_7a4b31f0cff2
);
impl windows_core::RuntimeType for IInputNonClientPointerSourceStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IInputNonClientPointerSourceStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub GetForWindowId: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        WindowId,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IIsTextTrimmedChangedEventArgs,
    IIsTextTrimmedChangedEventArgs_Vtbl,
    0x3c709b2f_16ba_55d2_b6f6_dfc54a1ed021
);
impl windows_core::RuntimeType for IIsTextTrimmedChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IIsTextTrimmedChangedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IItemClickEventArgs,
    IItemClickEventArgs_Vtbl,
    0x1cf87a70_6348_57ec_9eac_fa0565adc60f
);
impl windows_core::RuntimeType for IItemClickEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IItemClickEventArgs {
    pub fn ClickedItem(&self) -> windows_core::Result<windows_core::IInspectable> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ClickedItem)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IItemClickEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub ClickedItem: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IItemContainer,
    IItemContainer_Vtbl,
    0x6332a67f_7fd9_53c7_afd8_cfa1237cf6d1
);
impl windows_core::RuntimeType for IItemContainer {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IItemContainer_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IItemContainerMapping,
    IItemContainerMapping_Vtbl,
    0xb3e03a32_ea83_5626_bfda_d327a1c7550c
);
impl windows_core::RuntimeType for IItemContainerMapping {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
windows_core::imp::interface_hierarchy!(
    IItemContainerMapping,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl IItemContainerMapping {
    pub fn ContainerFromIndex(&self, index: i32) -> windows_core::Result<DependencyObject> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ContainerFromIndex)(
                windows_core::Interface::as_raw(self),
                index,
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IItemContainerMapping_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    ItemFromContainer: usize,
    ContainerFromItem: usize,
    IndexFromContainer: usize,
    pub ContainerFromIndex: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        i32,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IItemIndexRange,
    IItemIndexRange_Vtbl,
    0xeba09846_2554_5b86_ac17_614f05105fa2
);
impl windows_core::RuntimeType for IItemIndexRange {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IItemIndexRange_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IItemsControl,
    IItemsControl_Vtbl,
    0xbf1ccb54_83e2_5b98_acbc_736f876c3d35
);
impl windows_core::RuntimeType for IItemsControl {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IItemsControl {
    pub fn Items(&self) -> windows_core::Result<ItemCollection> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Items)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetItemTemplate<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<DataTemplate>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetItemTemplate)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetItemsPanel<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<ItemsPanelTemplate>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetItemsPanel)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn ItemsPanelRoot(&self) -> windows_core::Result<Panel> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ItemsPanelRoot)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetItemContainerStyle<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Style>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetItemContainerStyle)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IItemsControl_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    ItemsSource: usize,
    SetItemsSource: usize,
    pub Items: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    ItemTemplate: usize,
    pub SetItemTemplate: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    ItemTemplateSelector: usize,
    SetItemTemplateSelector: usize,
    ItemsPanel: usize,
    pub SetItemsPanel: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    DisplayMemberPath: usize,
    SetDisplayMemberPath: usize,
    pub ItemsPanelRoot: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    ItemContainerStyle: usize,
    pub SetItemContainerStyle: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IItemsPanelTemplate,
    IItemsPanelTemplate_Vtbl,
    0x6153af2f_f095_5e8c_89d4_9e03203b9cc2
);
impl windows_core::RuntimeType for IItemsPanelTemplate {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IItemsPanelTemplate_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IItemsWrapGrid,
    IItemsWrapGrid_Vtbl,
    0x29910bc5_b305_5529_b88c_776c66e1b3ba
);
impl windows_core::RuntimeType for IItemsWrapGrid {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IItemsWrapGrid {
    pub fn SetItemWidth(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetItemWidth)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetItemHeight(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetItemHeight)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IItemsWrapGrid_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    GroupPadding: usize,
    SetGroupPadding: usize,
    Orientation: usize,
    SetOrientation: usize,
    MaximumRowsOrColumns: usize,
    SetMaximumRowsOrColumns: usize,
    ItemWidth: usize,
    pub SetItemWidth:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    ItemHeight: usize,
    pub SetItemHeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IKeyRoutedEventArgs,
    IKeyRoutedEventArgs_Vtbl,
    0xee357007_a2d6_5c75_9431_05fd66ec7915
);
impl windows_core::RuntimeType for IKeyRoutedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IKeyRoutedEventArgs {
    pub fn Key(&self) -> windows_core::Result<VirtualKey> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Key)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn SetHandled(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetHandled)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IKeyRoutedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Key:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut VirtualKey) -> windows_core::HRESULT,
    KeyStatus: usize,
    Handled: usize,
    pub SetHandled:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IKeyboardAccelerator,
    IKeyboardAccelerator_Vtbl,
    0x6f8bf1e2_4e91_5cf9_a6be_4770caf3d770
);
impl windows_core::RuntimeType for IKeyboardAccelerator {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IKeyboardAccelerator {
    pub fn SetKey(&self, value: VirtualKey) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetKey)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetModifiers(&self, value: VirtualKeyModifiers) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetModifiers)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn Invoked<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<KeyboardAccelerator>,
                windows_core::Ref<KeyboardAcceleratorInvokedEventArgs>,
            ) + 'static,
    {
        let handler: TypedEventHandler<KeyboardAccelerator, KeyboardAcceleratorInvokedEventArgs> = {
            let com =
                windows_core::imp::DelegateBox::<
                    TypedEventHandler<KeyboardAccelerator, KeyboardAcceleratorInvokedEventArgs>,
                    F,
                >::new(
                    &TypedEventHandlerBox::<
                        KeyboardAccelerator,
                        KeyboardAcceleratorInvokedEventArgs,
                        F,
                    >::VTABLE,
                    handler,
                );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Invoked)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveInvoked,
            ))
        }
    }
}
#[repr(C)]
pub struct IKeyboardAccelerator_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Key: usize,
    pub SetKey:
        unsafe extern "system" fn(*mut core::ffi::c_void, VirtualKey) -> windows_core::HRESULT,
    Modifiers: usize,
    pub SetModifiers: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        VirtualKeyModifiers,
    ) -> windows_core::HRESULT,
    IsEnabled: usize,
    SetIsEnabled: usize,
    ScopeOwner: usize,
    SetScopeOwner: usize,
    pub Invoked: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveInvoked:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IKeyboardAcceleratorFactory,
    IKeyboardAcceleratorFactory_Vtbl,
    0xca1d410a_af2a_51b9_a1de_6c0af9f3b598
);
impl windows_core::RuntimeType for IKeyboardAcceleratorFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IKeyboardAcceleratorFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IKeyboardAcceleratorInvokedEventArgs,
    IKeyboardAcceleratorInvokedEventArgs_Vtbl,
    0x62c9fdb0_b574_527d_97eb_5c7f674441e0
);
impl windows_core::RuntimeType for IKeyboardAcceleratorInvokedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IKeyboardAcceleratorInvokedEventArgs {
    pub fn SetHandled(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetHandled)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IKeyboardAcceleratorInvokedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Handled: usize,
    pub SetHandled:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ILaunchActivatedEventArgs,
    ILaunchActivatedEventArgs_Vtbl,
    0xd505cea9_1bcb_5b29_a8be_944e00f06f78
);
impl windows_core::RuntimeType for ILaunchActivatedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ILaunchActivatedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IListView,
    IListView_Vtbl,
    0xf6015db1_df63_52fd_a164_0df44715ee0a
);
impl windows_core::RuntimeType for IListView {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IListView_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IListViewBase,
    IListViewBase_Vtbl,
    0x775c57ac_abce_5beb_8e34_3b8158aedd80
);
impl windows_core::RuntimeType for IListViewBase {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IListViewBase {
    pub fn SelectedItems(
        &self,
    ) -> windows_core::Result<windows_collections::IVector<windows_core::IInspectable>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).SelectedItems)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetSelectionMode(&self, value: ListViewSelectionMode) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetSelectionMode)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetCanDragItems(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetCanDragItems)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetCanReorderItems(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetCanReorderItems)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetIsItemClickEnabled(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsItemClickEnabled)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn ItemClick<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<ItemClickEventArgs>)
            + 'static,
    {
        let handler: ItemClickEventHandler = {
            let com = windows_core::imp::DelegateBox::<ItemClickEventHandler, F>::new(
                &ItemClickEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).ItemClick)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveItemClick,
            ))
        }
    }
    pub fn DragItemsCompleted<F>(
        &self,
        handler: F,
    ) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<ListViewBase>, windows_core::Ref<DragItemsCompletedEventArgs>)
            + 'static,
    {
        let handler: TypedEventHandler<ListViewBase, DragItemsCompletedEventArgs> = {
            let com = windows_core::imp::DelegateBox::<
                TypedEventHandler<ListViewBase, DragItemsCompletedEventArgs>,
                F,
            >::new(
                &TypedEventHandlerBox::<ListViewBase, DragItemsCompletedEventArgs, F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).DragItemsCompleted)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveDragItemsCompleted,
            ))
        }
    }
    pub fn ContainerContentChanging<F>(
        &self,
        handler: F,
    ) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<ListViewBase>,
                windows_core::Ref<ContainerContentChangingEventArgs>,
            ) + 'static,
    {
        let handler: TypedEventHandler<ListViewBase, ContainerContentChangingEventArgs> = {
            let com = windows_core::imp::DelegateBox::<
                TypedEventHandler<ListViewBase, ContainerContentChangingEventArgs>,
                F,
            >::new(
                &TypedEventHandlerBox::<ListViewBase, ContainerContentChangingEventArgs, F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).ContainerContentChanging)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveContainerContentChanging,
            ))
        }
    }
    pub fn ScrollIntoView<P0>(&self, item: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<windows_core::IInspectable>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).ScrollIntoView)(
                windows_core::Interface::as_raw(self),
                item.param().abi(),
            )
            .ok()
        }
    }
    pub fn SelectRange<P0>(&self, itemindexrange: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<ItemIndexRange>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SelectRange)(
                windows_core::Interface::as_raw(self),
                itemindexrange.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IListViewBase_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub SelectedItems: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    SelectionMode: usize,
    pub SetSelectionMode: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        ListViewSelectionMode,
    ) -> windows_core::HRESULT,
    IsSwipeEnabled: usize,
    SetIsSwipeEnabled: usize,
    CanDragItems: usize,
    pub SetCanDragItems:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    CanReorderItems: usize,
    pub SetCanReorderItems:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    IsItemClickEnabled: usize,
    pub SetIsItemClickEnabled:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    DataFetchSize: usize,
    SetDataFetchSize: usize,
    IncrementalLoadingThreshold: usize,
    SetIncrementalLoadingThreshold: usize,
    IncrementalLoadingTrigger: usize,
    SetIncrementalLoadingTrigger: usize,
    ShowsScrollingPlaceholders: usize,
    SetShowsScrollingPlaceholders: usize,
    ReorderMode: usize,
    SetReorderMode: usize,
    SelectedRanges: usize,
    IsMultiSelectCheckBoxEnabled: usize,
    SetIsMultiSelectCheckBoxEnabled: usize,
    SingleSelectionFollowsFocus: usize,
    SetSingleSelectionFollowsFocus: usize,
    pub ItemClick: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveItemClick:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    DragItemsStarting: usize,
    RemoveDragItemsStarting: usize,
    pub DragItemsCompleted: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveDragItemsCompleted:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    pub ContainerContentChanging: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveContainerContentChanging:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    ChoosingItemContainer: usize,
    RemoveChoosingItemContainer: usize,
    ChoosingGroupHeaderContainer: usize,
    RemoveChoosingGroupHeaderContainer: usize,
    pub ScrollIntoView: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    SelectAll: usize,
    LoadMoreItemsAsync: usize,
    ScrollIntoViewWithAlignment: usize,
    SetDesiredContainerUpdateDuration: usize,
    pub SelectRange: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IListViewFactory,
    IListViewFactory_Vtbl,
    0x03ebefb8_f64a_5bf9_9570_cb09eeea2335
);
impl windows_core::RuntimeType for IListViewFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IListViewFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IListViewItem,
    IListViewItem_Vtbl,
    0x05fe41c2_0451_5d38_9c55_5d10cfd08889
);
impl windows_core::RuntimeType for IListViewItem {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IListViewItem_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IMicaBackdrop,
    IMicaBackdrop_Vtbl,
    0xc156a404_3dac_593a_b1f3_7a33c289dc83
);
impl windows_core::RuntimeType for IMicaBackdrop {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IMicaBackdrop_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IMicaBackdropFactory,
    IMicaBackdropFactory_Vtbl,
    0x774379ce_74bd_59d4_849d_d99c4184d838
);
impl windows_core::RuntimeType for IMicaBackdropFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IMicaBackdropFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
pub const INVALID_HANDLE_VALUE: HANDLE = -1 as _;
windows_core::imp::define_interface!(
    INavigationView,
    INavigationView_Vtbl,
    0xe77a4b36_3dd1_53d9_9f97_65dccaa74a5c
);
impl windows_core::RuntimeType for INavigationView {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl INavigationView {
    pub fn SetIsSettingsVisible(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsSettingsVisible)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetIsPaneToggleButtonVisible(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsPaneToggleButtonVisible)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetAlwaysShowHeader(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetAlwaysShowHeader)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetOpenPaneLength(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetOpenPaneLength)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetSelectedItem<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<windows_core::IInspectable>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetSelectedItem)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn MenuItems(
        &self,
    ) -> windows_core::Result<windows_collections::IVector<windows_core::IInspectable>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).MenuItems)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SelectionChanged<F>(
        &self,
        handler: F,
    ) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<NavigationView>,
                windows_core::Ref<NavigationViewSelectionChangedEventArgs>,
            ) + 'static,
    {
        let handler: TypedEventHandler<NavigationView, NavigationViewSelectionChangedEventArgs> = {
            let com =
                windows_core::imp::DelegateBox::<
                    TypedEventHandler<NavigationView, NavigationViewSelectionChangedEventArgs>,
                    F,
                >::new(
                    &TypedEventHandlerBox::<
                        NavigationView,
                        NavigationViewSelectionChangedEventArgs,
                        F,
                    >::VTABLE,
                    handler,
                );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).SelectionChanged)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveSelectionChanged,
            ))
        }
    }
    pub fn SetIsTitleBarAutoPaddingEnabled(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsTitleBarAutoPaddingEnabled)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct INavigationView_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    IsPaneOpen: usize,
    SetIsPaneOpen: usize,
    CompactModeThresholdWidth: usize,
    SetCompactModeThresholdWidth: usize,
    ExpandedModeThresholdWidth: usize,
    SetExpandedModeThresholdWidth: usize,
    FooterMenuItems: usize,
    FooterMenuItemsSource: usize,
    SetFooterMenuItemsSource: usize,
    PaneFooter: usize,
    SetPaneFooter: usize,
    Header: usize,
    SetHeader: usize,
    HeaderTemplate: usize,
    SetHeaderTemplate: usize,
    DisplayMode: usize,
    IsSettingsVisible: usize,
    pub SetIsSettingsVisible:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    IsPaneToggleButtonVisible: usize,
    pub SetIsPaneToggleButtonVisible:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    AlwaysShowHeader: usize,
    pub SetAlwaysShowHeader:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    CompactPaneLength: usize,
    SetCompactPaneLength: usize,
    OpenPaneLength: usize,
    pub SetOpenPaneLength:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    PaneToggleButtonStyle: usize,
    SetPaneToggleButtonStyle: usize,
    SelectedItem: usize,
    pub SetSelectedItem: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub MenuItems: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    MenuItemsSource: usize,
    SetMenuItemsSource: usize,
    SettingsItem: usize,
    AutoSuggestBox: usize,
    SetAutoSuggestBox: usize,
    MenuItemTemplate: usize,
    SetMenuItemTemplate: usize,
    MenuItemTemplateSelector: usize,
    SetMenuItemTemplateSelector: usize,
    MenuItemContainerStyle: usize,
    SetMenuItemContainerStyle: usize,
    MenuItemContainerStyleSelector: usize,
    SetMenuItemContainerStyleSelector: usize,
    MenuItemFromContainer: usize,
    ContainerFromMenuItem: usize,
    pub SelectionChanged: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveSelectionChanged:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    ItemInvoked: usize,
    RemoveItemInvoked: usize,
    DisplayModeChanged: usize,
    RemoveDisplayModeChanged: usize,
    IsTitleBarAutoPaddingEnabled: usize,
    pub SetIsTitleBarAutoPaddingEnabled:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    INavigationView2,
    INavigationView2_Vtbl,
    0x05b428cf_014c_56dd_896a_a3e7089d73b5
);
impl windows_core::RuntimeType for INavigationView2 {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl INavigationView2 {
    pub fn SetIsBackButtonVisible(
        &self,
        value: NavigationViewBackButtonVisible,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsBackButtonVisible)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetPaneDisplayMode(
        &self,
        value: NavigationViewPaneDisplayMode,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetPaneDisplayMode)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetPaneHeader<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<UIElement>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetPaneHeader)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct INavigationView2_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    IsBackButtonVisible: usize,
    pub SetIsBackButtonVisible: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        NavigationViewBackButtonVisible,
    ) -> windows_core::HRESULT,
    IsBackEnabled: usize,
    SetIsBackEnabled: usize,
    PaneTitle: usize,
    SetPaneTitle: usize,
    BackRequested: usize,
    RemoveBackRequested: usize,
    PaneClosed: usize,
    RemovePaneClosed: usize,
    PaneClosing: usize,
    RemovePaneClosing: usize,
    PaneOpened: usize,
    RemovePaneOpened: usize,
    PaneOpening: usize,
    RemovePaneOpening: usize,
    PaneDisplayMode: usize,
    pub SetPaneDisplayMode: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        NavigationViewPaneDisplayMode,
    ) -> windows_core::HRESULT,
    PaneHeader: usize,
    pub SetPaneHeader: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    INavigationViewFactory,
    INavigationViewFactory_Vtbl,
    0xffea1ada_9232_5507_a320_ed2fadbe6127
);
impl windows_core::RuntimeType for INavigationViewFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct INavigationViewFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    INavigationViewItem,
    INavigationViewItem_Vtbl,
    0x3ab3d503_a37c_5836_8adb_2882062e73a1
);
impl windows_core::RuntimeType for INavigationViewItem {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl INavigationViewItem {
    pub fn SetIcon<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<IconElement>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetIcon)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct INavigationViewItem_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Icon: usize,
    pub SetIcon: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    INavigationViewItemBase,
    INavigationViewItemBase_Vtbl,
    0x33586494_af48_513f_be4d_f645e8c89005
);
impl windows_core::RuntimeType for INavigationViewItemBase {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct INavigationViewItemBase_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    INavigationViewItemFactory,
    INavigationViewItemFactory_Vtbl,
    0xde60a001_9385_5535_80e1_2b68f4bfde26
);
impl windows_core::RuntimeType for INavigationViewItemFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct INavigationViewItemFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    INavigationViewSelectionChangedEventArgs,
    INavigationViewSelectionChangedEventArgs_Vtbl,
    0x14a064a5_c79d_5f63_ac6e_1c313fe63566
);
impl windows_core::RuntimeType for INavigationViewSelectionChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl INavigationViewSelectionChangedEventArgs {
    pub fn SelectedItem(&self) -> windows_core::Result<windows_core::IInspectable> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).SelectedItem)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct INavigationViewSelectionChangedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub SelectedItem: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IOverlappedPresenter,
    IOverlappedPresenter_Vtbl,
    0x21693970_4f4c_5172_9e9d_682a2d174884
);
impl windows_core::RuntimeType for IOverlappedPresenter {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IOverlappedPresenter {
    pub fn State(&self) -> windows_core::Result<OverlappedPresenterState> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).State)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn Maximize(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Maximize)(windows_core::Interface::as_raw(self))
                .ok()
        }
    }
    pub fn Restore(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Restore)(windows_core::Interface::as_raw(self))
                .ok()
        }
    }
}
#[repr(C)]
pub struct IOverlappedPresenter_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    HasBorder: usize,
    HasTitleBar: usize,
    IsAlwaysOnTop: usize,
    SetIsAlwaysOnTop: usize,
    IsMaximizable: usize,
    SetIsMaximizable: usize,
    IsMinimizable: usize,
    SetIsMinimizable: usize,
    IsModal: usize,
    SetIsModal: usize,
    IsResizable: usize,
    SetIsResizable: usize,
    pub State: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut OverlappedPresenterState,
    ) -> windows_core::HRESULT,
    pub Maximize: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
    Minimize: usize,
    pub Restore: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IOverlappedPresenter3,
    IOverlappedPresenter3_Vtbl,
    0x55d26138_4c38_57e7_a0c1_d467b774db8c
);
impl windows_core::RuntimeType for IOverlappedPresenter3 {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IOverlappedPresenter3 {
    pub fn SetPreferredMinimumHeight(&self, value: Option<i32>) -> windows_core::Result<()> {
        let value__ = value.map(<windows_reference::IReference<i32> as From<_>>::from);
        unsafe {
            (windows_core::Interface::vtable(self).SetPreferredMinimumHeight)(
                windows_core::Interface::as_raw(self),
                windows_core::Param::param(value__.as_ref()).abi(),
            )
            .ok()
        }
    }
    pub fn SetPreferredMinimumWidth(&self, value: Option<i32>) -> windows_core::Result<()> {
        let value__ = value.map(<windows_reference::IReference<i32> as From<_>>::from);
        unsafe {
            (windows_core::Interface::vtable(self).SetPreferredMinimumWidth)(
                windows_core::Interface::as_raw(self),
                windows_core::Param::param(value__.as_ref()).abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IOverlappedPresenter3_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    PreferredMinimumHeight: usize,
    pub SetPreferredMinimumHeight: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    PreferredMinimumWidth: usize,
    pub SetPreferredMinimumWidth: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(IPanel, IPanel_Vtbl, 0x27a1b418_56f3_525e_b883_cefed905eed3);
impl windows_core::RuntimeType for IPanel {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IPanel {
    pub fn Children(&self) -> windows_core::Result<UIElementCollection> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Children)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetBackground<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Brush>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetBackground)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IPanel_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Children: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    Background: usize,
    pub SetBackground: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(IPath, IPath_Vtbl, 0x757d1cd8_0ec0_55c5_b400_66657e493e78);
impl windows_core::RuntimeType for IPath {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IPath {
    pub fn SetData<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Geometry>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetData)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IPath_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Data: usize,
    pub SetData: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IPathFactory,
    IPathFactory_Vtbl,
    0x5e82e4c9_7502_5b1f_b940_c3346a71362a
);
impl windows_core::RuntimeType for IPathFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IPathFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IPickFileResult,
    IPickFileResult_Vtbl,
    0xe6f2e3d6_7bb0_5d81_9e7d_6fd35a1f25ab
);
impl windows_core::RuntimeType for IPickFileResult {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IPickFileResult {
    pub fn Path(&self) -> windows_core::Result<String> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Path)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| {
                let hstring: windows_core::HSTRING = core::mem::transmute(result__);
                hstring.to_string_lossy()
            })
        }
    }
}
#[repr(C)]
pub struct IPickFileResult_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Path: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IPointerRoutedEventArgs,
    IPointerRoutedEventArgs_Vtbl,
    0x66e78a9a_1bec_5f92_b1a1_ea6334ee511c
);
impl windows_core::RuntimeType for IPointerRoutedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IPointerRoutedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IProgressRing,
    IProgressRing_Vtbl,
    0x2670d03f_e28c_5652_bee2_b5212ebdf7ff
);
impl windows_core::RuntimeType for IProgressRing {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IProgressRing {
    pub fn SetIsActive(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsActive)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IProgressRing_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    IsActive: usize,
    pub SetIsActive:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IProgressRingFactory,
    IProgressRingFactory_Vtbl,
    0x092fa98c_62a7_5dbc_9a85_3e556ba81f79
);
impl windows_core::RuntimeType for IProgressRingFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IProgressRingFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IPropertyValue,
    IPropertyValue_Vtbl,
    0x4bd682dd_7554_40e9_9a9b_82654ede7e62
);
impl windows_core::RuntimeType for IPropertyValue {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
windows_core::imp::interface_hierarchy!(
    IPropertyValue,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl IPropertyValue {
    pub fn Type(&self) -> windows_core::Result<PropertyType> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Type)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn IsNumericScalar(&self) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).IsNumericScalar)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetUInt8(&self) -> windows_core::Result<u8> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetUInt8)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetInt16(&self) -> windows_core::Result<i16> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetInt16)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetUInt16(&self) -> windows_core::Result<u16> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetUInt16)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetInt32(&self) -> windows_core::Result<i32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetInt32)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetUInt32(&self) -> windows_core::Result<u32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetUInt32)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetInt64(&self) -> windows_core::Result<i64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetInt64)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetUInt64(&self) -> windows_core::Result<u64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetUInt64)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetSingle(&self) -> windows_core::Result<f32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetSingle)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetDouble(&self) -> windows_core::Result<f64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetDouble)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetChar16(&self) -> windows_core::Result<u16> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetChar16)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetBoolean(&self) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetBoolean)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetString(&self) -> windows_core::Result<String> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetString)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| {
                let hstring: windows_core::HSTRING = core::mem::transmute(result__);
                hstring.to_string_lossy()
            })
        }
    }
    pub fn GetGuid(&self) -> windows_core::Result<windows_core::GUID> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetGuid)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetDateTime(&self) -> windows_core::Result<windows_time::DateTime> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetDateTime)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetTimeSpan(&self) -> windows_core::Result<windows_time::TimeSpan> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetTimeSpan)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetPoint(&self) -> windows_core::Result<Point> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetPoint)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetSize(&self) -> windows_core::Result<Size> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetSize)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetRect(&self) -> windows_core::Result<Rect> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetRect)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn GetUInt8Array(&self, value: &mut windows_core::Array<u8>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetUInt8Array)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetInt16Array(&self, value: &mut windows_core::Array<i16>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetInt16Array)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetUInt16Array(&self, value: &mut windows_core::Array<u16>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetUInt16Array)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetInt32Array(&self, value: &mut windows_core::Array<i32>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetInt32Array)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetUInt32Array(&self, value: &mut windows_core::Array<u32>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetUInt32Array)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetInt64Array(&self, value: &mut windows_core::Array<i64>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetInt64Array)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetUInt64Array(&self, value: &mut windows_core::Array<u64>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetUInt64Array)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetSingleArray(&self, value: &mut windows_core::Array<f32>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetSingleArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetDoubleArray(&self, value: &mut windows_core::Array<f64>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetDoubleArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetChar16Array(&self, value: &mut windows_core::Array<u16>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetChar16Array)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetBooleanArray(
        &self,
        value: &mut windows_core::Array<bool>,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetBooleanArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetStringArray(
        &self,
        value: &mut windows_core::Array<windows_core::HSTRING>,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetStringArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetInspectableArray(
        &self,
        value: &mut windows_core::Array<windows_core::IInspectable>,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetInspectableArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetGuidArray(
        &self,
        value: &mut windows_core::Array<windows_core::GUID>,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetGuidArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetDateTimeArray(
        &self,
        value: &mut windows_core::Array<windows_time::DateTime>,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetDateTimeArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetTimeSpanArray(
        &self,
        value: &mut windows_core::Array<windows_time::TimeSpan>,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetTimeSpanArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetPointArray(
        &self,
        value: &mut windows_core::Array<Point>,
    ) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetPointArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetSizeArray(&self, value: &mut windows_core::Array<Size>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetSizeArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
    pub fn GetRectArray(&self, value: &mut windows_core::Array<Rect>) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).GetRectArray)(
                windows_core::Interface::as_raw(self),
                value.set_abi_len(),
                value as *mut _ as _,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IPropertyValue_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Type: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut PropertyType,
    ) -> windows_core::HRESULT,
    pub IsNumericScalar:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut bool) -> windows_core::HRESULT,
    pub GetUInt8:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut u8) -> windows_core::HRESULT,
    pub GetInt16:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i16) -> windows_core::HRESULT,
    pub GetUInt16:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut u16) -> windows_core::HRESULT,
    pub GetInt32:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> windows_core::HRESULT,
    pub GetUInt32:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut u32) -> windows_core::HRESULT,
    pub GetInt64:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i64) -> windows_core::HRESULT,
    pub GetUInt64:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut u64) -> windows_core::HRESULT,
    pub GetSingle:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut f32) -> windows_core::HRESULT,
    pub GetDouble:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut f64) -> windows_core::HRESULT,
    pub GetChar16:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut u16) -> windows_core::HRESULT,
    pub GetBoolean:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut bool) -> windows_core::HRESULT,
    pub GetString: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub GetGuid: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut windows_core::GUID,
    ) -> windows_core::HRESULT,
    pub GetDateTime: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut windows_time::DateTime,
    ) -> windows_core::HRESULT,
    pub GetTimeSpan: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut windows_time::TimeSpan,
    ) -> windows_core::HRESULT,
    pub GetPoint:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut Point) -> windows_core::HRESULT,
    pub GetSize:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut Size) -> windows_core::HRESULT,
    pub GetRect:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut Rect) -> windows_core::HRESULT,
    pub GetUInt8Array: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut u8,
    ) -> windows_core::HRESULT,
    pub GetInt16Array: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut i16,
    ) -> windows_core::HRESULT,
    pub GetUInt16Array: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut u16,
    ) -> windows_core::HRESULT,
    pub GetInt32Array: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut i32,
    ) -> windows_core::HRESULT,
    pub GetUInt32Array: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut u32,
    ) -> windows_core::HRESULT,
    pub GetInt64Array: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut i64,
    ) -> windows_core::HRESULT,
    pub GetUInt64Array: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut u64,
    ) -> windows_core::HRESULT,
    pub GetSingleArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut f32,
    ) -> windows_core::HRESULT,
    pub GetDoubleArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut f64,
    ) -> windows_core::HRESULT,
    pub GetChar16Array: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut u16,
    ) -> windows_core::HRESULT,
    pub GetBooleanArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut bool,
    ) -> windows_core::HRESULT,
    pub GetStringArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut windows_core::HSTRING,
    ) -> windows_core::HRESULT,
    pub GetInspectableArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut windows_core::IInspectable,
    ) -> windows_core::HRESULT,
    pub GetGuidArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut windows_core::GUID,
    ) -> windows_core::HRESULT,
    pub GetDateTimeArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut windows_time::DateTime,
    ) -> windows_core::HRESULT,
    pub GetTimeSpanArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut windows_time::TimeSpan,
    ) -> windows_core::HRESULT,
    pub GetPointArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut Point,
    ) -> windows_core::HRESULT,
    pub GetSizeArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut Size,
    ) -> windows_core::HRESULT,
    pub GetRectArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut Rect,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IPropertyValueStatics,
    IPropertyValueStatics_Vtbl,
    0x629bdbc8_d932_4ff4_96b9_8d96c5c1e858
);
impl windows_core::RuntimeType for IPropertyValueStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IPropertyValueStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    CreateEmpty: usize,
    CreateUInt8: usize,
    CreateInt16: usize,
    CreateUInt16: usize,
    CreateInt32: usize,
    CreateUInt32: usize,
    CreateInt64: usize,
    CreateUInt64: usize,
    CreateSingle: usize,
    CreateDouble: usize,
    CreateChar16: usize,
    CreateBoolean: usize,
    pub CreateString: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IRadioButton,
    IRadioButton_Vtbl,
    0x38f30cee_e75a_5ba1_ae64_4474a3abeac7
);
impl windows_core::RuntimeType for IRadioButton {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IRadioButton {
    pub fn SetGroupName(&self, value: &str) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetGroupName)(
                windows_core::Interface::as_raw(self),
                core::mem::transmute_copy(&windows_core::HSTRING::from(value)),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IRadioButton_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    GroupName: usize,
    pub SetGroupName: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IRadioButtonFactory,
    IRadioButtonFactory_Vtbl,
    0x5772c79a_b3eb_5719_8005_2a513429495a
);
impl windows_core::RuntimeType for IRadioButtonFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IRadioButtonFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IRandomAccessStream,
    IRandomAccessStream_Vtbl,
    0x905a0fe1_bc53_11df_8c49_001e4fc686da
);
impl windows_core::RuntimeType for IRandomAccessStream {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
windows_core::imp::interface_hierarchy!(
    IRandomAccessStream,
    windows_core::IUnknown,
    windows_core::IInspectable
);
#[repr(C)]
pub struct IRandomAccessStream_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IRectangleGeometry,
    IRectangleGeometry_Vtbl,
    0xb6143890_a5f5_54e0_ab42_d88bab451f04
);
impl windows_core::RuntimeType for IRectangleGeometry {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IRectangleGeometry {
    pub fn SetRect(&self, value: Rect) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetRect)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IRectangleGeometry_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Rect: usize,
    pub SetRect: unsafe extern "system" fn(*mut core::ffi::c_void, Rect) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IRenderTargetBitmap,
    IRenderTargetBitmap_Vtbl,
    0xcf10407d_fa8b_57a3_9574_710529ae0b04
);
impl windows_core::RuntimeType for IRenderTargetBitmap {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IRenderTargetBitmap {
    pub fn PixelWidth(&self) -> windows_core::Result<i32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).PixelWidth)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn PixelHeight(&self) -> windows_core::Result<i32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).PixelHeight)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn RenderAsync<P0>(&self, element: P0) -> windows_core::Result<windows_future::IAsyncAction>
    where
        P0: windows_core::Param<UIElement>,
    {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).RenderAsync)(
                windows_core::Interface::as_raw(self),
                element.param().abi(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn GetPixelsAsync(&self) -> windows_core::Result<windows_future::IAsyncOperation<IBuffer>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetPixelsAsync)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IRenderTargetBitmap_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub PixelWidth:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> windows_core::HRESULT,
    pub PixelHeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> windows_core::HRESULT,
    pub RenderAsync: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    RenderToSizeAsync: usize,
    pub GetPixelsAsync: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IResourceDictionary,
    IResourceDictionary_Vtbl,
    0x1b690975_a710_5783_a6e1_15836f6186c2
);
impl windows_core::RuntimeType for IResourceDictionary {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IResourceDictionary {
    pub fn MergedDictionaries(
        &self,
    ) -> windows_core::Result<windows_collections::IVector<ResourceDictionary>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).MergedDictionaries)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IResourceDictionary_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Source: usize,
    SetSource: usize,
    pub MergedDictionaries: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IRoutedEventArgs,
    IRoutedEventArgs_Vtbl,
    0x0908c407_1c7d_5de3_9c50_d971c62ec8ec
);
impl windows_core::RuntimeType for IRoutedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IRoutedEventArgs {
    pub fn OriginalSource(&self) -> windows_core::Result<windows_core::IInspectable> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).OriginalSource)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IRoutedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub OriginalSource: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IRowDefinition,
    IRowDefinition_Vtbl,
    0xfe870f2f_89ef_5dac_9f33_968d0dc577c3
);
impl windows_core::RuntimeType for IRowDefinition {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IRowDefinition {
    pub fn SetHeight(&self, value: GridLength) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetHeight)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetMinHeight(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetMinHeight)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IRowDefinition_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Height: usize,
    pub SetHeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, GridLength) -> windows_core::HRESULT,
    MaxHeight: usize,
    SetMaxHeight: usize,
    MinHeight: usize,
    pub SetMinHeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IScrollViewer,
    IScrollViewer_Vtbl,
    0x1dc28c2e_996c_5394_89c3_4dc656b4ad46
);
impl windows_core::RuntimeType for IScrollViewer {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IScrollViewer {
    pub fn VerticalOffset(&self) -> windows_core::Result<f64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).VerticalOffset)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn ScrollableHeight(&self) -> windows_core::Result<f64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ScrollableHeight)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn ChangeViewWithOptionalAnimation(
        &self,
        horizontaloffset: Option<f64>,
        verticaloffset: Option<f64>,
        zoomfactor: Option<f32>,
        disableanimation: bool,
    ) -> windows_core::Result<bool> {
        let horizontaloffset__ =
            horizontaloffset.map(<windows_reference::IReference<f64> as From<_>>::from);
        let verticaloffset__ =
            verticaloffset.map(<windows_reference::IReference<f64> as From<_>>::from);
        let zoomfactor__ = zoomfactor.map(<windows_reference::IReference<f32> as From<_>>::from);
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).ChangeViewWithOptionalAnimation)(
                windows_core::Interface::as_raw(self),
                windows_core::Param::param(horizontaloffset__.as_ref()).abi(),
                windows_core::Param::param(verticaloffset__.as_ref()).abi(),
                windows_core::Param::param(zoomfactor__.as_ref()).abi(),
                disableanimation,
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IScrollViewer_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    HorizontalScrollBarVisibility: usize,
    SetHorizontalScrollBarVisibility: usize,
    VerticalScrollBarVisibility: usize,
    SetVerticalScrollBarVisibility: usize,
    IsHorizontalRailEnabled: usize,
    SetIsHorizontalRailEnabled: usize,
    IsVerticalRailEnabled: usize,
    SetIsVerticalRailEnabled: usize,
    IsHorizontalScrollChainingEnabled: usize,
    SetIsHorizontalScrollChainingEnabled: usize,
    IsVerticalScrollChainingEnabled: usize,
    SetIsVerticalScrollChainingEnabled: usize,
    IsZoomChainingEnabled: usize,
    SetIsZoomChainingEnabled: usize,
    IsScrollInertiaEnabled: usize,
    SetIsScrollInertiaEnabled: usize,
    IsZoomInertiaEnabled: usize,
    SetIsZoomInertiaEnabled: usize,
    HorizontalScrollMode: usize,
    SetHorizontalScrollMode: usize,
    VerticalScrollMode: usize,
    SetVerticalScrollMode: usize,
    ZoomMode: usize,
    SetZoomMode: usize,
    HorizontalSnapPointsAlignment: usize,
    SetHorizontalSnapPointsAlignment: usize,
    VerticalSnapPointsAlignment: usize,
    SetVerticalSnapPointsAlignment: usize,
    HorizontalSnapPointsType: usize,
    SetHorizontalSnapPointsType: usize,
    VerticalSnapPointsType: usize,
    SetVerticalSnapPointsType: usize,
    ZoomSnapPointsType: usize,
    SetZoomSnapPointsType: usize,
    HorizontalOffset: usize,
    ViewportWidth: usize,
    ScrollableWidth: usize,
    ComputedHorizontalScrollBarVisibility: usize,
    ExtentWidth: usize,
    pub VerticalOffset:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut f64) -> windows_core::HRESULT,
    ViewportHeight: usize,
    pub ScrollableHeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut f64) -> windows_core::HRESULT,
    ComputedVerticalScrollBarVisibility: usize,
    ExtentHeight: usize,
    MinZoomFactor: usize,
    SetMinZoomFactor: usize,
    MaxZoomFactor: usize,
    SetMaxZoomFactor: usize,
    ZoomFactor: usize,
    ZoomSnapPoints: usize,
    TopLeftHeader: usize,
    SetTopLeftHeader: usize,
    LeftHeader: usize,
    SetLeftHeader: usize,
    TopHeader: usize,
    SetTopHeader: usize,
    ReduceViewportForCoreInputViewOcclusions: usize,
    SetReduceViewportForCoreInputViewOcclusions: usize,
    HorizontalAnchorRatio: usize,
    SetHorizontalAnchorRatio: usize,
    VerticalAnchorRatio: usize,
    SetVerticalAnchorRatio: usize,
    CanContentRenderOutsideBounds: usize,
    SetCanContentRenderOutsideBounds: usize,
    AnchorRequested: usize,
    RemoveAnchorRequested: usize,
    ViewChanging: usize,
    RemoveViewChanging: usize,
    ViewChanged: usize,
    RemoveViewChanged: usize,
    DirectManipulationStarted: usize,
    RemoveDirectManipulationStarted: usize,
    DirectManipulationCompleted: usize,
    RemoveDirectManipulationCompleted: usize,
    ScrollToHorizontalOffset: usize,
    ScrollToVerticalOffset: usize,
    ZoomToFactor: usize,
    ChangeView: usize,
    pub ChangeViewWithOptionalAnimation: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        bool,
        *mut bool,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IScrollViewerStatics,
    IScrollViewerStatics_Vtbl,
    0xd971fd86_0a96_50c4_a6e1_9975faa2a142
);
impl windows_core::RuntimeType for IScrollViewerStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IScrollViewerStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    HorizontalSnapPointsAlignmentProperty: usize,
    VerticalSnapPointsAlignmentProperty: usize,
    HorizontalSnapPointsTypeProperty: usize,
    VerticalSnapPointsTypeProperty: usize,
    ZoomSnapPointsTypeProperty: usize,
    HorizontalOffsetProperty: usize,
    ViewportWidthProperty: usize,
    ScrollableWidthProperty: usize,
    ComputedHorizontalScrollBarVisibilityProperty: usize,
    ExtentWidthProperty: usize,
    VerticalOffsetProperty: usize,
    ViewportHeightProperty: usize,
    ScrollableHeightProperty: usize,
    ComputedVerticalScrollBarVisibilityProperty: usize,
    ExtentHeightProperty: usize,
    MinZoomFactorProperty: usize,
    MaxZoomFactorProperty: usize,
    ZoomFactorProperty: usize,
    ZoomSnapPointsProperty: usize,
    TopLeftHeaderProperty: usize,
    LeftHeaderProperty: usize,
    TopHeaderProperty: usize,
    ReduceViewportForCoreInputViewOcclusionsProperty: usize,
    HorizontalAnchorRatioProperty: usize,
    VerticalAnchorRatioProperty: usize,
    HorizontalScrollBarVisibilityProperty: usize,
    GetHorizontalScrollBarVisibility: usize,
    pub SetHorizontalScrollBarVisibility: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        ScrollBarVisibility,
    ) -> windows_core::HRESULT,
    VerticalScrollBarVisibilityProperty: usize,
    GetVerticalScrollBarVisibility: usize,
    pub SetVerticalScrollBarVisibility: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        ScrollBarVisibility,
    ) -> windows_core::HRESULT,
    IsHorizontalRailEnabledProperty: usize,
    GetIsHorizontalRailEnabled: usize,
    SetIsHorizontalRailEnabled: usize,
    IsVerticalRailEnabledProperty: usize,
    GetIsVerticalRailEnabled: usize,
    SetIsVerticalRailEnabled: usize,
    IsHorizontalScrollChainingEnabledProperty: usize,
    GetIsHorizontalScrollChainingEnabled: usize,
    SetIsHorizontalScrollChainingEnabled: usize,
    IsVerticalScrollChainingEnabledProperty: usize,
    GetIsVerticalScrollChainingEnabled: usize,
    SetIsVerticalScrollChainingEnabled: usize,
    IsZoomChainingEnabledProperty: usize,
    GetIsZoomChainingEnabled: usize,
    SetIsZoomChainingEnabled: usize,
    IsScrollInertiaEnabledProperty: usize,
    GetIsScrollInertiaEnabled: usize,
    SetIsScrollInertiaEnabled: usize,
    IsZoomInertiaEnabledProperty: usize,
    GetIsZoomInertiaEnabled: usize,
    SetIsZoomInertiaEnabled: usize,
    HorizontalScrollModeProperty: usize,
    GetHorizontalScrollMode: usize,
    pub SetHorizontalScrollMode: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        ScrollMode,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISelectionChangedEventArgs,
    ISelectionChangedEventArgs_Vtbl,
    0xb6c18076_4b76_5416_ad29_e2dc20c46246
);
impl windows_core::RuntimeType for ISelectionChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ISelectionChangedEventArgs {
    pub fn AddedItems(
        &self,
    ) -> windows_core::Result<windows_collections::IVector<windows_core::IInspectable>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).AddedItems)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn RemovedItems(
        &self,
    ) -> windows_core::Result<windows_collections::IVector<windows_core::IInspectable>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).RemovedItems)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct ISelectionChangedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub AddedItems: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub RemovedItems: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISelector,
    ISelector_Vtbl,
    0x8f7e2159_e61d_576f_8476_f83fde3d689e
);
impl windows_core::RuntimeType for ISelector {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ISelector {
    pub fn SelectedIndex(&self) -> windows_core::Result<i32> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).SelectedIndex)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn SetSelectedIndex(&self, value: i32) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetSelectedIndex)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SelectionChanged<F>(
        &self,
        handler: F,
    ) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<SelectionChangedEventArgs>,
            ) + 'static,
    {
        let handler: SelectionChangedEventHandler = {
            let com = windows_core::imp::DelegateBox::<SelectionChangedEventHandler, F>::new(
                &SelectionChangedEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).SelectionChanged)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveSelectionChanged,
            ))
        }
    }
}
#[repr(C)]
pub struct ISelector_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub SelectedIndex:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> windows_core::HRESULT,
    pub SetSelectedIndex:
        unsafe extern "system" fn(*mut core::ffi::c_void, i32) -> windows_core::HRESULT,
    SelectedItem: usize,
    SetSelectedItem: usize,
    SelectedValue: usize,
    SetSelectedValue: usize,
    SelectedValuePath: usize,
    SetSelectedValuePath: usize,
    IsSynchronizedWithCurrentItem: usize,
    SetIsSynchronizedWithCurrentItem: usize,
    pub SelectionChanged: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveSelectionChanged:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISelectorBar,
    ISelectorBar_Vtbl,
    0x7f4ad191_55ea_508e_bf47_7047d8677370
);
impl windows_core::RuntimeType for ISelectorBar {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ISelectorBar {
    pub fn Items(&self) -> windows_core::Result<windows_collections::IVector<SelectorBarItem>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Items)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SelectedItem(&self) -> windows_core::Result<SelectorBarItem> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).SelectedItem)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetSelectedItem<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<SelectorBarItem>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetSelectedItem)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SelectionChanged<F>(
        &self,
        handler: F,
    ) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<SelectorBar>,
                windows_core::Ref<SelectorBarSelectionChangedEventArgs>,
            ) + 'static,
    {
        let handler: TypedEventHandler<SelectorBar, SelectorBarSelectionChangedEventArgs> = {
            let com = windows_core::imp::DelegateBox::< TypedEventHandler < SelectorBar , SelectorBarSelectionChangedEventArgs > , F >::new (& TypedEventHandlerBox::< SelectorBar , SelectorBarSelectionChangedEventArgs , F >::VTABLE , handler) ;
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).SelectionChanged)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveSelectionChanged,
            ))
        }
    }
}
#[repr(C)]
pub struct ISelectorBar_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Items: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SelectedItem: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetSelectedItem: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SelectionChanged: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveSelectionChanged:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISelectorBarFactory,
    ISelectorBarFactory_Vtbl,
    0x71243dc7_b46c_5a04_9894_e420e462703f
);
impl windows_core::RuntimeType for ISelectorBarFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ISelectorBarFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISelectorBarItem,
    ISelectorBarItem_Vtbl,
    0x3cdba1f9_a13a_56a2_b9a9_f954998d3658
);
impl windows_core::RuntimeType for ISelectorBarItem {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ISelectorBarItem {
    pub fn SetText(&self, value: &str) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetText)(
                windows_core::Interface::as_raw(self),
                core::mem::transmute_copy(&windows_core::HSTRING::from(value)),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct ISelectorBarItem_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Text: usize,
    pub SetText: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISelectorBarItemFactory,
    ISelectorBarItemFactory_Vtbl,
    0xe46b62ea_e60d_5989_bea7_5470da326816
);
impl windows_core::RuntimeType for ISelectorBarItemFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ISelectorBarItemFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISelectorBarSelectionChangedEventArgs,
    ISelectorBarSelectionChangedEventArgs_Vtbl,
    0x73b3f6c5_5050_5c5a_899c_4e6e0474cb63
);
impl windows_core::RuntimeType for ISelectorBarSelectionChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ISelectorBarSelectionChangedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    ISelectorItem,
    ISelectorItem_Vtbl,
    0x5772c4de_60ea_5492_8c5e_b3323d5a3ca6
);
impl windows_core::RuntimeType for ISelectorItem {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ISelectorItem {
    pub fn IsSelected(&self) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).IsSelected)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct ISelectorItem_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub IsSelected:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISequentialStream,
    ISequentialStream_Vtbl,
    0x0c733a30_2a1c_11ce_ade5_00aa0044773d
);
windows_core::imp::interface_hierarchy!(ISequentialStream, windows_core::IUnknown);
#[repr(C)]
pub struct ISequentialStream_Vtbl {
    pub base__: windows_core::IUnknown_Vtbl,
    Read: usize,
    Write: usize,
}
windows_core::imp::define_interface!(
    IShadow,
    IShadow_Vtbl,
    0xcc12fd6a_50aa_5eb3_9a0e_b938b454c439
);
impl windows_core::RuntimeType for IShadow {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IShadow_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(IShape, IShape_Vtbl, 0x9941aad3_6af2_5ba2_9085_8506d5f2485e);
impl windows_core::RuntimeType for IShape {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IShape {
    pub fn SetFill<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Brush>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetFill)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetStroke<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<Brush>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetStroke)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetStrokeThickness(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetStrokeThickness)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetStrokeStartLineCap(&self, value: PenLineCap) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetStrokeStartLineCap)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetStrokeEndLineCap(&self, value: PenLineCap) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetStrokeEndLineCap)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetStrokeLineJoin(&self, value: PenLineJoin) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetStrokeLineJoin)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetStrokeDashArray<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<DoubleCollection>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetStrokeDashArray)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IShape_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Fill: usize,
    pub SetFill: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    Stroke: usize,
    pub SetStroke: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    StrokeMiterLimit: usize,
    SetStrokeMiterLimit: usize,
    StrokeThickness: usize,
    pub SetStrokeThickness:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    StrokeStartLineCap: usize,
    pub SetStrokeStartLineCap:
        unsafe extern "system" fn(*mut core::ffi::c_void, PenLineCap) -> windows_core::HRESULT,
    StrokeEndLineCap: usize,
    pub SetStrokeEndLineCap:
        unsafe extern "system" fn(*mut core::ffi::c_void, PenLineCap) -> windows_core::HRESULT,
    StrokeLineJoin: usize,
    pub SetStrokeLineJoin:
        unsafe extern "system" fn(*mut core::ffi::c_void, PenLineJoin) -> windows_core::HRESULT,
    StrokeDashOffset: usize,
    SetStrokeDashOffset: usize,
    StrokeDashCap: usize,
    SetStrokeDashCap: usize,
    StrokeDashArray: usize,
    pub SetStrokeDashArray: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISizeChangedEventArgs,
    ISizeChangedEventArgs_Vtbl,
    0xfe76324e_6dfb_58b1_9dcd_886ca8f9a2ea
);
impl windows_core::RuntimeType for ISizeChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ISizeChangedEventArgs {
    pub fn NewSize(&self) -> windows_core::Result<Size> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).NewSize)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct ISizeChangedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    PreviousSize: usize,
    pub NewSize:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut Size) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ISolidColorBrush,
    ISolidColorBrush_Vtbl,
    0xb3865c31_37c8_55c1_8a72_d41c67642e2a
);
impl windows_core::RuntimeType for ISolidColorBrush {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ISolidColorBrush {
    pub fn SetColor(&self, value: Color) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetColor)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct ISolidColorBrush_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Color: usize,
    pub SetColor: unsafe extern "system" fn(*mut core::ffi::c_void, Color) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IStackPanel,
    IStackPanel_Vtbl,
    0x493ab00b_3a6a_5e4a_9452_407cd5197406
);
impl windows_core::RuntimeType for IStackPanel {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IStackPanel {
    pub fn SetOrientation(&self, value: Orientation) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetOrientation)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetSpacing(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetSpacing)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IStackPanel_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    AreScrollSnapPointsRegular: usize,
    SetAreScrollSnapPointsRegular: usize,
    Orientation: usize,
    pub SetOrientation:
        unsafe extern "system" fn(*mut core::ffi::c_void, Orientation) -> windows_core::HRESULT,
    BackgroundSizing: usize,
    SetBackgroundSizing: usize,
    BorderBrush: usize,
    SetBorderBrush: usize,
    BorderThickness: usize,
    SetBorderThickness: usize,
    CornerRadius: usize,
    SetCornerRadius: usize,
    Padding: usize,
    SetPadding: usize,
    Spacing: usize,
    pub SetSpacing: unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IStackPanelFactory,
    IStackPanelFactory_Vtbl,
    0x64c1d388_47a2_5a74_a75b_559d151ee5ac
);
impl windows_core::RuntimeType for IStackPanelFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IStackPanelFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IStream,
    IStream_Vtbl,
    0x0000000c_0000_0000_c000_000000000046
);
impl core::ops::Deref for IStream {
    type Target = ISequentialStream;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
windows_core::imp::interface_hierarchy!(IStream, windows_core::IUnknown, ISequentialStream);
#[repr(C)]
pub struct IStream_Vtbl {
    pub base__: ISequentialStream_Vtbl,
    Seek: usize,
    SetSize: usize,
    CopyTo: usize,
    Commit: usize,
    Revert: usize,
    LockRegion: usize,
    UnlockRegion: usize,
    Stat: usize,
    Clone: usize,
}
windows_core::imp::define_interface!(IStyle, IStyle_Vtbl, 0x65e1d164_572f_5b0e_a80f_9c02441fac49);
impl windows_core::RuntimeType for IStyle {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IStyle_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    ISystemBackdrop,
    ISystemBackdrop_Vtbl,
    0x5aeed5c4_37ac_5852_b73f_1b76ebc3205f
);
impl windows_core::RuntimeType for ISystemBackdrop {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ISystemBackdrop_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    ITextBlock,
    ITextBlock_Vtbl,
    0x1ac8d84f_392c_5c7e_83f5_a53e3bf0abb0
);
impl windows_core::RuntimeType for ITextBlock {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ITextBlock {
    pub fn SetFontSize(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetFontSize)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetFontFamily<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<FontFamily>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetFontFamily)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetFontWeight(&self, value: FontWeight) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetFontWeight)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetTextWrapping(&self, value: TextWrapping) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetTextWrapping)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetTextTrimming(&self, value: TextTrimming) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetTextTrimming)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetTextAlignment(&self, value: TextAlignment) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetTextAlignment)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn Text(&self) -> windows_core::Result<String> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Text)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| {
                let hstring: windows_core::HSTRING = core::mem::transmute(result__);
                hstring.to_string_lossy()
            })
        }
    }
    pub fn SetText(&self, value: &str) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetText)(
                windows_core::Interface::as_raw(self),
                core::mem::transmute_copy(&windows_core::HSTRING::from(value)),
            )
            .ok()
        }
    }
    pub fn SetIsTextSelectionEnabled(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsTextSelectionEnabled)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetMaxLines(&self, value: i32) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetMaxLines)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn IsTextTrimmed(&self) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).IsTextTrimmed)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn IsTextTrimmedChanged<F>(
        &self,
        handler: F,
    ) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<TextBlock>, windows_core::Ref<IsTextTrimmedChangedEventArgs>)
            + 'static,
    {
        let handler: TypedEventHandler<TextBlock, IsTextTrimmedChangedEventArgs> = {
            let com = windows_core::imp::DelegateBox::<
                TypedEventHandler<TextBlock, IsTextTrimmedChangedEventArgs>,
                F,
            >::new(
                &TypedEventHandlerBox::<TextBlock, IsTextTrimmedChangedEventArgs, F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).IsTextTrimmedChanged)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveIsTextTrimmedChanged,
            ))
        }
    }
}
#[repr(C)]
pub struct ITextBlock_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    FontSize: usize,
    pub SetFontSize:
        unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    FontFamily: usize,
    pub SetFontFamily: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    FontWeight: usize,
    pub SetFontWeight:
        unsafe extern "system" fn(*mut core::ffi::c_void, FontWeight) -> windows_core::HRESULT,
    FontStyle: usize,
    SetFontStyle: usize,
    FontStretch: usize,
    SetFontStretch: usize,
    CharacterSpacing: usize,
    SetCharacterSpacing: usize,
    Foreground: usize,
    SetForeground: usize,
    TextWrapping: usize,
    pub SetTextWrapping:
        unsafe extern "system" fn(*mut core::ffi::c_void, TextWrapping) -> windows_core::HRESULT,
    TextTrimming: usize,
    pub SetTextTrimming:
        unsafe extern "system" fn(*mut core::ffi::c_void, TextTrimming) -> windows_core::HRESULT,
    TextAlignment: usize,
    pub SetTextAlignment:
        unsafe extern "system" fn(*mut core::ffi::c_void, TextAlignment) -> windows_core::HRESULT,
    pub Text: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetText: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    Inlines: usize,
    Padding: usize,
    SetPadding: usize,
    LineHeight: usize,
    SetLineHeight: usize,
    LineStackingStrategy: usize,
    SetLineStackingStrategy: usize,
    IsTextSelectionEnabled: usize,
    pub SetIsTextSelectionEnabled:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    SelectedText: usize,
    ContentStart: usize,
    ContentEnd: usize,
    SelectionStart: usize,
    SelectionEnd: usize,
    BaselineOffset: usize,
    SelectionHighlightColor: usize,
    SetSelectionHighlightColor: usize,
    MaxLines: usize,
    pub SetMaxLines:
        unsafe extern "system" fn(*mut core::ffi::c_void, i32) -> windows_core::HRESULT,
    TextLineBounds: usize,
    SetTextLineBounds: usize,
    OpticalMarginAlignment: usize,
    SetOpticalMarginAlignment: usize,
    IsColorFontEnabled: usize,
    SetIsColorFontEnabled: usize,
    TextReadingOrder: usize,
    SetTextReadingOrder: usize,
    IsTextScaleFactorEnabled: usize,
    SetIsTextScaleFactorEnabled: usize,
    TextDecorations: usize,
    SetTextDecorations: usize,
    pub IsTextTrimmed:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut bool) -> windows_core::HRESULT,
    HorizontalTextAlignment: usize,
    SetHorizontalTextAlignment: usize,
    TextHighlighters: usize,
    SelectionFlyout: usize,
    SetSelectionFlyout: usize,
    SelectionChanged: usize,
    RemoveSelectionChanged: usize,
    ContextMenuOpening: usize,
    RemoveContextMenuOpening: usize,
    pub IsTextTrimmedChanged: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveIsTextTrimmedChanged:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ITextBox,
    ITextBox_Vtbl,
    0x873af7c2_ab89_5d76_8dbe_3d6325669df5
);
impl windows_core::RuntimeType for ITextBox {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl ITextBox {
    pub fn Text(&self) -> windows_core::Result<String> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Text)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| {
                let hstring: windows_core::HSTRING = core::mem::transmute(result__);
                hstring.to_string_lossy()
            })
        }
    }
    pub fn SetText(&self, value: &str) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetText)(
                windows_core::Interface::as_raw(self),
                core::mem::transmute_copy(&windows_core::HSTRING::from(value)),
            )
            .ok()
        }
    }
    pub fn SetIsReadOnly(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsReadOnly)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetAcceptsReturn(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetAcceptsReturn)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetTextWrapping(&self, value: TextWrapping) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetTextWrapping)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetIsSpellCheckEnabled(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsSpellCheckEnabled)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetPlaceholderText(&self, value: &str) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetPlaceholderText)(
                windows_core::Interface::as_raw(self),
                core::mem::transmute_copy(&windows_core::HSTRING::from(value)),
            )
            .ok()
        }
    }
    pub fn TextChanged<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<TextChangedEventArgs>,
            ) + 'static,
    {
        let handler: TextChangedEventHandler = {
            let com = windows_core::imp::DelegateBox::<TextChangedEventHandler, F>::new(
                &TextChangedEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).TextChanged)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveTextChanged,
            ))
        }
    }
    pub fn Select(&self, start: i32, length: i32) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Select)(
                windows_core::Interface::as_raw(self),
                start,
                length,
            )
            .ok()
        }
    }
    pub fn ClearUndoRedoHistory(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).ClearUndoRedoHistory)(
                windows_core::Interface::as_raw(self),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct ITextBox_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Text: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetText: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    SelectedText: usize,
    SetSelectedText: usize,
    SelectionLength: usize,
    SetSelectionLength: usize,
    SelectionStart: usize,
    SetSelectionStart: usize,
    MaxLength: usize,
    SetMaxLength: usize,
    IsReadOnly: usize,
    pub SetIsReadOnly:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    AcceptsReturn: usize,
    pub SetAcceptsReturn:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    TextAlignment: usize,
    SetTextAlignment: usize,
    TextWrapping: usize,
    pub SetTextWrapping:
        unsafe extern "system" fn(*mut core::ffi::c_void, TextWrapping) -> windows_core::HRESULT,
    IsSpellCheckEnabled: usize,
    pub SetIsSpellCheckEnabled:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    IsTextPredictionEnabled: usize,
    SetIsTextPredictionEnabled: usize,
    InputScope: usize,
    SetInputScope: usize,
    Header: usize,
    SetHeader: usize,
    HeaderTemplate: usize,
    SetHeaderTemplate: usize,
    PlaceholderText: usize,
    pub SetPlaceholderText: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    SelectionHighlightColor: usize,
    SetSelectionHighlightColor: usize,
    PreventKeyboardDisplayOnProgrammaticFocus: usize,
    SetPreventKeyboardDisplayOnProgrammaticFocus: usize,
    IsColorFontEnabled: usize,
    SetIsColorFontEnabled: usize,
    SelectionHighlightColorWhenNotFocused: usize,
    SetSelectionHighlightColorWhenNotFocused: usize,
    HorizontalTextAlignment: usize,
    SetHorizontalTextAlignment: usize,
    CharacterCasing: usize,
    SetCharacterCasing: usize,
    PlaceholderForeground: usize,
    SetPlaceholderForeground: usize,
    CanPasteClipboardContent: usize,
    CanUndo: usize,
    CanRedo: usize,
    SelectionFlyout: usize,
    SetSelectionFlyout: usize,
    ProofingMenuFlyout: usize,
    Description: usize,
    SetDescription: usize,
    pub TextChanged: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveTextChanged:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    SelectionChanged: usize,
    RemoveSelectionChanged: usize,
    ContextMenuOpening: usize,
    RemoveContextMenuOpening: usize,
    Paste: usize,
    RemovePaste: usize,
    TextCompositionStarted: usize,
    RemoveTextCompositionStarted: usize,
    TextCompositionChanged: usize,
    RemoveTextCompositionChanged: usize,
    TextCompositionEnded: usize,
    RemoveTextCompositionEnded: usize,
    CopyingToClipboard: usize,
    RemoveCopyingToClipboard: usize,
    CuttingToClipboard: usize,
    RemoveCuttingToClipboard: usize,
    BeforeTextChanging: usize,
    RemoveBeforeTextChanging: usize,
    SelectionChanging: usize,
    RemoveSelectionChanging: usize,
    pub Select:
        unsafe extern "system" fn(*mut core::ffi::c_void, i32, i32) -> windows_core::HRESULT,
    SelectAll: usize,
    GetRectFromCharacterIndex: usize,
    GetLinguisticAlternativesAsync: usize,
    Undo: usize,
    Redo: usize,
    PasteFromClipboard: usize,
    CopySelectionToClipboard: usize,
    CutSelectionToClipboard: usize,
    pub ClearUndoRedoHistory:
        unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ITextBoxFactory,
    ITextBoxFactory_Vtbl,
    0xe1d8b82e_bc60_5d27_b646_5ca4c4a69432
);
impl windows_core::RuntimeType for ITextBoxFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ITextBoxFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ITextChangedEventArgs,
    ITextChangedEventArgs_Vtbl,
    0x71c37e43_7be7_52fc_bf8c_9867f44be5f4
);
impl windows_core::RuntimeType for ITextChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ITextChangedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IThemeShadow,
    IThemeShadow_Vtbl,
    0xc264208a_d1f4_58ae_8a88_fc59148bee69
);
impl windows_core::RuntimeType for IThemeShadow {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IThemeShadow {
    pub fn Receivers(&self) -> windows_core::Result<UIElementWeakCollection> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Receivers)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IThemeShadow_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Receivers: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IToggleButton,
    IToggleButton_Vtbl,
    0x686fbaa4_c866_568b_8f75_481d8d545291
);
impl windows_core::RuntimeType for IToggleButton {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IToggleButton {
    pub fn IsChecked(&self) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).IsChecked)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
            .and_then(|r__: windows_reference::IReference<bool>| r__.Value())
        }
    }
    pub fn SetIsChecked(&self, value: Option<bool>) -> windows_core::Result<()> {
        let value__ = value.map(<windows_reference::IReference<bool> as From<_>>::from);
        unsafe {
            (windows_core::Interface::vtable(self).SetIsChecked)(
                windows_core::Interface::as_raw(self),
                windows_core::Param::param(value__.as_ref()).abi(),
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IToggleButton_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub IsChecked: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetIsChecked: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IToggleButtonFactory,
    IToggleButtonFactory_Vtbl,
    0x519511bb_d35b_5e2d_966c_8369405a4408
);
impl windows_core::RuntimeType for IToggleButtonFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IToggleButtonFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IToggleSwitch,
    IToggleSwitch_Vtbl,
    0x1b17eeb1_74bf_5a83_8161_a86f0fdcdf24
);
impl windows_core::RuntimeType for IToggleSwitch {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IToggleSwitch {
    pub fn IsOn(&self) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).IsOn)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn SetIsOn(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsOn)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetOnContent<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<windows_core::IInspectable>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetOnContent)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetOffContent<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<windows_core::IInspectable>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetOffContent)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn Toggled<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<RoutedEventArgs>)
            + 'static,
    {
        let handler: RoutedEventHandler = {
            let com = windows_core::imp::DelegateBox::<RoutedEventHandler, F>::new(
                &RoutedEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Toggled)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveToggled,
            ))
        }
    }
}
#[repr(C)]
pub struct IToggleSwitch_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub IsOn: unsafe extern "system" fn(*mut core::ffi::c_void, *mut bool) -> windows_core::HRESULT,
    pub SetIsOn: unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    Header: usize,
    SetHeader: usize,
    HeaderTemplate: usize,
    SetHeaderTemplate: usize,
    OnContent: usize,
    pub SetOnContent: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    OnContentTemplate: usize,
    SetOnContentTemplate: usize,
    OffContent: usize,
    pub SetOffContent: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    OffContentTemplate: usize,
    SetOffContentTemplate: usize,
    TemplateSettings: usize,
    pub Toggled: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveToggled:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IToolTipService,
    IToolTipService_Vtbl,
    0x01140768_2727_5f89_80e0_5210326a3431
);
impl windows_core::RuntimeType for IToolTipService {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IToolTipService_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IToolTipServiceStatics,
    IToolTipServiceStatics_Vtbl,
    0x5aa38adc_9874_5e0a_8d8e_1574efc0b88f
);
impl windows_core::RuntimeType for IToolTipServiceStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IToolTipServiceStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    PlacementProperty: usize,
    GetPlacement: usize,
    SetPlacement: usize,
    PlacementTargetProperty: usize,
    GetPlacementTarget: usize,
    SetPlacementTarget: usize,
    ToolTipProperty: usize,
    pub GetToolTip: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetToolTip: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    ITypography,
    ITypography_Vtbl,
    0xfa27e2e3_be5e_5d21_9a5e_90cf102af828
);
impl windows_core::RuntimeType for ITypography {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ITypography_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    ITypographyStatics,
    ITypographyStatics_Vtbl,
    0x55fe4535_2125_533a_ada8_27be2b9e1193
);
impl windows_core::RuntimeType for ITypographyStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ITypographyStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    AnnotationAlternatesProperty: usize,
    GetAnnotationAlternates: usize,
    SetAnnotationAlternates: usize,
    EastAsianExpertFormsProperty: usize,
    GetEastAsianExpertForms: usize,
    SetEastAsianExpertForms: usize,
    EastAsianLanguageProperty: usize,
    GetEastAsianLanguage: usize,
    SetEastAsianLanguage: usize,
    EastAsianWidthsProperty: usize,
    GetEastAsianWidths: usize,
    SetEastAsianWidths: usize,
    StandardLigaturesProperty: usize,
    GetStandardLigatures: usize,
    SetStandardLigatures: usize,
    ContextualLigaturesProperty: usize,
    GetContextualLigatures: usize,
    SetContextualLigatures: usize,
    DiscretionaryLigaturesProperty: usize,
    GetDiscretionaryLigatures: usize,
    SetDiscretionaryLigatures: usize,
    HistoricalLigaturesProperty: usize,
    GetHistoricalLigatures: usize,
    SetHistoricalLigatures: usize,
    StandardSwashesProperty: usize,
    GetStandardSwashes: usize,
    SetStandardSwashes: usize,
    ContextualSwashesProperty: usize,
    GetContextualSwashes: usize,
    SetContextualSwashes: usize,
    ContextualAlternatesProperty: usize,
    GetContextualAlternates: usize,
    SetContextualAlternates: usize,
    StylisticAlternatesProperty: usize,
    GetStylisticAlternates: usize,
    SetStylisticAlternates: usize,
    StylisticSet1Property: usize,
    GetStylisticSet1: usize,
    SetStylisticSet1: usize,
    StylisticSet2Property: usize,
    GetStylisticSet2: usize,
    SetStylisticSet2: usize,
    StylisticSet3Property: usize,
    GetStylisticSet3: usize,
    SetStylisticSet3: usize,
    StylisticSet4Property: usize,
    GetStylisticSet4: usize,
    SetStylisticSet4: usize,
    StylisticSet5Property: usize,
    GetStylisticSet5: usize,
    SetStylisticSet5: usize,
    StylisticSet6Property: usize,
    GetStylisticSet6: usize,
    SetStylisticSet6: usize,
    StylisticSet7Property: usize,
    GetStylisticSet7: usize,
    SetStylisticSet7: usize,
    StylisticSet8Property: usize,
    GetStylisticSet8: usize,
    SetStylisticSet8: usize,
    StylisticSet9Property: usize,
    GetStylisticSet9: usize,
    SetStylisticSet9: usize,
    StylisticSet10Property: usize,
    GetStylisticSet10: usize,
    SetStylisticSet10: usize,
    StylisticSet11Property: usize,
    GetStylisticSet11: usize,
    SetStylisticSet11: usize,
    StylisticSet12Property: usize,
    GetStylisticSet12: usize,
    SetStylisticSet12: usize,
    StylisticSet13Property: usize,
    GetStylisticSet13: usize,
    SetStylisticSet13: usize,
    StylisticSet14Property: usize,
    GetStylisticSet14: usize,
    SetStylisticSet14: usize,
    StylisticSet15Property: usize,
    GetStylisticSet15: usize,
    SetStylisticSet15: usize,
    StylisticSet16Property: usize,
    GetStylisticSet16: usize,
    SetStylisticSet16: usize,
    StylisticSet17Property: usize,
    GetStylisticSet17: usize,
    SetStylisticSet17: usize,
    StylisticSet18Property: usize,
    GetStylisticSet18: usize,
    SetStylisticSet18: usize,
    StylisticSet19Property: usize,
    GetStylisticSet19: usize,
    SetStylisticSet19: usize,
    StylisticSet20Property: usize,
    GetStylisticSet20: usize,
    SetStylisticSet20: usize,
    CapitalsProperty: usize,
    GetCapitals: usize,
    SetCapitals: usize,
    CapitalSpacingProperty: usize,
    GetCapitalSpacing: usize,
    SetCapitalSpacing: usize,
    KerningProperty: usize,
    GetKerning: usize,
    SetKerning: usize,
    CaseSensitiveFormsProperty: usize,
    GetCaseSensitiveForms: usize,
    SetCaseSensitiveForms: usize,
    HistoricalFormsProperty: usize,
    GetHistoricalForms: usize,
    SetHistoricalForms: usize,
    FractionProperty: usize,
    GetFraction: usize,
    SetFraction: usize,
    NumeralStyleProperty: usize,
    GetNumeralStyle: usize,
    SetNumeralStyle: usize,
    NumeralAlignmentProperty: usize,
    GetNumeralAlignment: usize,
    pub SetNumeralAlignment: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        FontNumeralAlignment,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IUIElement,
    IUIElement_Vtbl,
    0xc3c01020_320c_5cf6_9d24_d396bbfa4d8b
);
impl windows_core::RuntimeType for IUIElement {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IUIElement {
    pub fn DesiredSize(&self) -> windows_core::Result<Size> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).DesiredSize)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn SetAllowDrop(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetAllowDrop)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetOpacity(&self, value: f64) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetOpacity)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetClip<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<RectangleGeometry>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetClip)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetIsHitTestVisible(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsHitTestVisible)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn SetVisibility(&self, value: Visibility) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetVisibility)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn KeyboardAccelerators(
        &self,
    ) -> windows_core::Result<windows_collections::IVector<KeyboardAccelerator>> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).KeyboardAccelerators)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetTranslation(&self, value: Vector3) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetTranslation)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn XamlRoot(&self) -> windows_core::Result<XamlRoot> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).XamlRoot)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetXamlRoot<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<XamlRoot>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetXamlRoot)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn Shadow(&self) -> windows_core::Result<Shadow> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Shadow)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetIsTabStop(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetIsTabStop)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn KeyDown<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<KeyRoutedEventArgs>)
            + 'static,
    {
        let handler: KeyEventHandler = {
            let com = windows_core::imp::DelegateBox::<KeyEventHandler, F>::new(
                &KeyEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).KeyDown)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveKeyDown,
            ))
        }
    }
    pub fn GotFocus<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<RoutedEventArgs>)
            + 'static,
    {
        let handler: RoutedEventHandler = {
            let com = windows_core::imp::DelegateBox::<RoutedEventHandler, F>::new(
                &RoutedEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).GotFocus)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveGotFocus,
            ))
        }
    }
    pub fn LostFocus<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<RoutedEventArgs>)
            + 'static,
    {
        let handler: RoutedEventHandler = {
            let com = windows_core::imp::DelegateBox::<RoutedEventHandler, F>::new(
                &RoutedEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).LostFocus)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveLostFocus,
            ))
        }
    }
    pub fn PointerPressed<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<PointerRoutedEventArgs>,
            ) + 'static,
    {
        let handler: PointerEventHandler = {
            let com = windows_core::imp::DelegateBox::<PointerEventHandler, F>::new(
                &PointerEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).PointerPressed)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemovePointerPressed,
            ))
        }
    }
    pub fn PointerEntered<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<PointerRoutedEventArgs>,
            ) + 'static,
    {
        let handler: PointerEventHandler = {
            let com = windows_core::imp::DelegateBox::<PointerEventHandler, F>::new(
                &PointerEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).PointerEntered)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemovePointerEntered,
            ))
        }
    }
    pub fn PointerExited<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<PointerRoutedEventArgs>,
            ) + 'static,
    {
        let handler: PointerEventHandler = {
            let com = windows_core::imp::DelegateBox::<PointerEventHandler, F>::new(
                &PointerEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).PointerExited)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemovePointerExited,
            ))
        }
    }
    pub fn DoubleTapped<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<DoubleTappedRoutedEventArgs>,
            ) + 'static,
    {
        let handler: DoubleTappedEventHandler = {
            let com = windows_core::imp::DelegateBox::<DoubleTappedEventHandler, F>::new(
                &DoubleTappedEventHandlerBox::<F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).DoubleTapped)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveDoubleTapped,
            ))
        }
    }
    pub fn Measure(&self, availablesize: Size) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Measure)(
                windows_core::Interface::as_raw(self),
                availablesize,
            )
            .ok()
        }
    }
    pub fn TransformToVisual<P0>(&self, visual: P0) -> windows_core::Result<GeneralTransform>
    where
        P0: windows_core::Param<UIElement>,
    {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).TransformToVisual)(
                windows_core::Interface::as_raw(self),
                visual.param().abi(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn UpdateLayout(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).UpdateLayout)(windows_core::Interface::as_raw(
                self,
            ))
            .ok()
        }
    }
    pub fn Focus(&self, value: FocusState) -> windows_core::Result<bool> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Focus)(
                windows_core::Interface::as_raw(self),
                value,
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IUIElement_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub DesiredSize:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut Size) -> windows_core::HRESULT,
    AllowDrop: usize,
    pub SetAllowDrop:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    Opacity: usize,
    pub SetOpacity: unsafe extern "system" fn(*mut core::ffi::c_void, f64) -> windows_core::HRESULT,
    Clip: usize,
    pub SetClip: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    RenderTransform: usize,
    SetRenderTransform: usize,
    Projection: usize,
    SetProjection: usize,
    Transform3D: usize,
    SetTransform3D: usize,
    RenderTransformOrigin: usize,
    SetRenderTransformOrigin: usize,
    IsHitTestVisible: usize,
    pub SetIsHitTestVisible:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    Visibility: usize,
    pub SetVisibility:
        unsafe extern "system" fn(*mut core::ffi::c_void, Visibility) -> windows_core::HRESULT,
    RenderSize: usize,
    UseLayoutRounding: usize,
    SetUseLayoutRounding: usize,
    Transitions: usize,
    SetTransitions: usize,
    CacheMode: usize,
    SetCacheMode: usize,
    IsTapEnabled: usize,
    SetIsTapEnabled: usize,
    IsDoubleTapEnabled: usize,
    SetIsDoubleTapEnabled: usize,
    CanDrag: usize,
    SetCanDrag: usize,
    IsRightTapEnabled: usize,
    SetIsRightTapEnabled: usize,
    IsHoldingEnabled: usize,
    SetIsHoldingEnabled: usize,
    ManipulationMode: usize,
    SetManipulationMode: usize,
    PointerCaptures: usize,
    ContextFlyout: usize,
    SetContextFlyout: usize,
    CompositeMode: usize,
    SetCompositeMode: usize,
    Lights: usize,
    CanBeScrollAnchor: usize,
    SetCanBeScrollAnchor: usize,
    ExitDisplayModeOnAccessKeyInvoked: usize,
    SetExitDisplayModeOnAccessKeyInvoked: usize,
    IsAccessKeyScope: usize,
    SetIsAccessKeyScope: usize,
    AccessKeyScopeOwner: usize,
    SetAccessKeyScopeOwner: usize,
    AccessKey: usize,
    SetAccessKey: usize,
    KeyTipPlacementMode: usize,
    SetKeyTipPlacementMode: usize,
    KeyTipHorizontalOffset: usize,
    SetKeyTipHorizontalOffset: usize,
    KeyTipVerticalOffset: usize,
    SetKeyTipVerticalOffset: usize,
    KeyTipTarget: usize,
    SetKeyTipTarget: usize,
    XYFocusKeyboardNavigation: usize,
    SetXYFocusKeyboardNavigation: usize,
    XYFocusUpNavigationStrategy: usize,
    SetXYFocusUpNavigationStrategy: usize,
    XYFocusDownNavigationStrategy: usize,
    SetXYFocusDownNavigationStrategy: usize,
    XYFocusLeftNavigationStrategy: usize,
    SetXYFocusLeftNavigationStrategy: usize,
    XYFocusRightNavigationStrategy: usize,
    SetXYFocusRightNavigationStrategy: usize,
    pub KeyboardAccelerators: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    KeyboardAcceleratorPlacementTarget: usize,
    SetKeyboardAcceleratorPlacementTarget: usize,
    KeyboardAcceleratorPlacementMode: usize,
    SetKeyboardAcceleratorPlacementMode: usize,
    HighContrastAdjustment: usize,
    SetHighContrastAdjustment: usize,
    TabFocusNavigation: usize,
    SetTabFocusNavigation: usize,
    OpacityTransition: usize,
    SetOpacityTransition: usize,
    Translation: usize,
    pub SetTranslation:
        unsafe extern "system" fn(*mut core::ffi::c_void, Vector3) -> windows_core::HRESULT,
    TranslationTransition: usize,
    SetTranslationTransition: usize,
    Rotation: usize,
    SetRotation: usize,
    RotationTransition: usize,
    SetRotationTransition: usize,
    Scale: usize,
    SetScale: usize,
    ScaleTransition: usize,
    SetScaleTransition: usize,
    TransformMatrix: usize,
    SetTransformMatrix: usize,
    CenterPoint: usize,
    SetCenterPoint: usize,
    RotationAxis: usize,
    SetRotationAxis: usize,
    ActualOffset: usize,
    ActualSize: usize,
    pub XamlRoot: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetXamlRoot: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub Shadow: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    SetShadow: usize,
    RasterizationScale: usize,
    SetRasterizationScale: usize,
    FocusState: usize,
    UseSystemFocusVisuals: usize,
    SetUseSystemFocusVisuals: usize,
    XYFocusLeft: usize,
    SetXYFocusLeft: usize,
    XYFocusRight: usize,
    SetXYFocusRight: usize,
    XYFocusUp: usize,
    SetXYFocusUp: usize,
    XYFocusDown: usize,
    SetXYFocusDown: usize,
    IsTabStop: usize,
    pub SetIsTabStop:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    TabIndex: usize,
    SetTabIndex: usize,
    KeyUp: usize,
    RemoveKeyUp: usize,
    pub KeyDown: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveKeyDown:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    pub GotFocus: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveGotFocus:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    pub LostFocus: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveLostFocus:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    DragStarting: usize,
    RemoveDragStarting: usize,
    DropCompleted: usize,
    RemoveDropCompleted: usize,
    CharacterReceived: usize,
    RemoveCharacterReceived: usize,
    DragEnter: usize,
    RemoveDragEnter: usize,
    DragLeave: usize,
    RemoveDragLeave: usize,
    DragOver: usize,
    RemoveDragOver: usize,
    Drop: usize,
    RemoveDrop: usize,
    pub PointerPressed: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemovePointerPressed:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    PointerMoved: usize,
    RemovePointerMoved: usize,
    PointerReleased: usize,
    RemovePointerReleased: usize,
    pub PointerEntered: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemovePointerEntered:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    pub PointerExited: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemovePointerExited:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    PointerCaptureLost: usize,
    RemovePointerCaptureLost: usize,
    PointerCanceled: usize,
    RemovePointerCanceled: usize,
    PointerWheelChanged: usize,
    RemovePointerWheelChanged: usize,
    Tapped: usize,
    RemoveTapped: usize,
    pub DoubleTapped: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveDoubleTapped:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    Holding: usize,
    RemoveHolding: usize,
    ContextRequested: usize,
    RemoveContextRequested: usize,
    ContextCanceled: usize,
    RemoveContextCanceled: usize,
    RightTapped: usize,
    RemoveRightTapped: usize,
    ManipulationStarting: usize,
    RemoveManipulationStarting: usize,
    ManipulationInertiaStarting: usize,
    RemoveManipulationInertiaStarting: usize,
    ManipulationStarted: usize,
    RemoveManipulationStarted: usize,
    ManipulationDelta: usize,
    RemoveManipulationDelta: usize,
    ManipulationCompleted: usize,
    RemoveManipulationCompleted: usize,
    AccessKeyDisplayRequested: usize,
    RemoveAccessKeyDisplayRequested: usize,
    AccessKeyDisplayDismissed: usize,
    RemoveAccessKeyDisplayDismissed: usize,
    AccessKeyInvoked: usize,
    RemoveAccessKeyInvoked: usize,
    ProcessKeyboardAccelerators: usize,
    RemoveProcessKeyboardAccelerators: usize,
    GettingFocus: usize,
    RemoveGettingFocus: usize,
    LosingFocus: usize,
    RemoveLosingFocus: usize,
    NoFocusCandidateFound: usize,
    RemoveNoFocusCandidateFound: usize,
    PreviewKeyDown: usize,
    RemovePreviewKeyDown: usize,
    PreviewKeyUp: usize,
    RemovePreviewKeyUp: usize,
    BringIntoViewRequested: usize,
    RemoveBringIntoViewRequested: usize,
    pub Measure: unsafe extern "system" fn(*mut core::ffi::c_void, Size) -> windows_core::HRESULT,
    Arrange: usize,
    CapturePointer: usize,
    ReleasePointerCapture: usize,
    ReleasePointerCaptures: usize,
    AddHandler: usize,
    RemoveHandler: usize,
    pub TransformToVisual: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    InvalidateMeasure: usize,
    InvalidateArrange: usize,
    pub UpdateLayout: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
    CancelDirectManipulations: usize,
    StartDragAsync: usize,
    StartBringIntoView: usize,
    StartBringIntoViewWithOptions: usize,
    TryInvokeKeyboardAccelerator: usize,
    pub Focus: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        FocusState,
        *mut bool,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IVisualTreeHelper,
    IVisualTreeHelper_Vtbl,
    0x5f69ac1e_6504_5e3f_a11c_87684c1db814
);
impl windows_core::RuntimeType for IVisualTreeHelper {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IVisualTreeHelper_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IVisualTreeHelperStatics,
    IVisualTreeHelperStatics_Vtbl,
    0x5aece43c_7651_5bb5_855c_2198496e455e
);
impl windows_core::RuntimeType for IVisualTreeHelperStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IVisualTreeHelperStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    FindElementsInHostCoordinatesPoint: usize,
    FindElementsInHostCoordinatesRect: usize,
    FindAllElementsInHostCoordinatesPoint: usize,
    FindAllElementsInHostCoordinatesRect: usize,
    pub GetChild: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        i32,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub GetChildrenCount: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i32,
    ) -> windows_core::HRESULT,
    pub GetParent: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IWindow,
    IWindow_Vtbl,
    0x61f0ec79_5d52_56b5_86fb_40fa4af288b0
);
impl windows_core::RuntimeType for IWindow {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IWindow {
    pub fn Content(&self) -> windows_core::Result<UIElement> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).Content)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn SetContent<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<UIElement>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetContent)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn SetTitle(&self, value: &str) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetTitle)(
                windows_core::Interface::as_raw(self),
                core::mem::transmute_copy(&windows_core::HSTRING::from(value)),
            )
            .ok()
        }
    }
    pub fn SetExtendsContentIntoTitleBar(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetExtendsContentIntoTitleBar)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
    pub fn Activated<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<WindowActivatedEventArgs>,
            ) + 'static,
    {
        let handler: TypedEventHandler<windows_core::IInspectable, WindowActivatedEventArgs> = {
            let com = windows_core::imp::DelegateBox::< TypedEventHandler < windows_core::IInspectable , WindowActivatedEventArgs > , F >::new (& TypedEventHandlerBox::< windows_core::IInspectable , WindowActivatedEventArgs , F >::VTABLE , handler) ;
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Activated)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveActivated,
            ))
        }
    }
    pub fn Closed<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<WindowEventArgs>)
            + 'static,
    {
        let handler: TypedEventHandler<windows_core::IInspectable, WindowEventArgs> = {
            let com = windows_core::imp::DelegateBox::<
                TypedEventHandler<windows_core::IInspectable, WindowEventArgs>,
                F,
            >::new(
                &TypedEventHandlerBox::<windows_core::IInspectable, WindowEventArgs, F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Closed)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveClosed,
            ))
        }
    }
    pub fn Activate(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Activate)(windows_core::Interface::as_raw(self))
                .ok()
        }
    }
    pub fn Close(&self) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).Close)(windows_core::Interface::as_raw(self))
                .ok()
        }
    }
}
#[repr(C)]
pub struct IWindow_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Bounds: usize,
    Visible: usize,
    pub Content: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub SetContent: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    CoreWindow: usize,
    Compositor: usize,
    Dispatcher: usize,
    DispatcherQueue: usize,
    Title: usize,
    pub SetTitle: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    ExtendsContentIntoTitleBar: usize,
    pub SetExtendsContentIntoTitleBar:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
    pub Activated: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveActivated:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    pub Closed: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveClosed:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
    SizeChanged: usize,
    RemoveSizeChanged: usize,
    VisibilityChanged: usize,
    RemoveVisibilityChanged: usize,
    pub Activate: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
    pub Close: unsafe extern "system" fn(*mut core::ffi::c_void) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IWindow2,
    IWindow2_Vtbl,
    0x42febaa5_1c32_522a_a591_57618c6f665d
);
impl windows_core::RuntimeType for IWindow2 {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IWindow2 {
    pub fn SetSystemBackdrop<P0>(&self, value: P0) -> windows_core::Result<()>
    where
        P0: windows_core::Param<SystemBackdrop>,
    {
        unsafe {
            (windows_core::Interface::vtable(self).SetSystemBackdrop)(
                windows_core::Interface::as_raw(self),
                value.param().abi(),
            )
            .ok()
        }
    }
    pub fn AppWindow(&self) -> windows_core::Result<AppWindow> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).AppWindow)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
}
#[repr(C)]
pub struct IWindow2_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    SystemBackdrop: usize,
    pub SetSystemBackdrop: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub AppWindow: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IWindowActivatedEventArgs,
    IWindowActivatedEventArgs_Vtbl,
    0xc723a5ea_82c4_5dd6_861b_70ef573b88d6
);
impl windows_core::RuntimeType for IWindowActivatedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IWindowActivatedEventArgs {
    pub fn WindowActivationState(&self) -> windows_core::Result<WindowActivationState> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).WindowActivationState)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
}
#[repr(C)]
pub struct IWindowActivatedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Handled: usize,
    SetHandled: usize,
    pub WindowActivationState: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut WindowActivationState,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IWindowEventArgs,
    IWindowEventArgs_Vtbl,
    0x1140827c_fe0a_5268_bc2b_f4492c2ccb49
);
impl windows_core::RuntimeType for IWindowEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IWindowEventArgs {
    pub fn SetHandled(&self, value: bool) -> windows_core::Result<()> {
        unsafe {
            (windows_core::Interface::vtable(self).SetHandled)(
                windows_core::Interface::as_raw(self),
                value,
            )
            .ok()
        }
    }
}
#[repr(C)]
pub struct IWindowEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Handled: usize,
    pub SetHandled:
        unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IWindowFactory,
    IWindowFactory_Vtbl,
    0xf0441536_afef_5222_918f_324a9b2dec75
);
impl windows_core::RuntimeType for IWindowFactory {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IWindowFactory_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub CreateInstance: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IXamlBindingHelper,
    IXamlBindingHelper_Vtbl,
    0x607a9bf2_5a6d_5c89_a756_bb44f24f28f8
);
impl windows_core::RuntimeType for IXamlBindingHelper {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IXamlBindingHelper_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IXamlBindingHelperStatics,
    IXamlBindingHelperStatics_Vtbl,
    0x93c7dad3_f9c2_5372_84dc_9e9c4661d083
);
impl windows_core::RuntimeType for IXamlBindingHelperStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IXamlBindingHelperStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    DataTemplateComponentProperty: usize,
    GetDataTemplateComponent: usize,
    SetDataTemplateComponent: usize,
    SuspendRendering: usize,
    ResumeRendering: usize,
    pub ConvertValue: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        core::mem::MaybeUninit<TypeName>,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IXamlControlsResources,
    IXamlControlsResources_Vtbl,
    0x918ca043_f42c_5805_861b_62d6d1d0c162
);
impl windows_core::RuntimeType for IXamlControlsResources {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IXamlControlsResources_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IXamlMetadataProvider,
    IXamlMetadataProvider_Vtbl,
    0xa96251f0_2214_5d53_8746_ce99a2593cd7
);
impl windows_core::RuntimeType for IXamlMetadataProvider {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
    const NAME: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"Microsoft.UI.Xaml.Markup.IXamlMetadataProvider",
    );
}
windows_core::imp::interface_hierarchy!(
    IXamlMetadataProvider,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl IXamlMetadataProvider {
    pub fn GetXamlType(&self, r#type: &TypeName) -> windows_core::Result<IXamlType> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetXamlType)(
                windows_core::Interface::as_raw(self),
                core::mem::transmute_copy(r#type),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn GetXamlTypeByFullName(&self, fullname: &str) -> windows_core::Result<IXamlType> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).GetXamlTypeByFullName)(
                windows_core::Interface::as_raw(self),
                core::mem::transmute_copy(&windows_core::HSTRING::from(fullname)),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        }
    }
    pub fn GetXmlnsDefinitions(
        &self,
    ) -> windows_core::Result<windows_core::Array<XmlnsDefinition>> {
        unsafe {
            let mut result__ = core::mem::MaybeUninit::zeroed();
            (windows_core::Interface::vtable(self).GetXmlnsDefinitions)(
                windows_core::Interface::as_raw(self),
                windows_core::Array::<XmlnsDefinition>::set_abi_len(core::mem::transmute(
                    &mut result__,
                )),
                result__.as_mut_ptr() as *mut _ as _,
            )
            .map(|| result__.assume_init())
        }
    }
}
impl windows_core::RuntimeName for IXamlMetadataProvider {
    const NAME: &'static str = "Microsoft.UI.Xaml.Markup.IXamlMetadataProvider";
}
pub trait IXamlMetadataProvider_Impl: windows_core::IUnknownImpl {
    fn GetXamlType(&self, r#type: &TypeName) -> windows_core::Result<IXamlType>;
    fn GetXamlTypeByFullName(
        &self,
        fullName: &windows_core::HSTRING,
    ) -> windows_core::Result<IXamlType>;
    fn GetXmlnsDefinitions(&self) -> windows_core::Result<windows_core::Array<XmlnsDefinition>>;
}
impl IXamlMetadataProvider_Vtbl {
    pub const fn new<Identity: IXamlMetadataProvider_Impl, const OFFSET: isize>() -> Self {
        unsafe extern "system" fn GetXamlType<
            Identity: IXamlMetadataProvider_Impl,
            const OFFSET: isize,
        >(
            this: *mut core::ffi::c_void,
            r#type: core::mem::MaybeUninit<TypeName>,
            result__: *mut *mut core::ffi::c_void,
        ) -> windows_core::HRESULT {
            unsafe {
                let this: &Identity =
                    &*((this as *const *const ()).offset(OFFSET) as *const Identity);
                match IXamlMetadataProvider_Impl::GetXamlType(this, core::mem::transmute(&r#type)) {
                    Ok(ok__) => {
                        result__.write(core::mem::transmute_copy(&ok__));
                        core::mem::forget(ok__);
                        windows_core::HRESULT(0)
                    }
                    Err(err) => err.into(),
                }
            }
        }
        unsafe extern "system" fn GetXamlTypeByFullName<
            Identity: IXamlMetadataProvider_Impl,
            const OFFSET: isize,
        >(
            this: *mut core::ffi::c_void,
            fullname: *mut core::ffi::c_void,
            result__: *mut *mut core::ffi::c_void,
        ) -> windows_core::HRESULT {
            unsafe {
                let this: &Identity =
                    &*((this as *const *const ()).offset(OFFSET) as *const Identity);
                match IXamlMetadataProvider_Impl::GetXamlTypeByFullName(
                    this,
                    core::mem::transmute(&fullname),
                ) {
                    Ok(ok__) => {
                        result__.write(core::mem::transmute_copy(&ok__));
                        core::mem::forget(ok__);
                        windows_core::HRESULT(0)
                    }
                    Err(err) => err.into(),
                }
            }
        }
        unsafe extern "system" fn GetXmlnsDefinitions<
            Identity: IXamlMetadataProvider_Impl,
            const OFFSET: isize,
        >(
            this: *mut core::ffi::c_void,
            result_size__: *mut u32,
            result__: *mut *mut core::mem::MaybeUninit<XmlnsDefinition>,
        ) -> windows_core::HRESULT {
            unsafe {
                let this: &Identity =
                    &*((this as *const *const ()).offset(OFFSET) as *const Identity);
                match IXamlMetadataProvider_Impl::GetXmlnsDefinitions(this) {
                    Ok(ok__) => {
                        let (ok_data__, ok_data_len__) = ok__.into_abi();
                        result__.write(ok_data__);
                        result_size__.write(ok_data_len__);
                        windows_core::HRESULT(0)
                    }
                    Err(err) => err.into(),
                }
            }
        }
        Self {
            base__: windows_core::IInspectable_Vtbl::new::<Identity, IXamlMetadataProvider, OFFSET>(
            ),
            GetXamlType: GetXamlType::<Identity, OFFSET>,
            GetXamlTypeByFullName: GetXamlTypeByFullName::<Identity, OFFSET>,
            GetXmlnsDefinitions: GetXmlnsDefinitions::<Identity, OFFSET>,
        }
    }
    pub fn matches(iid: &windows_core::GUID) -> bool {
        iid == &<IXamlMetadataProvider as windows_core::Interface>::IID
    }
}
#[repr(C)]
pub struct IXamlMetadataProvider_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub GetXamlType: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        core::mem::MaybeUninit<TypeName>,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub GetXamlTypeByFullName: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
    pub GetXmlnsDefinitions: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut u32,
        *mut *mut core::mem::MaybeUninit<XmlnsDefinition>,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IXamlReader,
    IXamlReader_Vtbl,
    0x54ce54c8_38c6_50d9_ac98_4b03eddbde9f
);
impl windows_core::RuntimeType for IXamlReader {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IXamlReader_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IXamlReaderStatics,
    IXamlReaderStatics_Vtbl,
    0x82a4cd9e_435e_5aeb_8c4f_300cece45cae
);
impl windows_core::RuntimeType for IXamlReaderStatics {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IXamlReaderStatics_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    pub Load: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IXamlRoot,
    IXamlRoot_Vtbl,
    0x60cb215a_ad15_520a_8b01_4416824f0441
);
impl windows_core::RuntimeType for IXamlRoot {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
impl IXamlRoot {
    pub fn RasterizationScale(&self) -> windows_core::Result<f64> {
        unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(self).RasterizationScale)(
                windows_core::Interface::as_raw(self),
                &mut result__,
            )
            .map(|| result__)
        }
    }
    pub fn Changed<F>(&self, handler: F) -> windows_core::Result<windows_core::EventRevoker>
    where
        F: Fn(windows_core::Ref<XamlRoot>, windows_core::Ref<XamlRootChangedEventArgs>) + 'static,
    {
        let handler: TypedEventHandler<XamlRoot, XamlRootChangedEventArgs> = {
            let com = windows_core::imp::DelegateBox::<
                TypedEventHandler<XamlRoot, XamlRootChangedEventArgs>,
                F,
            >::new(
                &TypedEventHandlerBox::<XamlRoot, XamlRootChangedEventArgs, F>::VTABLE,
                handler,
            );
            unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
        };
        unsafe {
            let mut result__ = core::mem::zeroed();
            let token__ = (windows_core::Interface::vtable(self).Changed)(
                windows_core::Interface::as_raw(self),
                windows_core::Interface::as_raw(&handler),
                &mut result__,
            )
            .map(|| result__)?;
            Ok(windows_core::EventRevoker::new(
                self.clone(),
                token__,
                windows_core::Interface::vtable(self).RemoveChanged,
            ))
        }
    }
}
#[repr(C)]
pub struct IXamlRoot_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
    Content: usize,
    Size: usize,
    pub RasterizationScale:
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut f64) -> windows_core::HRESULT,
    IsHostVisible: usize,
    pub Changed: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i64,
    ) -> windows_core::HRESULT,
    pub RemoveChanged:
        unsafe extern "system" fn(*mut core::ffi::c_void, i64) -> windows_core::HRESULT,
}
windows_core::imp::define_interface!(
    IXamlRootChangedEventArgs,
    IXamlRootChangedEventArgs_Vtbl,
    0x61d2c719_f8a1_515a_902c_cfa498ba7a7f
);
impl windows_core::RuntimeType for IXamlRootChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct IXamlRootChangedEventArgs_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
windows_core::imp::define_interface!(
    IXamlType,
    IXamlType_Vtbl,
    0xd24219df_7ec9_57f1_a27b_6af251d9c5bc
);
impl windows_core::RuntimeType for IXamlType {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
windows_core::imp::interface_hierarchy!(
    IXamlType,
    windows_core::IUnknown,
    windows_core::IInspectable
);
#[repr(C)]
pub struct IXamlType_Vtbl {
    pub base__: windows_core::IInspectable_Vtbl,
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IconElement(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    IconElement,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(IconElement, FrameworkElement, UIElement, DependencyObject);
impl windows_core::RuntimeType for IconElement {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IIconElement>();
}
unsafe impl windows_core::Interface for IconElement {
    type Vtable = <IIconElement as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IIconElement as windows_core::Interface>::IID;
}
impl core::ops::Deref for IconElement {
    type Target = IIconElement;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for IconElement {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.IconElement";
}
unsafe impl Send for IconElement {}
unsafe impl Sync for IconElement {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Image(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Image, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Image, FrameworkElement, UIElement, DependencyObject);
impl Image {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Image, windows_core::imp::IGenericFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Image {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IImage>();
}
unsafe impl windows_core::Interface for Image {
    type Vtable = <IImage as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IImage as windows_core::Interface>::IID;
}
impl core::ops::Deref for Image {
    type Target = IImage;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Image {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Image";
}
unsafe impl Send for Image {}
unsafe impl Sync for Image {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageSource(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ImageSource,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(ImageSource, DependencyObject);
impl windows_core::RuntimeType for ImageSource {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IImageSource>();
}
unsafe impl windows_core::Interface for ImageSource {
    type Vtable = <IImageSource as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IImageSource as windows_core::Interface>::IID;
}
impl core::ops::Deref for ImageSource {
    type Target = IImageSource;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ImageSource {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.ImageSource";
}
unsafe impl Send for ImageSource {}
unsafe impl Sync for ImageSource {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputNonClientPointerSource(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    InputNonClientPointerSource,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl InputNonClientPointerSource {
    pub fn GetForWindowId(windowid: WindowId) -> windows_core::Result<Self> {
        Self::IInputNonClientPointerSourceStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).GetForWindowId)(
                windows_core::Interface::as_raw(this),
                windowid,
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IInputNonClientPointerSourceStatics<
        R,
        F: FnOnce(&IInputNonClientPointerSourceStatics) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            InputNonClientPointerSource,
            IInputNonClientPointerSourceStatics,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for InputNonClientPointerSource {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IInputNonClientPointerSource>();
}
unsafe impl windows_core::Interface for InputNonClientPointerSource {
    type Vtable = <IInputNonClientPointerSource as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IInputNonClientPointerSource as windows_core::Interface>::IID;
}
impl core::ops::Deref for InputNonClientPointerSource {
    type Target = IInputNonClientPointerSource;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for InputNonClientPointerSource {
    const NAME: &'static str = "Microsoft.UI.Input.InputNonClientPointerSource";
}
unsafe impl Send for InputNonClientPointerSource {}
unsafe impl Sync for InputNonClientPointerSource {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsTextTrimmedChangedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    IsTextTrimmedChangedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for IsTextTrimmedChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IIsTextTrimmedChangedEventArgs>();
}
unsafe impl windows_core::Interface for IsTextTrimmedChangedEventArgs {
    type Vtable = <IIsTextTrimmedChangedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <IIsTextTrimmedChangedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for IsTextTrimmedChangedEventArgs {
    type Target = IIsTextTrimmedChangedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for IsTextTrimmedChangedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.IsTextTrimmedChangedEventArgs";
}
unsafe impl Send for IsTextTrimmedChangedEventArgs {}
unsafe impl Sync for IsTextTrimmedChangedEventArgs {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemClickEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ItemClickEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(ItemClickEventArgs, RoutedEventArgs);
impl windows_core::RuntimeType for ItemClickEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IItemClickEventArgs>();
}
unsafe impl windows_core::Interface for ItemClickEventArgs {
    type Vtable = <IItemClickEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IItemClickEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for ItemClickEventArgs {
    type Target = IItemClickEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ItemClickEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ItemClickEventArgs";
}
unsafe impl Send for ItemClickEventArgs {}
unsafe impl Sync for ItemClickEventArgs {}
windows_core::imp::define_interface!(
    ItemClickEventHandler,
    ItemClickEventHandler_Vtbl,
    0xa3903624_3393_566c_a6b9_a6b4b3e301c3
);
impl windows_core::RuntimeType for ItemClickEventHandler {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct ItemClickEventHandler_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
struct ItemClickEventHandlerBox<
    F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<ItemClickEventArgs>)
        + 'static,
>(core::marker::PhantomData<(fn() -> F,)>);
impl<
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<ItemClickEventArgs>)
            + 'static,
    > ItemClickEventHandlerBox<F>
{
    const VTABLE: ItemClickEventHandler_Vtbl = ItemClickEventHandler_Vtbl {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface:
                windows_core::imp::DelegateBox::<ItemClickEventHandler, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<ItemClickEventHandler, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<ItemClickEventHandler, F>::Release,
        },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<ItemClickEventHandler, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&e),
            );
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemCollection(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ItemCollection,
    windows_core::IUnknown,
    windows_core::IInspectable,
    windows_collections::IObservableVector<windows_core::IInspectable>
);
impl windows_core::RuntimeType for ItemCollection {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::for_class::<
        Self,
        windows_collections::IObservableVector<windows_core::IInspectable>,
    >();
}
unsafe impl windows_core::Interface for ItemCollection {
    type Vtable = < windows_collections::IObservableVector < windows_core::IInspectable > as windows_core::Interface >::Vtable ;
    const IID: windows_core::GUID = <windows_collections::IObservableVector<
        windows_core::IInspectable,
    > as windows_core::Interface>::IID;
}
impl core::ops::Deref for ItemCollection {
    type Target = windows_collections::IObservableVector<windows_core::IInspectable>;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ItemCollection {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ItemCollection";
}
unsafe impl Send for ItemCollection {}
unsafe impl Sync for ItemCollection {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemContainer(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ItemContainer,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ItemContainer,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for ItemContainer {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IItemContainer>();
}
unsafe impl windows_core::Interface for ItemContainer {
    type Vtable = <IItemContainer as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IItemContainer as windows_core::Interface>::IID;
}
impl core::ops::Deref for ItemContainer {
    type Target = IItemContainer;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ItemContainer {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ItemContainer";
}
unsafe impl Send for ItemContainer {}
unsafe impl Sync for ItemContainer {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemIndexRange(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ItemIndexRange,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for ItemIndexRange {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IItemIndexRange>();
}
unsafe impl windows_core::Interface for ItemIndexRange {
    type Vtable = <IItemIndexRange as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IItemIndexRange as windows_core::Interface>::IID;
}
impl core::ops::Deref for ItemIndexRange {
    type Target = IItemIndexRange;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ItemIndexRange {
    const NAME: &'static str = "Microsoft.UI.Xaml.Data.ItemIndexRange";
}
unsafe impl Send for ItemIndexRange {}
unsafe impl Sync for ItemIndexRange {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemsControl(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ItemsControl,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ItemsControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for ItemsControl {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IItemsControl>();
}
unsafe impl windows_core::Interface for ItemsControl {
    type Vtable = <IItemsControl as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IItemsControl as windows_core::Interface>::IID;
}
impl core::ops::Deref for ItemsControl {
    type Target = IItemsControl;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ItemsControl {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ItemsControl";
}
unsafe impl Send for ItemsControl {}
unsafe impl Sync for ItemsControl {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemsPanelTemplate(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ItemsPanelTemplate,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(ItemsPanelTemplate, FrameworkTemplate, DependencyObject);
impl windows_core::RuntimeType for ItemsPanelTemplate {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IItemsPanelTemplate>();
}
unsafe impl windows_core::Interface for ItemsPanelTemplate {
    type Vtable = <IItemsPanelTemplate as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IItemsPanelTemplate as windows_core::Interface>::IID;
}
impl core::ops::Deref for ItemsPanelTemplate {
    type Target = IItemsPanelTemplate;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ItemsPanelTemplate {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ItemsPanelTemplate";
}
unsafe impl Send for ItemsPanelTemplate {}
unsafe impl Sync for ItemsPanelTemplate {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemsWrapGrid(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ItemsWrapGrid,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ItemsWrapGrid,
    Panel,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for ItemsWrapGrid {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IItemsWrapGrid>();
}
unsafe impl windows_core::Interface for ItemsWrapGrid {
    type Vtable = <IItemsWrapGrid as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IItemsWrapGrid as windows_core::Interface>::IID;
}
impl core::ops::Deref for ItemsWrapGrid {
    type Target = IItemsWrapGrid;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ItemsWrapGrid {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ItemsWrapGrid";
}
unsafe impl Send for ItemsWrapGrid {}
unsafe impl Sync for ItemsWrapGrid {}
windows_core::imp::define_interface!(
    KeyEventHandler,
    KeyEventHandler_Vtbl,
    0xdb68e7cc_9a2b_527d_9989_25284daccc03
);
impl windows_core::RuntimeType for KeyEventHandler {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct KeyEventHandler_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
struct KeyEventHandlerBox<
    F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<KeyRoutedEventArgs>)
        + 'static,
>(core::marker::PhantomData<(fn() -> F,)>);
impl<
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<KeyRoutedEventArgs>)
            + 'static,
    > KeyEventHandlerBox<F>
{
    const VTABLE: KeyEventHandler_Vtbl = KeyEventHandler_Vtbl {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface: windows_core::imp::DelegateBox::<KeyEventHandler, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<KeyEventHandler, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<KeyEventHandler, F>::Release,
        },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<KeyEventHandler, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&e),
            );
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRoutedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    KeyRoutedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(KeyRoutedEventArgs, RoutedEventArgs);
impl windows_core::RuntimeType for KeyRoutedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IKeyRoutedEventArgs>();
}
unsafe impl windows_core::Interface for KeyRoutedEventArgs {
    type Vtable = <IKeyRoutedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IKeyRoutedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for KeyRoutedEventArgs {
    type Target = IKeyRoutedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for KeyRoutedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Input.KeyRoutedEventArgs";
}
unsafe impl Send for KeyRoutedEventArgs {}
unsafe impl Sync for KeyRoutedEventArgs {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyboardAccelerator(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    KeyboardAccelerator,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(KeyboardAccelerator, DependencyObject);
impl KeyboardAccelerator {
    pub fn new() -> windows_core::Result<Self> {
        Self::IKeyboardAcceleratorFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IKeyboardAcceleratorFactory<
        R,
        F: FnOnce(&IKeyboardAcceleratorFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            KeyboardAccelerator,
            IKeyboardAcceleratorFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for KeyboardAccelerator {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IKeyboardAccelerator>();
}
unsafe impl windows_core::Interface for KeyboardAccelerator {
    type Vtable = <IKeyboardAccelerator as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IKeyboardAccelerator as windows_core::Interface>::IID;
}
impl core::ops::Deref for KeyboardAccelerator {
    type Target = IKeyboardAccelerator;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for KeyboardAccelerator {
    const NAME: &'static str = "Microsoft.UI.Xaml.Input.KeyboardAccelerator";
}
unsafe impl Send for KeyboardAccelerator {}
unsafe impl Sync for KeyboardAccelerator {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyboardAcceleratorInvokedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    KeyboardAcceleratorInvokedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for KeyboardAcceleratorInvokedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IKeyboardAcceleratorInvokedEventArgs>();
}
unsafe impl windows_core::Interface for KeyboardAcceleratorInvokedEventArgs {
    type Vtable = <IKeyboardAcceleratorInvokedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <IKeyboardAcceleratorInvokedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for KeyboardAcceleratorInvokedEventArgs {
    type Target = IKeyboardAcceleratorInvokedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for KeyboardAcceleratorInvokedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Input.KeyboardAcceleratorInvokedEventArgs";
}
unsafe impl Send for KeyboardAcceleratorInvokedEventArgs {}
unsafe impl Sync for KeyboardAcceleratorInvokedEventArgs {}
pub const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: i32 = 256;
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: i32 = 2048;
pub type LPARAM = isize;
pub type LRESULT = isize;
pub const LR_DEFAULTCOLOR: i32 = 0;
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchActivatedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    LaunchActivatedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for LaunchActivatedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ILaunchActivatedEventArgs>();
}
unsafe impl windows_core::Interface for LaunchActivatedEventArgs {
    type Vtable = <ILaunchActivatedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ILaunchActivatedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for LaunchActivatedEventArgs {
    type Target = ILaunchActivatedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for LaunchActivatedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.LaunchActivatedEventArgs";
}
unsafe impl Send for LaunchActivatedEventArgs {}
unsafe impl Sync for LaunchActivatedEventArgs {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListView(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ListView,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ListView,
    ListViewBase,
    Selector,
    ItemsControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl ListView {
    pub fn new() -> windows_core::Result<Self> {
        Self::IListViewFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IListViewFactory<R, F: FnOnce(&IListViewFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<ListView, IListViewFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for ListView {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IListView>();
}
unsafe impl windows_core::Interface for ListView {
    type Vtable = <IListView as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IListView as windows_core::Interface>::IID;
}
impl core::ops::Deref for ListView {
    type Target = IListView;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ListView {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ListView";
}
unsafe impl Send for ListView {}
unsafe impl Sync for ListView {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListViewBase(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ListViewBase,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ListViewBase,
    Selector,
    ItemsControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for ListViewBase {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IListViewBase>();
}
unsafe impl windows_core::Interface for ListViewBase {
    type Vtable = <IListViewBase as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IListViewBase as windows_core::Interface>::IID;
}
impl core::ops::Deref for ListViewBase {
    type Target = IListViewBase;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ListViewBase {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ListViewBase";
}
unsafe impl Send for ListViewBase {}
unsafe impl Sync for ListViewBase {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListViewItem(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ListViewItem,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ListViewItem,
    SelectorItem,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for ListViewItem {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IListViewItem>();
}
unsafe impl windows_core::Interface for ListViewItem {
    type Vtable = <IListViewItem as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IListViewItem as windows_core::Interface>::IID;
}
impl core::ops::Deref for ListViewItem {
    type Target = IListViewItem;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ListViewItem {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ListViewItem";
}
unsafe impl Send for ListViewItem {}
unsafe impl Sync for ListViewItem {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ListViewSelectionMode(pub i32);
impl ListViewSelectionMode {
    pub const None: Self = Self(0);
    pub const Single: Self = Self(1);
    pub const Extended: Self = Self(3);
}
impl windows_core::imp::TypeKind for ListViewSelectionMode {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for ListViewSelectionMode {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.Controls.ListViewSelectionMode;i4)",
    );
}
pub const MB_ICONERROR: i32 = 16;
pub const MB_OK: i32 = 0;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MENUITEMINFOW {
    pub cbSize: u32,
    pub fMask: u32,
    pub fType: u32,
    pub fState: u32,
    pub wID: u32,
    pub hSubMenu: HMENU,
    pub hbmpChecked: HBITMAP,
    pub hbmpUnchecked: HBITMAP,
    pub dwItemData: usize,
    pub dwTypeData: windows_core::PWSTR,
    pub cch: u32,
    pub hbmpItem: HBITMAP,
}
pub const MFS_CHECKED: i32 = 8;
pub const MFS_GRAYED: i32 = 3;
pub const MFT_RADIOCHECK: i32 = 512;
pub const MFT_SEPARATOR: i32 = 2048;
pub const MF_BYPOSITION: i32 = 1024;
pub const MF_CHECKED: i32 = 8;
pub const MF_GRAYED: i32 = 1;
pub const MF_POPUP: i32 = 16;
pub const MF_SEPARATOR: i32 = 2048;
pub const MF_STRING: i32 = 0;
pub const MIIM_FTYPE: i32 = 256;
pub const MIIM_STATE: i32 = 1;
pub type MMRESULT = u32;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MSG {
    pub hwnd: HWND,
    pub message: u32,
    pub wParam: WPARAM,
    pub lParam: LPARAM,
    pub time: u32,
    pub pt: POINT,
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MicaBackdrop(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    MicaBackdrop,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(MicaBackdrop, SystemBackdrop, DependencyObject);
impl MicaBackdrop {
    pub fn new() -> windows_core::Result<Self> {
        Self::IMicaBackdropFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IMicaBackdropFactory<R, F: FnOnce(&IMicaBackdropFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<MicaBackdrop, IMicaBackdropFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for MicaBackdrop {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IMicaBackdrop>();
}
unsafe impl windows_core::Interface for MicaBackdrop {
    type Vtable = <IMicaBackdrop as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IMicaBackdrop as windows_core::Interface>::IID;
}
impl core::ops::Deref for MicaBackdrop {
    type Target = IMicaBackdrop;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for MicaBackdrop {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.MicaBackdrop";
}
unsafe impl Send for MicaBackdrop {}
unsafe impl Sync for MicaBackdrop {}
pub const NIF_ICON: i32 = 2;
pub const NIF_MESSAGE: i32 = 1;
pub const NIF_SHOWTIP: i32 = 128;
pub const NIF_TIP: i32 = 4;
pub const NIM_ADD: i32 = 0;
pub const NIM_DELETE: i32 = 2;
pub const NIM_MODIFY: i32 = 1;
pub const NIM_SETVERSION: i32 = 4;
pub const NIN_KEYSELECT: i32 = 1025;
pub const NIN_SELECT: i32 = 1024;
#[repr(C, packed(1))]
#[cfg(target_arch = "x86")]
#[derive(Clone, Copy)]
pub struct NOTIFYICONDATAW {
    pub cbSize: u32,
    pub hWnd: HWND,
    pub uID: u32,
    pub uFlags: u32,
    pub uCallbackMessage: u32,
    pub hIcon: HICON,
    pub szTip: [u16; 128],
    pub dwState: u32,
    pub dwStateMask: u32,
    pub szInfo: [u16; 256],
    pub Anonymous: NOTIFYICONDATAW_0,
    pub szInfoTitle: [u16; 64],
    pub dwInfoFlags: u32,
    pub guidItem: windows_core::GUID,
    pub hBalloonIcon: HICON,
}
#[cfg(target_arch = "x86")]
impl Default for NOTIFYICONDATAW {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C, packed(1))]
#[cfg(target_arch = "x86")]
#[derive(Clone, Copy)]
pub union NOTIFYICONDATAW_0 {
    pub uTimeout: u32,
    pub uVersion: u32,
}
#[cfg(target_arch = "x86")]
impl Default for NOTIFYICONDATAW_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "x86_64"
))]
#[derive(Clone, Copy)]
pub struct NOTIFYICONDATAW {
    pub cbSize: u32,
    pub hWnd: HWND,
    pub uID: u32,
    pub uFlags: u32,
    pub uCallbackMessage: u32,
    pub hIcon: HICON,
    pub szTip: [u16; 128],
    pub dwState: u32,
    pub dwStateMask: u32,
    pub szInfo: [u16; 256],
    pub Anonymous: NOTIFYICONDATAW_0,
    pub szInfoTitle: [u16; 64],
    pub dwInfoFlags: u32,
    pub guidItem: windows_core::GUID,
    pub hBalloonIcon: HICON,
}
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "x86_64"
))]
impl Default for NOTIFYICONDATAW {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "x86_64"
))]
#[derive(Clone, Copy)]
pub union NOTIFYICONDATAW_0 {
    pub uTimeout: u32,
    pub uVersion: u32,
}
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "x86_64"
))]
impl Default for NOTIFYICONDATAW_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const NOTIFYICON_VERSION_4: i32 = 4;
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NavigationView(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    NavigationView,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    NavigationView,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl NavigationView {
    pub fn new() -> windows_core::Result<Self> {
        Self::INavigationViewFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn INavigationViewFactory<R, F: FnOnce(&INavigationViewFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<NavigationView, INavigationViewFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for NavigationView {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, INavigationView>();
}
unsafe impl windows_core::Interface for NavigationView {
    type Vtable = <INavigationView as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <INavigationView as windows_core::Interface>::IID;
}
impl core::ops::Deref for NavigationView {
    type Target = INavigationView;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for NavigationView {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.NavigationView";
}
unsafe impl Send for NavigationView {}
unsafe impl Sync for NavigationView {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NavigationViewBackButtonVisible(pub i32);
impl NavigationViewBackButtonVisible {
    pub const Collapsed: Self = Self(0);
}
impl windows_core::imp::TypeKind for NavigationViewBackButtonVisible {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for NavigationViewBackButtonVisible {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.Controls.NavigationViewBackButtonVisible;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NavigationViewItem(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    NavigationViewItem,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    NavigationViewItem,
    NavigationViewItemBase,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl NavigationViewItem {
    pub fn new() -> windows_core::Result<Self> {
        Self::INavigationViewItemFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn INavigationViewItemFactory<
        R,
        F: FnOnce(&INavigationViewItemFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            NavigationViewItem,
            INavigationViewItemFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for NavigationViewItem {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, INavigationViewItem>();
}
unsafe impl windows_core::Interface for NavigationViewItem {
    type Vtable = <INavigationViewItem as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <INavigationViewItem as windows_core::Interface>::IID;
}
impl core::ops::Deref for NavigationViewItem {
    type Target = INavigationViewItem;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for NavigationViewItem {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.NavigationViewItem";
}
unsafe impl Send for NavigationViewItem {}
unsafe impl Sync for NavigationViewItem {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NavigationViewItemBase(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    NavigationViewItemBase,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    NavigationViewItemBase,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for NavigationViewItemBase {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, INavigationViewItemBase>();
}
unsafe impl windows_core::Interface for NavigationViewItemBase {
    type Vtable = <INavigationViewItemBase as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <INavigationViewItemBase as windows_core::Interface>::IID;
}
impl core::ops::Deref for NavigationViewItemBase {
    type Target = INavigationViewItemBase;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for NavigationViewItemBase {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.NavigationViewItemBase";
}
unsafe impl Send for NavigationViewItemBase {}
unsafe impl Sync for NavigationViewItemBase {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NavigationViewPaneDisplayMode(pub i32);
impl NavigationViewPaneDisplayMode {
    pub const Left: Self = Self(1);
}
impl windows_core::imp::TypeKind for NavigationViewPaneDisplayMode {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for NavigationViewPaneDisplayMode {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.Controls.NavigationViewPaneDisplayMode;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NavigationViewSelectionChangedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    NavigationViewSelectionChangedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for NavigationViewSelectionChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::for_class::<
        Self,
        INavigationViewSelectionChangedEventArgs,
    >();
}
unsafe impl windows_core::Interface for NavigationViewSelectionChangedEventArgs {
    type Vtable = <INavigationViewSelectionChangedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <INavigationViewSelectionChangedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for NavigationViewSelectionChangedEventArgs {
    type Target = INavigationViewSelectionChangedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for NavigationViewSelectionChangedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.NavigationViewSelectionChangedEventArgs";
}
unsafe impl Send for NavigationViewSelectionChangedEventArgs {}
unsafe impl Sync for NavigationViewSelectionChangedEventArgs {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NonClientRegionKind(pub i32);
impl NonClientRegionKind {
    pub const Icon: Self = Self(3);
    pub const Passthrough: Self = Self(9);
}
impl windows_core::imp::TypeKind for NonClientRegionKind {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for NonClientRegionKind {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Input.NonClientRegionKind;i4)",
    );
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OVERLAPPED {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Anonymous: OVERLAPPED_0,
    pub hEvent: HANDLE,
}
impl Default for OVERLAPPED {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union OVERLAPPED_0 {
    pub Anonymous: OVERLAPPED_0_0,
    pub Pointer: *mut core::ffi::c_void,
}
impl Default for OVERLAPPED_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OVERLAPPED_0_0 {
    pub Offset: u32,
    pub OffsetHigh: u32,
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Orientation(pub i32);
impl Orientation {
    pub const Vertical: Self = Self(0);
    pub const Horizontal: Self = Self(1);
}
impl windows_core::imp::TypeKind for Orientation {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for Orientation {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.Controls.Orientation;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OverlappedPresenterState(pub i32);
impl OverlappedPresenterState {
    pub const Maximized: Self = Self(0);
    pub const Minimized: Self = Self(1);
    pub const Restored: Self = Self(2);
}
impl windows_core::imp::TypeKind for OverlappedPresenterState {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for OverlappedPresenterState {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Windowing.OverlappedPresenterState;i4)",
    );
}
pub const PIPE_ACCESS_DUPLEX: i32 = 3;
pub const PIPE_READMODE_BYTE: i32 = 0;
pub const PIPE_REJECT_REMOTE_CLIENTS: i32 = 8;
pub const PIPE_TYPE_BYTE: i32 = 0;
pub const PIPE_UNLIMITED_INSTANCES: i32 = 255;
pub const PIPE_WAIT: i32 = 0;
pub const PM_REMOVE: i32 = 1;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct POINT {
    pub x: i32,
    pub y: i32,
}
pub type PSECURITY_DESCRIPTOR = *mut core::ffi::c_void;
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Panel(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Panel, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Panel, FrameworkElement, UIElement, DependencyObject);
impl windows_core::RuntimeType for Panel {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IPanel>();
}
unsafe impl windows_core::Interface for Panel {
    type Vtable = <IPanel as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IPanel as windows_core::Interface>::IID;
}
impl core::ops::Deref for Panel {
    type Target = IPanel;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Panel {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Panel";
}
unsafe impl Send for Panel {}
unsafe impl Sync for Panel {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Path(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Path, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Path, Shape, FrameworkElement, UIElement, DependencyObject);
impl Path {
    pub fn new() -> windows_core::Result<Self> {
        Self::IPathFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IPathFactory<R, F: FnOnce(&IPathFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Path, IPathFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Path {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IPath>();
}
unsafe impl windows_core::Interface for Path {
    type Vtable = <IPath as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IPath as windows_core::Interface>::IID;
}
impl core::ops::Deref for Path {
    type Target = IPath;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Path {
    const NAME: &'static str = "Microsoft.UI.Xaml.Shapes.Path";
}
unsafe impl Send for Path {}
unsafe impl Sync for Path {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PenLineCap(pub i32);
impl PenLineCap {
    pub const Round: Self = Self(2);
}
impl windows_core::imp::TypeKind for PenLineCap {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for PenLineCap {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.Media.PenLineCap;i4)");
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PenLineJoin(pub i32);
impl PenLineJoin {
    pub const Round: Self = Self(2);
}
impl windows_core::imp::TypeKind for PenLineJoin {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for PenLineJoin {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.Media.PenLineJoin;i4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PickFileResult(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    PickFileResult,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for PickFileResult {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IPickFileResult>();
}
unsafe impl windows_core::Interface for PickFileResult {
    type Vtable = <IPickFileResult as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IPickFileResult as windows_core::Interface>::IID;
}
impl core::ops::Deref for PickFileResult {
    type Target = IPickFileResult;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for PickFileResult {
    const NAME: &'static str = "Microsoft.Windows.Storage.Pickers.PickFileResult";
}
unsafe impl Send for PickFileResult {}
unsafe impl Sync for PickFileResult {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}
impl windows_core::imp::TypeKind for Point {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for Point {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"struct(Windows.Foundation.Point;f4;f4)");
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PointInt32 {
    pub x: i32,
    pub y: i32,
}
impl windows_core::imp::TypeKind for PointInt32 {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for PointInt32 {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"struct(Windows.Graphics.PointInt32;i4;i4)");
}
windows_core::imp::define_interface!(
    PointerEventHandler,
    PointerEventHandler_Vtbl,
    0xa48a71e1_8bb4_5597_9e31_903a3f6a04fb
);
impl windows_core::RuntimeType for PointerEventHandler {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct PointerEventHandler_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
struct PointerEventHandlerBox<
    F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<PointerRoutedEventArgs>)
        + 'static,
>(core::marker::PhantomData<(fn() -> F,)>);
impl<
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<PointerRoutedEventArgs>,
            ) + 'static,
    > PointerEventHandlerBox<F>
{
    const VTABLE: PointerEventHandler_Vtbl = PointerEventHandler_Vtbl {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface:
                windows_core::imp::DelegateBox::<PointerEventHandler, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<PointerEventHandler, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<PointerEventHandler, F>::Release,
        },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<PointerEventHandler, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&e),
            );
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointerRoutedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    PointerRoutedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(PointerRoutedEventArgs, RoutedEventArgs);
impl windows_core::RuntimeType for PointerRoutedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IPointerRoutedEventArgs>();
}
unsafe impl windows_core::Interface for PointerRoutedEventArgs {
    type Vtable = <IPointerRoutedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IPointerRoutedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for PointerRoutedEventArgs {
    type Target = IPointerRoutedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for PointerRoutedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Input.PointerRoutedEventArgs";
}
unsafe impl Send for PointerRoutedEventArgs {}
unsafe impl Sync for PointerRoutedEventArgs {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressRing(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ProgressRing,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ProgressRing,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl ProgressRing {
    pub fn new() -> windows_core::Result<Self> {
        Self::IProgressRingFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IProgressRingFactory<R, F: FnOnce(&IProgressRingFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<ProgressRing, IProgressRingFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for ProgressRing {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IProgressRing>();
}
unsafe impl windows_core::Interface for ProgressRing {
    type Vtable = <IProgressRing as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IProgressRing as windows_core::Interface>::IID;
}
impl core::ops::Deref for ProgressRing {
    type Target = IProgressRing;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ProgressRing {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ProgressRing";
}
unsafe impl Send for ProgressRing {}
unsafe impl Sync for ProgressRing {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PropertyType(pub i32);
impl PropertyType {
    pub const Empty: Self = Self(0);
    pub const UInt8: Self = Self(1);
    pub const Int16: Self = Self(2);
    pub const UInt16: Self = Self(3);
    pub const Int32: Self = Self(4);
    pub const UInt32: Self = Self(5);
    pub const Int64: Self = Self(6);
    pub const UInt64: Self = Self(7);
    pub const Single: Self = Self(8);
    pub const Double: Self = Self(9);
    pub const Char16: Self = Self(10);
    pub const Boolean: Self = Self(11);
    pub const String: Self = Self(12);
    pub const Inspectable: Self = Self(13);
    pub const DateTime: Self = Self(14);
    pub const TimeSpan: Self = Self(15);
    pub const Guid: Self = Self(16);
    pub const Point: Self = Self(17);
    pub const Size: Self = Self(18);
    pub const Rect: Self = Self(19);
    pub const OtherType: Self = Self(20);
    pub const UInt8Array: Self = Self(1025);
    pub const Int16Array: Self = Self(1026);
    pub const UInt16Array: Self = Self(1027);
    pub const Int32Array: Self = Self(1028);
    pub const UInt32Array: Self = Self(1029);
    pub const Int64Array: Self = Self(1030);
    pub const UInt64Array: Self = Self(1031);
    pub const SingleArray: Self = Self(1032);
    pub const DoubleArray: Self = Self(1033);
    pub const Char16Array: Self = Self(1034);
    pub const BooleanArray: Self = Self(1035);
    pub const StringArray: Self = Self(1036);
    pub const InspectableArray: Self = Self(1037);
    pub const DateTimeArray: Self = Self(1038);
    pub const TimeSpanArray: Self = Self(1039);
    pub const GuidArray: Self = Self(1040);
    pub const PointArray: Self = Self(1041);
    pub const SizeArray: Self = Self(1042);
    pub const RectArray: Self = Self(1043);
    pub const OtherTypeArray: Self = Self(1044);
}
impl windows_core::imp::TypeKind for PropertyType {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for PropertyType {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Windows.Foundation.PropertyType;i4)");
}
pub struct PropertyValue;
impl PropertyValue {
    pub fn CreateString(value: &str) -> windows_core::Result<windows_core::IInspectable> {
        Self::IPropertyValueStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateString)(
                windows_core::Interface::as_raw(this),
                core::mem::transmute_copy(&windows_core::HSTRING::from(value)),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IPropertyValueStatics<R, F: FnOnce(&IPropertyValueStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<PropertyValue, IPropertyValueStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeName for PropertyValue {
    const NAME: &'static str = "Windows.Foundation.PropertyValue";
}
pub const QS_ALLINPUT: i32 = 7423;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RECT {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RadioButton(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    RadioButton,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    RadioButton,
    ToggleButton,
    ButtonBase,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl RadioButton {
    pub fn new() -> windows_core::Result<Self> {
        Self::IRadioButtonFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IRadioButtonFactory<R, F: FnOnce(&IRadioButtonFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<RadioButton, IRadioButtonFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for RadioButton {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IRadioButton>();
}
unsafe impl windows_core::Interface for RadioButton {
    type Vtable = <IRadioButton as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IRadioButton as windows_core::Interface>::IID;
}
impl core::ops::Deref for RadioButton {
    type Target = IRadioButton;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for RadioButton {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.RadioButton";
}
unsafe impl Send for RadioButton {}
unsafe impl Sync for RadioButton {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}
impl windows_core::imp::TypeKind for Rect {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for Rect {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"struct(Windows.Foundation.Rect;f4;f4;f4;f4)");
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RectInt32 {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}
impl windows_core::imp::TypeKind for RectInt32 {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for RectInt32 {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"struct(Windows.Graphics.RectInt32;i4;i4;i4;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RectangleGeometry(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    RectangleGeometry,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(RectangleGeometry, Geometry, DependencyObject);
impl RectangleGeometry {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            RectangleGeometry,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for RectangleGeometry {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IRectangleGeometry>();
}
unsafe impl windows_core::Interface for RectangleGeometry {
    type Vtable = <IRectangleGeometry as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IRectangleGeometry as windows_core::Interface>::IID;
}
impl core::ops::Deref for RectangleGeometry {
    type Target = IRectangleGeometry;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for RectangleGeometry {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.RectangleGeometry";
}
unsafe impl Send for RectangleGeometry {}
unsafe impl Sync for RectangleGeometry {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderTargetBitmap(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    RenderTargetBitmap,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(RenderTargetBitmap, ImageSource, DependencyObject);
impl RenderTargetBitmap {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            RenderTargetBitmap,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for RenderTargetBitmap {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IRenderTargetBitmap>();
}
unsafe impl windows_core::Interface for RenderTargetBitmap {
    type Vtable = <IRenderTargetBitmap as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IRenderTargetBitmap as windows_core::Interface>::IID;
}
impl core::ops::Deref for RenderTargetBitmap {
    type Target = IRenderTargetBitmap;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for RenderTargetBitmap {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.Imaging.RenderTargetBitmap";
}
unsafe impl Send for RenderTargetBitmap {}
unsafe impl Sync for RenderTargetBitmap {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceDictionary(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ResourceDictionary,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(ResourceDictionary, DependencyObject);
impl windows_core::RuntimeType for ResourceDictionary {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IResourceDictionary>();
}
unsafe impl windows_core::Interface for ResourceDictionary {
    type Vtable = <IResourceDictionary as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IResourceDictionary as windows_core::Interface>::IID;
}
impl core::ops::Deref for ResourceDictionary {
    type Target = IResourceDictionary;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ResourceDictionary {
    const NAME: &'static str = "Microsoft.UI.Xaml.ResourceDictionary";
}
unsafe impl Send for ResourceDictionary {}
unsafe impl Sync for ResourceDictionary {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    RoutedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for RoutedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IRoutedEventArgs>();
}
unsafe impl windows_core::Interface for RoutedEventArgs {
    type Vtable = <IRoutedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IRoutedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for RoutedEventArgs {
    type Target = IRoutedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for RoutedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.RoutedEventArgs";
}
unsafe impl Send for RoutedEventArgs {}
unsafe impl Sync for RoutedEventArgs {}
windows_core::imp::define_interface!(
    RoutedEventHandler,
    RoutedEventHandler_Vtbl,
    0xdae23d85_69ca_5bdf_805b_6161a3a215cc
);
impl windows_core::RuntimeType for RoutedEventHandler {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct RoutedEventHandler_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
struct RoutedEventHandlerBox<
    F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<RoutedEventArgs>) + 'static,
>(core::marker::PhantomData<(fn() -> F,)>);
impl<
        F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<RoutedEventArgs>)
            + 'static,
    > RoutedEventHandlerBox<F>
{
    const VTABLE: RoutedEventHandler_Vtbl = RoutedEventHandler_Vtbl {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface: windows_core::imp::DelegateBox::<RoutedEventHandler, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<RoutedEventHandler, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<RoutedEventHandler, F>::Release,
        },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<RoutedEventHandler, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&e),
            );
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowDefinition(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    RowDefinition,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(RowDefinition, DependencyObject);
impl RowDefinition {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            RowDefinition,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for RowDefinition {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IRowDefinition>();
}
unsafe impl windows_core::Interface for RowDefinition {
    type Vtable = <IRowDefinition as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IRowDefinition as windows_core::Interface>::IID;
}
impl core::ops::Deref for RowDefinition {
    type Target = IRowDefinition;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for RowDefinition {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.RowDefinition";
}
unsafe impl Send for RowDefinition {}
unsafe impl Sync for RowDefinition {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowDefinitionCollection(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    RowDefinitionCollection,
    windows_core::IUnknown,
    windows_core::IInspectable,
    windows_collections::IVector<RowDefinition>
);
impl windows_core::RuntimeType for RowDefinitionCollection {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::for_class::<
        Self,
        windows_collections::IVector<RowDefinition>,
    >();
}
unsafe impl windows_core::Interface for RowDefinitionCollection {
    type Vtable = <windows_collections::IVector<RowDefinition> as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <windows_collections::IVector<RowDefinition> as windows_core::Interface>::IID;
}
impl core::ops::Deref for RowDefinitionCollection {
    type Target = windows_collections::IVector<RowDefinition>;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for RowDefinitionCollection {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.RowDefinitionCollection";
}
unsafe impl Send for RowDefinitionCollection {}
unsafe impl Sync for RowDefinitionCollection {}
pub const SDDL_REVISION_1: i32 = 1;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: *mut core::ffi::c_void,
    pub bInheritHandle: windows_core::BOOL,
}
pub const SM_CXICON: i32 = 11;
pub const SM_CXSCREEN: i32 = 0;
pub const SM_CXSMICON: i32 = 49;
pub const SM_CYICON: i32 = 12;
pub const SM_CYSMICON: i32 = 50;
pub const SW_HIDE: i32 = 0;
pub const SW_RESTORE: i32 = 9;
pub const SW_SHOW: i32 = 5;
pub const SW_SHOWMAXIMIZED: i32 = 3;
pub const SW_SHOWMINIMIZED: i32 = 2;
pub const SW_SHOWNORMAL: i32 = 1;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScrollBarVisibility(pub i32);
impl ScrollBarVisibility {
    pub const Disabled: Self = Self(0);
    pub const Auto: Self = Self(1);
    pub const Hidden: Self = Self(2);
}
impl windows_core::imp::TypeKind for ScrollBarVisibility {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for ScrollBarVisibility {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.Controls.ScrollBarVisibility;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScrollMode(pub i32);
impl ScrollMode {
    pub const Disabled: Self = Self(0);
    pub const Enabled: Self = Self(1);
}
impl windows_core::imp::TypeKind for ScrollMode {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for ScrollMode {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.Controls.ScrollMode;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScrollViewer(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ScrollViewer,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ScrollViewer,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl ScrollViewer {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            ScrollViewer,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
    pub fn SetHorizontalScrollBarVisibility<P0>(
        element: P0,
        horizontalscrollbarvisibility: ScrollBarVisibility,
    ) -> windows_core::Result<()>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::IScrollViewerStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetHorizontalScrollBarVisibility)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                horizontalscrollbarvisibility,
            )
            .ok()
        })
    }
    pub fn SetVerticalScrollBarVisibility<P0>(
        element: P0,
        verticalscrollbarvisibility: ScrollBarVisibility,
    ) -> windows_core::Result<()>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::IScrollViewerStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetVerticalScrollBarVisibility)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                verticalscrollbarvisibility,
            )
            .ok()
        })
    }
    pub fn SetHorizontalScrollMode<P0>(
        element: P0,
        horizontalscrollmode: ScrollMode,
    ) -> windows_core::Result<()>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::IScrollViewerStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetHorizontalScrollMode)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                horizontalscrollmode,
            )
            .ok()
        })
    }
    fn IScrollViewerStatics<R, F: FnOnce(&IScrollViewerStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<ScrollViewer, IScrollViewerStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for ScrollViewer {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IScrollViewer>();
}
unsafe impl windows_core::Interface for ScrollViewer {
    type Vtable = <IScrollViewer as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IScrollViewer as windows_core::Interface>::IID;
}
impl core::ops::Deref for ScrollViewer {
    type Target = IScrollViewer;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ScrollViewer {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ScrollViewer";
}
unsafe impl Send for ScrollViewer {}
unsafe impl Sync for ScrollViewer {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionChangedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    SelectionChangedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(SelectionChangedEventArgs, RoutedEventArgs);
impl windows_core::RuntimeType for SelectionChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ISelectionChangedEventArgs>();
}
unsafe impl windows_core::Interface for SelectionChangedEventArgs {
    type Vtable = <ISelectionChangedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ISelectionChangedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for SelectionChangedEventArgs {
    type Target = ISelectionChangedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for SelectionChangedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.SelectionChangedEventArgs";
}
unsafe impl Send for SelectionChangedEventArgs {}
unsafe impl Sync for SelectionChangedEventArgs {}
windows_core::imp::define_interface!(
    SelectionChangedEventHandler,
    SelectionChangedEventHandler_Vtbl,
    0xa232390d_0e34_595e_8931_fa928a9909f4
);
impl windows_core::RuntimeType for SelectionChangedEventHandler {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct SelectionChangedEventHandler_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
struct SelectionChangedEventHandlerBox<
    F: Fn(
            windows_core::Ref<windows_core::IInspectable>,
            windows_core::Ref<SelectionChangedEventArgs>,
        ) + 'static,
>(core::marker::PhantomData<(fn() -> F,)>);
impl<
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<SelectionChangedEventArgs>,
            ) + 'static,
    > SelectionChangedEventHandlerBox<F>
{
    const VTABLE: SelectionChangedEventHandler_Vtbl = SelectionChangedEventHandler_Vtbl {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface:
                windows_core::imp::DelegateBox::<SelectionChangedEventHandler, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<SelectionChangedEventHandler, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<SelectionChangedEventHandler, F>::Release,
        },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<SelectionChangedEventHandler, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&e),
            );
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selector(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    Selector,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    Selector,
    ItemsControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for Selector {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ISelector>();
}
unsafe impl windows_core::Interface for Selector {
    type Vtable = <ISelector as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ISelector as windows_core::Interface>::IID;
}
impl core::ops::Deref for Selector {
    type Target = ISelector;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Selector {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Primitives.Selector";
}
unsafe impl Send for Selector {}
unsafe impl Sync for Selector {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectorBar(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    SelectorBar,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    SelectorBar,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl SelectorBar {
    pub fn new() -> windows_core::Result<Self> {
        Self::ISelectorBarFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn ISelectorBarFactory<R, F: FnOnce(&ISelectorBarFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<SelectorBar, ISelectorBarFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for SelectorBar {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ISelectorBar>();
}
unsafe impl windows_core::Interface for SelectorBar {
    type Vtable = <ISelectorBar as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ISelectorBar as windows_core::Interface>::IID;
}
impl core::ops::Deref for SelectorBar {
    type Target = ISelectorBar;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for SelectorBar {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.SelectorBar";
}
unsafe impl Send for SelectorBar {}
unsafe impl Sync for SelectorBar {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectorBarItem(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    SelectorBarItem,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    SelectorBarItem,
    ItemContainer,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl SelectorBarItem {
    pub fn new() -> windows_core::Result<Self> {
        Self::ISelectorBarItemFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn ISelectorBarItemFactory<
        R,
        F: FnOnce(&ISelectorBarItemFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<SelectorBarItem, ISelectorBarItemFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for SelectorBarItem {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ISelectorBarItem>();
}
unsafe impl windows_core::Interface for SelectorBarItem {
    type Vtable = <ISelectorBarItem as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ISelectorBarItem as windows_core::Interface>::IID;
}
impl core::ops::Deref for SelectorBarItem {
    type Target = ISelectorBarItem;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for SelectorBarItem {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.SelectorBarItem";
}
unsafe impl Send for SelectorBarItem {}
unsafe impl Sync for SelectorBarItem {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectorBarSelectionChangedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    SelectorBarSelectionChangedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for SelectorBarSelectionChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ISelectorBarSelectionChangedEventArgs>();
}
unsafe impl windows_core::Interface for SelectorBarSelectionChangedEventArgs {
    type Vtable = <ISelectorBarSelectionChangedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <ISelectorBarSelectionChangedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for SelectorBarSelectionChangedEventArgs {
    type Target = ISelectorBarSelectionChangedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for SelectorBarSelectionChangedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.SelectorBarSelectionChangedEventArgs";
}
unsafe impl Send for SelectorBarSelectionChangedEventArgs {}
unsafe impl Sync for SelectorBarSelectionChangedEventArgs {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectorItem(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    SelectorItem,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    SelectorItem,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl windows_core::RuntimeType for SelectorItem {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ISelectorItem>();
}
unsafe impl windows_core::Interface for SelectorItem {
    type Vtable = <ISelectorItem as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ISelectorItem as windows_core::Interface>::IID;
}
impl core::ops::Deref for SelectorItem {
    type Target = ISelectorItem;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for SelectorItem {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Primitives.SelectorItem";
}
unsafe impl Send for SelectorItem {}
unsafe impl Sync for SelectorItem {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shadow(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Shadow, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Shadow, DependencyObject);
impl windows_core::RuntimeType for Shadow {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IShadow>();
}
unsafe impl windows_core::Interface for Shadow {
    type Vtable = <IShadow as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IShadow as windows_core::Interface>::IID;
}
impl core::ops::Deref for Shadow {
    type Target = IShadow;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Shadow {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.Shadow";
}
unsafe impl Send for Shadow {}
unsafe impl Sync for Shadow {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shape(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Shape, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Shape, FrameworkElement, UIElement, DependencyObject);
impl windows_core::RuntimeType for Shape {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IShape>();
}
unsafe impl windows_core::Interface for Shape {
    type Vtable = <IShape as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IShape as windows_core::Interface>::IID;
}
impl core::ops::Deref for Shape {
    type Target = IShape;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Shape {
    const NAME: &'static str = "Microsoft.UI.Xaml.Shapes.Shape";
}
unsafe impl Send for Shape {}
unsafe impl Sync for Shape {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Size {
    pub width: f32,
    pub height: f32,
}
impl windows_core::imp::TypeKind for Size {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for Size {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"struct(Windows.Foundation.Size;f4;f4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SizeChangedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    SizeChangedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(SizeChangedEventArgs, RoutedEventArgs);
impl windows_core::RuntimeType for SizeChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ISizeChangedEventArgs>();
}
unsafe impl windows_core::Interface for SizeChangedEventArgs {
    type Vtable = <ISizeChangedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ISizeChangedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for SizeChangedEventArgs {
    type Target = ISizeChangedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for SizeChangedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.SizeChangedEventArgs";
}
unsafe impl Send for SizeChangedEventArgs {}
unsafe impl Sync for SizeChangedEventArgs {}
windows_core::imp::define_interface!(
    SizeChangedEventHandler,
    SizeChangedEventHandler_Vtbl,
    0x8d7b1a58_14c6_51c9_892c_9fcce368e77d
);
impl windows_core::RuntimeType for SizeChangedEventHandler {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct SizeChangedEventHandler_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
struct SizeChangedEventHandlerBox<
    F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<SizeChangedEventArgs>)
        + 'static,
>(core::marker::PhantomData<(fn() -> F,)>);
impl<
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<SizeChangedEventArgs>,
            ) + 'static,
    > SizeChangedEventHandlerBox<F>
{
    const VTABLE: SizeChangedEventHandler_Vtbl = SizeChangedEventHandler_Vtbl {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface:
                windows_core::imp::DelegateBox::<SizeChangedEventHandler, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<SizeChangedEventHandler, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<SizeChangedEventHandler, F>::Release,
        },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<SizeChangedEventHandler, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&e),
            );
            windows_core::HRESULT(0)
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SizeInt32 {
    pub width: i32,
    pub height: i32,
}
impl windows_core::imp::TypeKind for SizeInt32 {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for SizeInt32 {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"struct(Windows.Graphics.SizeInt32;i4;i4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolidColorBrush(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    SolidColorBrush,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(SolidColorBrush, Brush, DependencyObject);
impl SolidColorBrush {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            SolidColorBrush,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for SolidColorBrush {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ISolidColorBrush>();
}
unsafe impl windows_core::Interface for SolidColorBrush {
    type Vtable = <ISolidColorBrush as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ISolidColorBrush as windows_core::Interface>::IID;
}
impl core::ops::Deref for SolidColorBrush {
    type Target = ISolidColorBrush;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for SolidColorBrush {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.SolidColorBrush";
}
unsafe impl Send for SolidColorBrush {}
unsafe impl Sync for SolidColorBrush {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackPanel(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    StackPanel,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    StackPanel,
    Panel,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl StackPanel {
    pub fn new() -> windows_core::Result<Self> {
        Self::IStackPanelFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IStackPanelFactory<R, F: FnOnce(&IStackPanelFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<StackPanel, IStackPanelFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for StackPanel {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IStackPanel>();
}
unsafe impl windows_core::Interface for StackPanel {
    type Vtable = <IStackPanel as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IStackPanel as windows_core::Interface>::IID;
}
impl core::ops::Deref for StackPanel {
    type Target = IStackPanel;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for StackPanel {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.StackPanel";
}
unsafe impl Send for StackPanel {}
unsafe impl Sync for StackPanel {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Style(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Style, windows_core::IUnknown, windows_core::IInspectable);
windows_core::imp::required_hierarchy!(Style, DependencyObject);
impl windows_core::RuntimeType for Style {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IStyle>();
}
unsafe impl windows_core::Interface for Style {
    type Vtable = <IStyle as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IStyle as windows_core::Interface>::IID;
}
impl core::ops::Deref for Style {
    type Target = IStyle;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Style {
    const NAME: &'static str = "Microsoft.UI.Xaml.Style";
}
unsafe impl Send for Style {}
unsafe impl Sync for Style {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemBackdrop(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    SystemBackdrop,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(SystemBackdrop, DependencyObject);
impl windows_core::RuntimeType for SystemBackdrop {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ISystemBackdrop>();
}
unsafe impl windows_core::Interface for SystemBackdrop {
    type Vtable = <ISystemBackdrop as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ISystemBackdrop as windows_core::Interface>::IID;
}
impl core::ops::Deref for SystemBackdrop {
    type Target = ISystemBackdrop;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for SystemBackdrop {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.SystemBackdrop";
}
unsafe impl Send for SystemBackdrop {}
unsafe impl Sync for SystemBackdrop {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TPMPARAMS {
    pub cbSize: u32,
    pub rcExclude: RECT,
}
pub const TPM_BOTTOMALIGN: i32 = 32;
pub const TPM_LEFTALIGN: i32 = 0;
pub const TPM_RETURNCMD: i32 = 256;
pub const TPM_RIGHTALIGN: i32 = 8;
pub const TPM_RIGHTBUTTON: i32 = 2;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TextAlignment(pub i32);
impl TextAlignment {
    pub const Center: Self = Self(0);
    pub const Left: Self = Self(1);
    pub const Right: Self = Self(2);
}
impl windows_core::imp::TypeKind for TextAlignment {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for TextAlignment {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.TextAlignment;i4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextBlock(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    TextBlock,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(TextBlock, FrameworkElement, UIElement, DependencyObject);
impl TextBlock {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            TextBlock,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for TextBlock {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ITextBlock>();
}
unsafe impl windows_core::Interface for TextBlock {
    type Vtable = <ITextBlock as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ITextBlock as windows_core::Interface>::IID;
}
impl core::ops::Deref for TextBlock {
    type Target = ITextBlock;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for TextBlock {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.TextBlock";
}
unsafe impl Send for TextBlock {}
unsafe impl Sync for TextBlock {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextBox(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    TextBox,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    TextBox,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl TextBox {
    pub fn new() -> windows_core::Result<Self> {
        Self::ITextBoxFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn ITextBoxFactory<R, F: FnOnce(&ITextBoxFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<TextBox, ITextBoxFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for TextBox {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ITextBox>();
}
unsafe impl windows_core::Interface for TextBox {
    type Vtable = <ITextBox as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ITextBox as windows_core::Interface>::IID;
}
impl core::ops::Deref for TextBox {
    type Target = ITextBox;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for TextBox {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.TextBox";
}
unsafe impl Send for TextBox {}
unsafe impl Sync for TextBox {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextChangedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    TextChangedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(TextChangedEventArgs, RoutedEventArgs);
impl windows_core::RuntimeType for TextChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ITextChangedEventArgs>();
}
unsafe impl windows_core::Interface for TextChangedEventArgs {
    type Vtable = <ITextChangedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ITextChangedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for TextChangedEventArgs {
    type Target = ITextChangedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for TextChangedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.TextChangedEventArgs";
}
unsafe impl Send for TextChangedEventArgs {}
unsafe impl Sync for TextChangedEventArgs {}
windows_core::imp::define_interface!(
    TextChangedEventHandler,
    TextChangedEventHandler_Vtbl,
    0x5d8ddcff_45d8_5e7c_9b8b_c41d2893c6a1
);
impl windows_core::RuntimeType for TextChangedEventHandler {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_interface::<Self>();
}
#[repr(C)]
pub struct TextChangedEventHandler_Vtbl {
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT,
}
struct TextChangedEventHandlerBox<
    F: Fn(windows_core::Ref<windows_core::IInspectable>, windows_core::Ref<TextChangedEventArgs>)
        + 'static,
>(core::marker::PhantomData<(fn() -> F,)>);
impl<
        F: Fn(
                windows_core::Ref<windows_core::IInspectable>,
                windows_core::Ref<TextChangedEventArgs>,
            ) + 'static,
    > TextChangedEventHandlerBox<F>
{
    const VTABLE: TextChangedEventHandler_Vtbl = TextChangedEventHandler_Vtbl {
        base__: windows_core::IUnknown_Vtbl {
            QueryInterface:
                windows_core::imp::DelegateBox::<TextChangedEventHandler, F>::QueryInterface,
            AddRef: windows_core::imp::DelegateBox::<TextChangedEventHandler, F>::AddRef,
            Release: windows_core::imp::DelegateBox::<TextChangedEventHandler, F>::Release,
        },
        Invoke: Self::Invoke,
    };
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: *mut core::ffi::c_void,
        e: *mut core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<TextChangedEventHandler, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&e),
            );
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TextTrimming(pub i32);
impl TextTrimming {
    pub const None: Self = Self(0);
    pub const CharacterEllipsis: Self = Self(1);
}
impl windows_core::imp::TypeKind for TextTrimming {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for TextTrimming {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.TextTrimming;i4)");
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TextWrapping(pub i32);
impl TextWrapping {
    pub const NoWrap: Self = Self(1);
    pub const Wrap: Self = Self(2);
}
impl windows_core::imp::TypeKind for TextWrapping {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for TextWrapping {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.TextWrapping;i4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThemeShadow(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ThemeShadow,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(ThemeShadow, Shadow, DependencyObject);
impl windows_core::RuntimeType for ThemeShadow {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IThemeShadow>();
}
unsafe impl windows_core::Interface for ThemeShadow {
    type Vtable = <IThemeShadow as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IThemeShadow as windows_core::Interface>::IID;
}
impl core::ops::Deref for ThemeShadow {
    type Target = IThemeShadow;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ThemeShadow {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.ThemeShadow";
}
unsafe impl Send for ThemeShadow {}
unsafe impl Sync for ThemeShadow {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Thickness {
    pub left: f64,
    pub top: f64,
    pub right: f64,
    pub bottom: f64,
}
impl windows_core::imp::TypeKind for Thickness {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for Thickness {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"struct(Microsoft.UI.Xaml.Thickness;f8;f8;f8;f8)",
    );
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TitleBarHeightOption(pub i32);
impl TitleBarHeightOption {
    pub const Standard: Self = Self(0);
    pub const Tall: Self = Self(1);
}
impl windows_core::imp::TypeKind for TitleBarHeightOption {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for TitleBarHeightOption {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Windowing.TitleBarHeightOption;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TitleBarTheme(pub i32);
impl TitleBarTheme {
    pub const UseDefaultAppMode: Self = Self(1);
    pub const Light: Self = Self(2);
    pub const Dark: Self = Self(3);
}
impl windows_core::imp::TypeKind for TitleBarTheme {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for TitleBarTheme {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Windowing.TitleBarTheme;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToggleButton(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ToggleButton,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ToggleButton,
    ButtonBase,
    ContentControl,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl ToggleButton {
    pub fn new() -> windows_core::Result<Self> {
        Self::IToggleButtonFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IToggleButtonFactory<R, F: FnOnce(&IToggleButtonFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<ToggleButton, IToggleButtonFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for ToggleButton {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IToggleButton>();
}
unsafe impl windows_core::Interface for ToggleButton {
    type Vtable = <IToggleButton as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IToggleButton as windows_core::Interface>::IID;
}
impl core::ops::Deref for ToggleButton {
    type Target = IToggleButton;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ToggleButton {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.Primitives.ToggleButton";
}
unsafe impl Send for ToggleButton {}
unsafe impl Sync for ToggleButton {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToggleSwitch(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ToggleSwitch,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(
    ToggleSwitch,
    Control,
    FrameworkElement,
    UIElement,
    DependencyObject
);
impl ToggleSwitch {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            ToggleSwitch,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for ToggleSwitch {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IToggleSwitch>();
}
unsafe impl windows_core::Interface for ToggleSwitch {
    type Vtable = <IToggleSwitch as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IToggleSwitch as windows_core::Interface>::IID;
}
impl core::ops::Deref for ToggleSwitch {
    type Target = IToggleSwitch;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ToggleSwitch {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ToggleSwitch";
}
unsafe impl Send for ToggleSwitch {}
unsafe impl Sync for ToggleSwitch {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolTipService(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    ToolTipService,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl ToolTipService {
    pub fn GetToolTip<P0>(element: P0) -> windows_core::Result<windows_core::IInspectable>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::IToolTipServiceStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).GetToolTip)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    pub fn SetToolTip<P0, P1>(element: P0, value: P1) -> windows_core::Result<()>
    where
        P0: windows_core::Param<DependencyObject>,
        P1: windows_core::Param<windows_core::IInspectable>,
    {
        Self::IToolTipServiceStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetToolTip)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                value.param().abi(),
            )
            .ok()
        })
    }
    fn IToolTipServiceStatics<R, F: FnOnce(&IToolTipServiceStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<ToolTipService, IToolTipServiceStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for ToolTipService {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IToolTipService>();
}
unsafe impl windows_core::Interface for ToolTipService {
    type Vtable = <IToolTipService as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IToolTipService as windows_core::Interface>::IID;
}
impl core::ops::Deref for ToolTipService {
    type Target = IToolTipService;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for ToolTipService {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.ToolTipService";
}
unsafe impl Send for ToolTipService {}
unsafe impl Sync for ToolTipService {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TypeKind(pub i32);
impl TypeKind {
    pub const Metadata: Self = Self(1);
}
impl windows_core::imp::TypeKind for TypeKind {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for TypeKind {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Windows.UI.Xaml.Interop.TypeKind;i4)");
}
#[repr(C)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TypeName {
    pub name: windows_core::HSTRING,
    pub kind: TypeKind,
}
impl windows_core::imp::TypeKind for TypeName {
    type TypeKind = windows_core::imp::CloneType;
}
impl windows_core::RuntimeType for TypeName {
    const SIGNATURE : windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice (b"struct(Windows.UI.Xaml.Interop.TypeName;string;enum(Windows.UI.Xaml.Interop.TypeKind;i4))") ;
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedEventHandler<TSender, TResult>(
    windows_core::IUnknown,
    core::marker::PhantomData<TSender>,
    core::marker::PhantomData<TResult>,
)
where
    TSender: windows_core::RuntimeType + 'static,
    TResult: windows_core::RuntimeType + 'static;
unsafe impl<
        TSender: windows_core::RuntimeType + 'static,
        TResult: windows_core::RuntimeType + 'static,
    > windows_core::Interface for TypedEventHandler<TSender, TResult>
{
    type Vtable = TypedEventHandler_Vtbl<TSender, TResult>;
    const IID: windows_core::GUID =
        windows_core::GUID::from_signature(<Self as windows_core::RuntimeType>::SIGNATURE);
}
impl<
        TSender: windows_core::RuntimeType + 'static,
        TResult: windows_core::RuntimeType + 'static,
    > windows_core::RuntimeType for TypedEventHandler<TSender, TResult>
{
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::new()
        .push_slice(b"pinterface({9de1c534-6ae1-11e0-84e1-18a905bcc53f}")
        .push_slice(b";")
        .push_other(TSender::SIGNATURE)
        .push_slice(b";")
        .push_other(TResult::SIGNATURE)
        .push_slice(b")");
}
impl<
        TSender: windows_core::RuntimeType + 'static,
        TResult: windows_core::RuntimeType + 'static,
    > TypedEventHandler<TSender, TResult>
{
    pub fn new<F: Fn(windows_core::Ref<TSender>, windows_core::Ref<TResult>) + 'static>(
        invoke: F,
    ) -> Self {
        let com = windows_core::imp::DelegateBox::<Self, F>::new(
            &TypedEventHandlerBox::<TSender, TResult, F>::VTABLE,
            invoke,
        );
        unsafe { core::mem::transmute(windows_core::imp::box_new(com)) }
    }
}
#[repr(C)]
pub struct TypedEventHandler_Vtbl<TSender, TResult>
where
    TSender: windows_core::RuntimeType + 'static,
    TResult: windows_core::RuntimeType + 'static,
{
    base__: windows_core::IUnknown_Vtbl,
    Invoke: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        sender: windows_core::imp::AbiType<TSender>,
        args: windows_core::imp::AbiType<TResult>,
    ) -> windows_core::HRESULT,
    TSender: core::marker::PhantomData<TSender>,
    TResult: core::marker::PhantomData<TResult>,
}
struct TypedEventHandlerBox<
    TSender,
    TResult,
    F: Fn(windows_core::Ref<TSender>, windows_core::Ref<TResult>) + 'static,
>(core::marker::PhantomData<(TSender, TResult, fn() -> F)>)
where
    TSender: windows_core::RuntimeType + 'static,
    TResult: windows_core::RuntimeType + 'static;
impl<
        TSender: windows_core::RuntimeType + 'static,
        TResult: windows_core::RuntimeType + 'static,
        F: Fn(windows_core::Ref<TSender>, windows_core::Ref<TResult>) + 'static,
    > TypedEventHandlerBox<TSender, TResult, F>
{
    const VTABLE : TypedEventHandler_Vtbl < TSender , TResult , > = TypedEventHandler_Vtbl::< TSender , TResult , > { base__ : windows_core::IUnknown_Vtbl { QueryInterface : windows_core::imp::DelegateBox::< TypedEventHandler < TSender , TResult > , F >::QueryInterface , AddRef : windows_core::imp::DelegateBox::< TypedEventHandler < TSender , TResult > , F >::AddRef , Release : windows_core::imp::DelegateBox::< TypedEventHandler < TSender , TResult > , F >::Release , } , Invoke : Self::Invoke , TSender : core::marker::PhantomData::< TSender > , TResult : core::marker::PhantomData::< TResult > } ;
    unsafe extern "system" fn Invoke(
        this: *mut core::ffi::c_void,
        sender: windows_core::imp::AbiType<TSender>,
        args: windows_core::imp::AbiType<TResult>,
    ) -> windows_core::HRESULT {
        unsafe {
            let this = &mut *(this as *mut *mut core::ffi::c_void
                as *mut windows_core::imp::DelegateBox<TypedEventHandler<TSender, TResult>, F>);
            (this.invoke)(
                core::mem::transmute_copy(&sender),
                core::mem::transmute_copy(&args),
            );
            windows_core::HRESULT(0)
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Typography(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    Typography,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl Typography {
    pub fn SetNumeralAlignment<P0>(
        element: P0,
        value: FontNumeralAlignment,
    ) -> windows_core::Result<()>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::ITypographyStatics(|this| unsafe {
            (windows_core::Interface::vtable(this).SetNumeralAlignment)(
                windows_core::Interface::as_raw(this),
                element.param().abi(),
                value,
            )
            .ok()
        })
    }
    fn ITypographyStatics<R, F: FnOnce(&ITypographyStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Typography, ITypographyStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Typography {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, ITypography>();
}
unsafe impl windows_core::Interface for Typography {
    type Vtable = <ITypography as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <ITypography as windows_core::Interface>::IID;
}
impl core::ops::Deref for Typography {
    type Target = ITypography;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Typography {
    const NAME: &'static str = "Microsoft.UI.Xaml.Documents.Typography";
}
unsafe impl Send for Typography {}
unsafe impl Sync for Typography {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UIElement(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    UIElement,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(UIElement, DependencyObject);
impl windows_core::RuntimeType for UIElement {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IUIElement>();
}
unsafe impl windows_core::Interface for UIElement {
    type Vtable = <IUIElement as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IUIElement as windows_core::Interface>::IID;
}
impl core::ops::Deref for UIElement {
    type Target = IUIElement;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for UIElement {
    const NAME: &'static str = "Microsoft.UI.Xaml.UIElement";
}
unsafe impl Send for UIElement {}
unsafe impl Sync for UIElement {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UIElementCollection(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    UIElementCollection,
    windows_core::IUnknown,
    windows_core::IInspectable,
    windows_collections::IVector<UIElement>
);
impl windows_core::RuntimeType for UIElementCollection {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, windows_collections::IVector<UIElement>>(
        );
}
unsafe impl windows_core::Interface for UIElementCollection {
    type Vtable = <windows_collections::IVector<UIElement> as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <windows_collections::IVector<UIElement> as windows_core::Interface>::IID;
}
impl core::ops::Deref for UIElementCollection {
    type Target = windows_collections::IVector<UIElement>;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for UIElementCollection {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.UIElementCollection";
}
unsafe impl Send for UIElementCollection {}
unsafe impl Sync for UIElementCollection {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UIElementWeakCollection(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    UIElementWeakCollection,
    windows_core::IUnknown,
    windows_core::IInspectable,
    windows_collections::IVector<UIElement>
);
impl windows_core::RuntimeType for UIElementWeakCollection {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, windows_collections::IVector<UIElement>>(
        );
}
unsafe impl windows_core::Interface for UIElementWeakCollection {
    type Vtable = <windows_collections::IVector<UIElement> as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID =
        <windows_collections::IVector<UIElement> as windows_core::Interface>::IID;
}
impl core::ops::Deref for UIElementWeakCollection {
    type Target = windows_collections::IVector<UIElement>;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for UIElementWeakCollection {
    const NAME: &'static str = "Microsoft.UI.Xaml.UIElementWeakCollection";
}
unsafe impl Send for UIElementWeakCollection {}
unsafe impl Sync for UIElementWeakCollection {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Vector3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}
impl windows_core::imp::TypeKind for Vector3 {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for Vector3 {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"struct(Windows.Foundation.Numerics.Vector3;f4;f4;f4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerticalAlignment(pub i32);
impl VerticalAlignment {
    pub const Top: Self = Self(0);
    pub const Center: Self = Self(1);
    pub const Bottom: Self = Self(2);
    pub const Stretch: Self = Self(3);
}
impl windows_core::imp::TypeKind for VerticalAlignment {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for VerticalAlignment {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.VerticalAlignment;i4)");
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtualKey(pub i32);
impl VirtualKey {
    pub const Enter: Self = Self(13);
    pub const Escape: Self = Self(27);
    pub const S: Self = Self(83);
}
impl windows_core::imp::TypeKind for VirtualKey {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for VirtualKey {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Windows.System.VirtualKey;i4)");
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtualKeyModifiers(pub u32);
impl VirtualKeyModifiers {
    pub const None: Self = Self(0);
    pub const Control: Self = Self(1);
}
impl windows_core::imp::TypeKind for VirtualKeyModifiers {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for VirtualKeyModifiers {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Windows.System.VirtualKeyModifiers;u4)");
}
impl VirtualKeyModifiers {
    pub const fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}
impl core::ops::BitOr for VirtualKeyModifiers {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl core::ops::BitAnd for VirtualKeyModifiers {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}
impl core::ops::BitOrAssign for VirtualKeyModifiers {
    fn bitor_assign(&mut self, other: Self) {
        self.0.bitor_assign(other.0);
    }
}
impl core::ops::BitAndAssign for VirtualKeyModifiers {
    fn bitand_assign(&mut self, other: Self) {
        self.0.bitand_assign(other.0);
    }
}
impl core::ops::Not for VirtualKeyModifiers {
    type Output = Self;
    fn not(self) -> Self {
        Self(self.0.not())
    }
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Visibility(pub i32);
impl Visibility {
    pub const Visible: Self = Self(0);
    pub const Collapsed: Self = Self(1);
}
impl windows_core::imp::TypeKind for Visibility {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for Visibility {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"enum(Microsoft.UI.Xaml.Visibility;i4)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisualTreeHelper(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    VisualTreeHelper,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl VisualTreeHelper {
    pub fn GetChild<P0>(reference: P0, childindex: i32) -> windows_core::Result<DependencyObject>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::IVisualTreeHelperStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).GetChild)(
                windows_core::Interface::as_raw(this),
                reference.param().abi(),
                childindex,
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    pub fn GetChildrenCount<P0>(reference: P0) -> windows_core::Result<i32>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::IVisualTreeHelperStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).GetChildrenCount)(
                windows_core::Interface::as_raw(this),
                reference.param().abi(),
                &mut result__,
            )
            .map(|| result__)
        })
    }
    pub fn GetParent<P0>(reference: P0) -> windows_core::Result<DependencyObject>
    where
        P0: windows_core::Param<DependencyObject>,
    {
        Self::IVisualTreeHelperStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).GetParent)(
                windows_core::Interface::as_raw(this),
                reference.param().abi(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IVisualTreeHelperStatics<
        R,
        F: FnOnce(&IVisualTreeHelperStatics) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<VisualTreeHelper, IVisualTreeHelperStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for VisualTreeHelper {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IVisualTreeHelper>();
}
unsafe impl windows_core::Interface for VisualTreeHelper {
    type Vtable = <IVisualTreeHelper as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IVisualTreeHelper as windows_core::Interface>::IID;
}
impl core::ops::Deref for VisualTreeHelper {
    type Target = IVisualTreeHelper;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for VisualTreeHelper {
    const NAME: &'static str = "Microsoft.UI.Xaml.Media.VisualTreeHelper";
}
unsafe impl Send for VisualTreeHelper {}
unsafe impl Sync for VisualTreeHelper {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WINDOWPLACEMENT {
    pub length: u32,
    pub flags: u32,
    pub showCmd: u32,
    pub ptMinPosition: POINT,
    pub ptMaxPosition: POINT,
    pub rcNormalPosition: RECT,
}
pub const WM_CONTEXTMENU: i32 = 123;
pub const WM_ENDSESSION: i32 = 22;
pub const WM_LBUTTONUP: i32 = 514;
pub const WM_NULL: i32 = 0;
pub const WM_QUERYENDSESSION: i32 = 17;
pub const WM_RBUTTONUP: i32 = 517;
pub const WM_SETICON: i32 = 128;
pub const WM_USER: i32 = 1024;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct WNDCLASSEXW {
    pub cbSize: u32,
    pub style: u32,
    pub lpfnWndProc: WNDPROC,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: HINSTANCE,
    pub hIcon: HICON,
    pub hCursor: HCURSOR,
    pub hbrBackground: HBRUSH,
    pub lpszMenuName: windows_core::PCWSTR,
    pub lpszClassName: windows_core::PCWSTR,
    pub hIconSm: HICON,
}
pub type WNDPROC = Option<
    unsafe extern "system" fn(param0: HWND, param1: u32, param2: WPARAM, param3: LPARAM) -> LRESULT,
>;
pub type WPARAM = usize;
pub const WPF_RESTORETOMAXIMIZED: i32 = 2;
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Window(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(Window, windows_core::IUnknown, windows_core::IInspectable);
impl Window {
    pub fn new() -> windows_core::Result<Self> {
        Self::IWindowFactory(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).CreateInstance)(
                windows_core::Interface::as_raw(this),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IWindowFactory<R, F: FnOnce(&IWindowFactory) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<Window, IWindowFactory> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for Window {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IWindow>();
}
unsafe impl windows_core::Interface for Window {
    type Vtable = <IWindow as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IWindow as windows_core::Interface>::IID;
}
impl core::ops::Deref for Window {
    type Target = IWindow;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for Window {
    const NAME: &'static str = "Microsoft.UI.Xaml.Window";
}
unsafe impl Send for Window {}
unsafe impl Sync for Window {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowActivatedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    WindowActivatedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for WindowActivatedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IWindowActivatedEventArgs>();
}
unsafe impl windows_core::Interface for WindowActivatedEventArgs {
    type Vtable = <IWindowActivatedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IWindowActivatedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for WindowActivatedEventArgs {
    type Target = IWindowActivatedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for WindowActivatedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.WindowActivatedEventArgs";
}
unsafe impl Send for WindowActivatedEventArgs {}
unsafe impl Sync for WindowActivatedEventArgs {}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowActivationState(pub i32);
impl WindowActivationState {
    pub const Deactivated: Self = Self(1);
}
impl windows_core::imp::TypeKind for WindowActivationState {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for WindowActivationState {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"enum(Microsoft.UI.Xaml.WindowActivationState;i4)",
    );
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    WindowEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for WindowEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IWindowEventArgs>();
}
unsafe impl windows_core::Interface for WindowEventArgs {
    type Vtable = <IWindowEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IWindowEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for WindowEventArgs {
    type Target = IWindowEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for WindowEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.WindowEventArgs";
}
unsafe impl Send for WindowEventArgs {}
unsafe impl Sync for WindowEventArgs {}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowId {
    pub value: u64,
}
impl windows_core::imp::TypeKind for WindowId {
    type TypeKind = windows_core::imp::CopyType;
}
impl windows_core::RuntimeType for WindowId {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::from_slice(b"struct(Microsoft.UI.WindowId;u8)");
}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XamlBindingHelper(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    XamlBindingHelper,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl XamlBindingHelper {
    pub fn ConvertValue<P1>(
        r#type: &TypeName,
        value: P1,
    ) -> windows_core::Result<windows_core::IInspectable>
    where
        P1: windows_core::Param<windows_core::IInspectable>,
    {
        Self::IXamlBindingHelperStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).ConvertValue)(
                windows_core::Interface::as_raw(this),
                core::mem::transmute_copy(r#type),
                value.param().abi(),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IXamlBindingHelperStatics<
        R,
        F: FnOnce(&IXamlBindingHelperStatics) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            XamlBindingHelper,
            IXamlBindingHelperStatics,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for XamlBindingHelper {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IXamlBindingHelper>();
}
unsafe impl windows_core::Interface for XamlBindingHelper {
    type Vtable = <IXamlBindingHelper as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IXamlBindingHelper as windows_core::Interface>::IID;
}
impl core::ops::Deref for XamlBindingHelper {
    type Target = IXamlBindingHelper;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for XamlBindingHelper {
    const NAME: &'static str = "Microsoft.UI.Xaml.Markup.XamlBindingHelper";
}
unsafe impl Send for XamlBindingHelper {}
unsafe impl Sync for XamlBindingHelper {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XamlControlsResources(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    XamlControlsResources,
    windows_core::IUnknown,
    windows_core::IInspectable
);
windows_core::imp::required_hierarchy!(XamlControlsResources, ResourceDictionary, DependencyObject);
impl XamlControlsResources {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            XamlControlsResources,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for XamlControlsResources {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IXamlControlsResources>();
}
unsafe impl windows_core::Interface for XamlControlsResources {
    type Vtable = <IXamlControlsResources as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IXamlControlsResources as windows_core::Interface>::IID;
}
impl core::ops::Deref for XamlControlsResources {
    type Target = IXamlControlsResources;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for XamlControlsResources {
    const NAME: &'static str = "Microsoft.UI.Xaml.Controls.XamlControlsResources";
}
unsafe impl Send for XamlControlsResources {}
unsafe impl Sync for XamlControlsResources {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XamlControlsXamlMetaDataProvider(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    XamlControlsXamlMetaDataProvider,
    windows_core::IUnknown,
    windows_core::IInspectable,
    IXamlMetadataProvider
);
impl XamlControlsXamlMetaDataProvider {
    pub fn new() -> windows_core::Result<Self> {
        Self::IActivationFactory(|f| f.ActivateInstance::<Self>())
    }
    fn IActivationFactory<
        R,
        F: FnOnce(&windows_core::imp::IGenericFactory) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            XamlControlsXamlMetaDataProvider,
            windows_core::imp::IGenericFactory,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for XamlControlsXamlMetaDataProvider {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IXamlMetadataProvider>();
}
unsafe impl windows_core::Interface for XamlControlsXamlMetaDataProvider {
    type Vtable = <IXamlMetadataProvider as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IXamlMetadataProvider as windows_core::Interface>::IID;
}
impl core::ops::Deref for XamlControlsXamlMetaDataProvider {
    type Target = IXamlMetadataProvider;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for XamlControlsXamlMetaDataProvider {
    const NAME: &'static str = "Microsoft.UI.Xaml.XamlTypeInfo.XamlControlsXamlMetaDataProvider";
}
unsafe impl Send for XamlControlsXamlMetaDataProvider {}
unsafe impl Sync for XamlControlsXamlMetaDataProvider {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XamlReader(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    XamlReader,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl XamlReader {
    pub fn Load(xaml: &str) -> windows_core::Result<windows_core::IInspectable> {
        Self::IXamlReaderStatics(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (windows_core::Interface::vtable(this).Load)(
                windows_core::Interface::as_raw(this),
                core::mem::transmute_copy(&windows_core::HSTRING::from(xaml)),
                &mut result__,
            )
            .and_then(|| windows_core::imp::Type::from_abi(result__))
        })
    }
    fn IXamlReaderStatics<R, F: FnOnce(&IXamlReaderStatics) -> windows_core::Result<R>>(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<XamlReader, IXamlReaderStatics> =
            windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
}
impl windows_core::RuntimeType for XamlReader {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IXamlReader>();
}
unsafe impl windows_core::Interface for XamlReader {
    type Vtable = <IXamlReader as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IXamlReader as windows_core::Interface>::IID;
}
impl core::ops::Deref for XamlReader {
    type Target = IXamlReader;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for XamlReader {
    const NAME: &'static str = "Microsoft.UI.Xaml.Markup.XamlReader";
}
unsafe impl Send for XamlReader {}
unsafe impl Sync for XamlReader {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XamlRoot(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    XamlRoot,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for XamlRoot {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IXamlRoot>();
}
unsafe impl windows_core::Interface for XamlRoot {
    type Vtable = <IXamlRoot as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IXamlRoot as windows_core::Interface>::IID;
}
impl core::ops::Deref for XamlRoot {
    type Target = IXamlRoot;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for XamlRoot {
    const NAME: &'static str = "Microsoft.UI.Xaml.XamlRoot";
}
unsafe impl Send for XamlRoot {}
unsafe impl Sync for XamlRoot {}
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XamlRootChangedEventArgs(windows_core::IUnknown);
windows_core::imp::interface_hierarchy!(
    XamlRootChangedEventArgs,
    windows_core::IUnknown,
    windows_core::IInspectable
);
impl windows_core::RuntimeType for XamlRootChangedEventArgs {
    const SIGNATURE: windows_core::imp::ConstBuffer =
        windows_core::imp::ConstBuffer::for_class::<Self, IXamlRootChangedEventArgs>();
}
unsafe impl windows_core::Interface for XamlRootChangedEventArgs {
    type Vtable = <IXamlRootChangedEventArgs as windows_core::Interface>::Vtable;
    const IID: windows_core::GUID = <IXamlRootChangedEventArgs as windows_core::Interface>::IID;
}
impl core::ops::Deref for XamlRootChangedEventArgs {
    type Target = IXamlRootChangedEventArgs;
    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}
impl windows_core::RuntimeName for XamlRootChangedEventArgs {
    const NAME: &'static str = "Microsoft.UI.Xaml.XamlRootChangedEventArgs";
}
unsafe impl Send for XamlRootChangedEventArgs {}
unsafe impl Sync for XamlRootChangedEventArgs {}
#[repr(C)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct XmlnsDefinition {
    pub xml_namespace: windows_core::HSTRING,
    pub namespace: windows_core::HSTRING,
}
impl windows_core::imp::TypeKind for XmlnsDefinition {
    type TypeKind = windows_core::imp::CloneType;
}
impl windows_core::RuntimeType for XmlnsDefinition {
    const SIGNATURE: windows_core::imp::ConstBuffer = windows_core::imp::ConstBuffer::from_slice(
        b"struct(Microsoft.UI.Xaml.Markup.XmlnsDefinition;string;string)",
    );
}
