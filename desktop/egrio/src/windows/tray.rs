//! The notification area icon and the tray's menu. The icon belongs to a
//! hidden top-level window that receives its messages ("Notifications and
//! the Notification Area", `NOTIFYICON_VERSION_4`): a click shows the main
//! window, the context menu key or a right click opens the menu. The menu is
//! a system popup menu built from the latest tray view each time it opens
//! (`TrackPopupMenuEx` with `TPM_RETURNCMD`), so changes never touch an open
//! menu. A member's latency sits in the menu's accelerator column, after a
//! tab. Choosing a group's latency test closes the menu like any other item;
//! its results are there the next time the menu opens. When Explorer
//! restarts, the `TaskbarCreated` message has the icon added again. When
//! the session ends (sign-out, restart, shutdown), the window's
//! `WM_ENDSESSION` quits as the tray's Quit does and waits, pumping the
//! thread's messages, until the quit's cleanup has restored the network
//! settings or a few seconds have passed: the process may end at any time
//! after the message returns ("Shutting Down", `WM_ENDSESSION`). The quit
//! then ends the process from inside that wait (`session_ending`), as
//! ending the WinUI application there would wait on the very message loop
//! the wait runs in.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use windows_core::{Result, PCWSTR};

use egrio_ui::backend::{TrayAction, TrayGroup, TrayItem, TrayMember, TrayView, UiEvent};

use super::bindings::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GetModuleHandleW, GetSystemMetrics, MsgWaitForMultipleObjects, PeekMessageW,
    PostMessageW, RegisterClassExW, RegisterWindowMessageW, SetForegroundWindow, SetMenuItemInfoW,
    Shell_NotifyIconW, TrackPopupMenuEx, TranslateMessage, HMENU, HWND, LPARAM, LRESULT,
    MENUITEMINFOW, MFT_RADIOCHECK, MF_CHECKED, MF_GRAYED, MF_POPUP, MF_SEPARATOR, MF_STRING,
    MIIM_FTYPE, MSG, NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NIM_SETVERSION, NIN_KEYSELECT, NIN_SELECT, NOTIFYICONDATAW, NOTIFYICONDATAW_0,
    NOTIFYICON_VERSION_4, PM_REMOVE, POINT, QS_ALLINPUT, SM_CXSCREEN, TPM_BOTTOMALIGN,
    TPM_LEFTALIGN, TPM_RETURNCMD, TPM_RIGHTALIGN, TPM_RIGHTBUTTON, WM_CONTEXTMENU, WM_ENDSESSION,
    WM_NULL, WM_USER, WNDCLASSEXW, WPARAM,
};
use super::hwnd::AppIcon;
use super::widgets::Post;

const CLASS: &str = "EgrioTray";
const CALLBACK_MESSAGE: u32 = WM_USER as u32 + 1;
const ICON_ID: u32 = 1;
/// How long an ending session waits for the quit's cleanup, within the
/// time Windows gives an app before it lists it as blocking.
const SESSION_END_WAIT: Duration = Duration::from_secs(4);

struct State {
    hwnd: HWND,
    view: TrayView,
    post: Post,
    taskbar_created: u32,
    /// The icon while traffic goes through Egrio, and while none does.
    icon: Option<AppIcon>,
    icon_off: Option<AppIcon>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static SESSION_ENDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The session is ending, and the quit runs inside the window's wait.
pub fn session_ending() -> bool {
    SESSION_ENDING.with(std::cell::Cell::get)
}

pub struct Tray;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The tooltip as the notification area takes it: at most 127 UTF-16 units.
fn tip(text: &str) -> [u16; 128] {
    let mut tip = [0u16; 128];
    for (slot, unit) in tip.iter_mut().take(127).zip(text.encode_utf16()) {
        *slot = unit;
    }
    tip
}

fn icon_data(state: &State) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: state.hwnd,
        uID: ICON_ID,
        uFlags: (NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP) as u32,
        uCallbackMessage: CALLBACK_MESSAGE,
        hIcon: if state.view.connected {
            &state.icon
        } else {
            &state.icon_off
        }
        .as_ref()
        .map_or(std::ptr::null_mut(), AppIcon::raw),
        szTip: tip(&state.view.tooltip),
        ..Default::default()
    }
}

fn add_icon(state: &State) {
    let data = icon_data(state);
    let version = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: state.hwnd,
        uID: ICON_ID,
        Anonymous: NOTIFYICONDATAW_0 {
            uVersion: NOTIFYICON_VERSION_4 as u32,
        },
        ..Default::default()
    };
    // SAFETY: filled structures of the documented size.
    unsafe {
        if !Shell_NotifyIconW(NIM_ADD as u32, &data).as_bool()
            || !Shell_NotifyIconW(NIM_SETVERSION as u32, &version).as_bool()
        {
            log::warn!(
                "add the notification area icon: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// The tray's menu as the interface last described it, and whom its items
/// report to, for the test control channel.
#[cfg(feature = "test-control")]
pub(super) fn menu() -> Option<(TrayView, Post)> {
    STATE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|state| (state.view.clone(), state.post))
    })
}

impl Tray {
    pub fn new(view: &TrayView, post: Post) -> Result<Self> {
        let class = wide(CLASS);
        // SAFETY: the class and window name outlive the calls; the window
        // procedure is a plain function.
        let hwnd = unsafe {
            let instance = GetModuleHandleW(PCWSTR::null());
            let description = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(window_proc),
                hInstance: instance,
                lpszClassName: PCWSTR(class.as_ptr()),
                ..std::mem::zeroed()
            };
            RegisterClassExW(&description);
            // A hidden top-level window: message-only windows do not get
            // the broadcast `TaskbarCreated`.
            CreateWindowExW(
                0,
                PCWSTR(class.as_ptr()),
                PCWSTR(class.as_ptr()),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            )
        };
        if hwnd.is_null() {
            return Err(windows_core::Error::from_thread());
        }
        let name = wide("TaskbarCreated");
        // SAFETY: a NUL-terminated name.
        let taskbar_created = unsafe { RegisterWindowMessageW(PCWSTR(name.as_ptr())) };
        let state = State {
            hwnd,
            view: view.clone(),
            post,
            taskbar_created,
            icon: AppIcon::tray(true),
            icon_off: AppIcon::tray(false),
        };
        add_icon(&state);
        STATE.with(|slot| *slot.borrow_mut() = Some(state));
        Ok(Self)
    }

    pub fn update(&self, view: &TrayView) {
        STATE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(state) = slot.as_mut() else { return };
            let changed =
                state.view.tooltip != view.tooltip || state.view.connected != view.connected;
            state.view = view.clone();
            if changed {
                let data = icon_data(state);
                // SAFETY: a filled structure of the documented size.
                unsafe {
                    let _ = Shell_NotifyIconW(NIM_MODIFY as u32, &data);
                }
            }
        });
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        if let Some(state) = STATE.with(|slot| slot.borrow_mut().take()) {
            let data = icon_data(&state);
            // SAFETY: the icon and window this added and created.
            unsafe {
                let _ = Shell_NotifyIconW(NIM_DELETE as u32, &data);
                let _ = DestroyWindow(state.hwnd);
            }
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let known = STATE.with(|slot| {
        slot.try_borrow().ok().and_then(|state| {
            state
                .as_ref()
                .map(|state| (state.taskbar_created, state.post))
        })
    });
    if let Some((taskbar_created, post)) = known {
        if message == taskbar_created {
            STATE.with(|slot| {
                if let Some(state) = slot.borrow().as_ref() {
                    add_icon(state);
                }
            });
            return 0;
        }
        if message == CALLBACK_MESSAGE {
            // Version 4: the event in the low word of `lparam`.
            match (lparam as u32 & 0xffff) as i32 {
                NIN_SELECT | NIN_KEYSELECT => post(UiEvent::Tray(TrayAction::ShowMainWindow)),
                WM_CONTEXTMENU => show_menu(hwnd, icon_point(wparam), post),
                _ => {}
            }
            return 0;
        }
        // `wparam` is nonzero when the session really ends.
        if message == WM_ENDSESSION as u32 && wparam != 0 {
            end_session(post);
            return 0;
        }
    }
    // SAFETY: the arguments Windows passed in.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

/// Quits and keeps the thread's messages moving, which carry the quit
/// through the runtime, until its cleanup has finished or the wait is over.
fn end_session(post: Post) {
    log::info!("the session is ending; quitting");
    SESSION_ENDING.with(|ending| ending.set(true));
    post(UiEvent::QuitRequested);
    let deadline = Instant::now() + SESSION_END_WAIT;
    while !egrio_desktop::exit::is_ready_to_exit() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            log::warn!("the session ended before the quit's cleanup finished");
            return;
        }
        let mut message = MSG::default();
        // SAFETY: a message structure for this thread's queue.
        unsafe {
            while PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE as u32).as_bool()
            {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            MsgWaitForMultipleObjects(
                0,
                std::ptr::null(),
                false.into(),
                left.as_millis().min(50) as u32,
                QS_ALLINPUT as u32,
            );
        }
    }
}

/// Where the shell says the icon is, which version 4 of the notification
/// puts in the message's `wparam`: the keyboard opens the menu there too,
/// where the pointer may be anywhere else.
fn icon_point(wparam: usize) -> POINT {
    POINT {
        x: i32::from(wparam as u16 as i16),
        y: i32::from((wparam >> 16) as u16 as i16),
    }
}

/// What choosing an item does. A group's test and its members name theirs
/// when they are chosen: a menu of a subscription's groups has thousands of
/// members and one of them is chosen.
enum Chosen<'a> {
    Action(&'a TrayAction),
    Test(&'a TrayGroup),
    Member(&'a TrayGroup, &'a TrayMember),
}

impl Chosen<'_> {
    fn action(&self) -> TrayAction {
        match self {
            Self::Action(action) => (*action).clone(),
            Self::Test(group) => group.test(),
            Self::Member(group, member) => group.select(member),
        }
    }
}

/// Builds the menu from the latest view, tracks it at the icon and posts
/// the chosen item's action.
fn show_menu(hwnd: HWND, at: POINT, post: Post) {
    let Some(view) = STATE.with(|slot| slot.borrow().as_ref().map(|state| state.view.clone()))
    else {
        return;
    };
    let mut choices = Vec::new();
    // SAFETY: no arguments.
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return;
    }
    append_items(menu, &view.items, &mut choices);
    // SAFETY: the menu and window this owns. The window must be in the
    // foreground for the menu to close when the user clicks elsewhere, and
    // a message posted after the menu ends lets it close properly
    // (`TrackPopupMenu`'s remarks).
    let chosen = unsafe {
        let _ = SetForegroundWindow(hwnd);
        // An icon in the right half of the screen opens its menu leftwards,
        // where there is room for it, as the shell's own menus do.
        let align = if at.x > GetSystemMetrics(SM_CXSCREEN) / 2 {
            TPM_RIGHTALIGN
        } else {
            TPM_LEFTALIGN
        };
        let chosen = TrackPopupMenuEx(
            menu,
            (TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | align) as u32,
            at.x,
            at.y,
            hwnd,
            std::ptr::null(),
        );
        let _ = PostMessageW(hwnd, WM_NULL as u32, 0, 0);
        let _ = DestroyMenu(menu);
        chosen.0
    };
    // Item ids start at 1; 0 means the menu was dismissed.
    if let Some(choice) = usize::try_from(chosen)
        .ok()
        .and_then(|id| id.checked_sub(1))
        .and_then(|index| choices.get(index))
    {
        post(UiEvent::Tray(choice.action()));
    }
}

/// Appends an item of `flags` to `menu`: a separator without a text, else a
/// command whose id is `id`, or a submenu whose handle is.
fn append(menu: HMENU, flags: u32, id: usize, text: Option<&str>) {
    let text = text.map(wide);
    // SAFETY: a menu this owns and a NUL-terminated string or none.
    unsafe {
        let _ = AppendMenuW(
            menu,
            flags,
            id,
            text.as_ref()
                .map_or(PCWSTR::null(), |text| PCWSTR(text.as_ptr())),
        );
    }
}

/// The flags of a text item that may be checked and may be unavailable.
fn text_flags(enabled: bool, checked: bool) -> u32 {
    let mut flags = MF_STRING;
    if checked {
        flags |= MF_CHECKED;
    }
    if !enabled {
        flags |= MF_GRAYED;
    }
    flags as u32
}

/// The flags of a submenu's item.
fn popup_flags(enabled: bool) -> u32 {
    (if enabled {
        MF_POPUP
    } else {
        MF_POPUP | MF_GRAYED
    }) as u32
}

fn append_items<'a>(menu: HMENU, items: &'a [TrayItem], choices: &mut Vec<Chosen<'a>>) {
    for item in items {
        match item {
            TrayItem::Separator => append(menu, MF_SEPARATOR as u32, 0, None),
            TrayItem::Command {
                label,
                action,
                enabled,
                checked,
            } => {
                choices.push(Chosen::Action(action));
                append(
                    menu,
                    text_flags(*enabled, *checked),
                    choices.len(),
                    Some(&menu_text(label, None)),
                );
            }
            TrayItem::Submenu {
                label,
                enabled,
                items,
            } => {
                // SAFETY: no arguments; the parent menu destroys it.
                let submenu = unsafe { CreatePopupMenu() };
                append_items(submenu, items, choices);
                append(
                    menu,
                    popup_flags(*enabled),
                    submenu as usize,
                    Some(&menu_text(label, None)),
                );
            }
            TrayItem::Group(group) => {
                // SAFETY: no arguments; the parent menu destroys it.
                let submenu = unsafe { CreatePopupMenu() };
                append_group(submenu, group, choices);
                append(
                    menu,
                    popup_flags(group.enabled),
                    submenu as usize,
                    Some(&menu_text(&group.label, None)),
                );
            }
        }
    }
}

/// A group's submenu: its latency test, a separator and its members.
fn append_group<'a>(menu: HMENU, group: &'a TrayGroup, choices: &mut Vec<Chosen<'a>>) {
    choices.push(Chosen::Test(group));
    append(
        menu,
        text_flags(group.test_enabled, false),
        choices.len(),
        Some(&menu_text(group.test_label, None)),
    );
    append(menu, MF_SEPARATOR as u32, 0, None);
    for member in &group.members {
        choices.push(Chosen::Member(group, member));
        let id = choices.len();
        let latency = member.latency.map(|latency| latency.text());
        append(
            menu,
            text_flags(member.enabled, member.checked),
            id,
            Some(&menu_text(&member.label(), latency.as_deref())),
        );
        // A member of a group is one of a set: its mark is the radio one,
        // which a menu item takes only through its item info.
        let info = MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_FTYPE as u32,
            fType: MFT_RADIOCHECK as u32,
            ..Default::default()
        };
        // SAFETY: a menu this owns and a filled structure of the
        // documented size.
        unsafe {
            let _ = SetMenuItemInfoW(menu, id as u32, false.into(), &info);
        }
    }
}

/// A menu item's text: `&` shown as itself rather than marking a mnemonic,
/// and a latency after a tab, in the column menus align at the end.
fn menu_text(label: &str, latency: Option<&str>) -> String {
    let label = label.replace('&', "&&");
    match latency {
        Some(latency) => format!("{label}\t{latency}"),
        None => label,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use egrio_ui::backend::TrayLatency;

    use super::super::bindings::{
        GetMenuItemCount, GetMenuItemID, GetMenuItemInfoW, GetMenuStringW, GetSubMenu, MFS_CHECKED,
        MFS_GRAYED, MFT_SEPARATOR, MF_BYPOSITION, MIIM_STATE,
    };
    use super::*;

    /// What the item at `position` of `menu` is, as Windows holds it: its
    /// text, whether it is checked, whether it is unavailable, and its type.
    fn item(menu: HMENU, position: i32) -> (String, bool, bool, u32) {
        let mut text = [0u16; 128];
        let mut info = MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: (MIIM_STATE | MIIM_FTYPE) as u32,
            ..Default::default()
        };
        // SAFETY: a buffer of the length given, and a structure of the
        // documented size that asks for the state and the type.
        let length = unsafe {
            assert!(GetMenuItemInfoW(menu, position as u32, true.into(), &mut info).as_bool());
            GetMenuStringW(
                menu,
                position as u32,
                windows_core::PWSTR(text.as_mut_ptr()),
                text.len() as i32,
                MF_BYPOSITION as u32,
            )
        };
        (
            String::from_utf16_lossy(&text[..length as usize]),
            info.fState & MFS_CHECKED as u32 != 0,
            info.fState & MFS_GRAYED as u32 != 0,
            info.fType,
        )
    }

    #[test]
    fn a_groups_submenu_is_its_test_a_separator_and_its_members() {
        let member = |name: &str, enabled: bool, checked, latency| TrayMember {
            name: name.into(),
            badge: (!enabled).then_some("Unsupported"),
            enabled,
            checked,
            latency,
        };
        let group = Arc::new(TrayGroup {
            label: "Proxy · TW".into(),
            enabled: true,
            profile_id: "p".into(),
            group_id: "group-Proxy".into(),
            test_label: "Test Latency",
            test_enabled: false,
            members: vec![
                member("H&K", true, false, Some(TrayLatency::Ready(42))),
                member("TW", true, true, None),
                member("VMess", false, false, None),
            ],
        });
        let items = [
            TrayItem::Command {
                label: "Quit".into(),
                action: TrayAction::Quit,
                enabled: true,
                checked: false,
            },
            TrayItem::Separator,
            TrayItem::Group(group.clone()),
        ];
        let mut choices = Vec::new();
        // SAFETY: no arguments; the menu is destroyed below.
        let menu = unsafe { CreatePopupMenu() };
        assert!(!menu.is_null());
        append_items(menu, &items, &mut choices);

        // SAFETY: a menu this owns, read by position.
        let (count, submenu) = unsafe { (GetMenuItemCount(menu), GetSubMenu(menu, 2)) };
        assert_eq!(count, 3);
        assert_eq!(item(menu, 0), ("Quit".into(), false, false, 0));
        assert_eq!(item(menu, 1).3, MFT_SEPARATOR as u32);
        assert_eq!(item(menu, 2).0, "Proxy · TW");
        assert!(!submenu.is_null());

        // SAFETY: the group's submenu, which the menu owns.
        assert_eq!(unsafe { GetMenuItemCount(submenu) }, 5);
        // A test that runs cannot be chosen again.
        assert_eq!(item(submenu, 0), ("Test Latency".into(), false, true, 0));
        assert_eq!(item(submenu, 1).3, MFT_SEPARATOR as u32);
        // A member's mark is the radio one; its latency follows a tab.
        let radio = MFT_RADIOCHECK as u32;
        assert_eq!(
            item(submenu, 2),
            ("H&&K\t42 ms".into(), false, false, radio)
        );
        assert_eq!(item(submenu, 3), ("TW".into(), true, false, radio));
        assert_eq!(
            item(submenu, 4),
            ("VMess · Unsupported".into(), false, true, radio)
        );

        // An item's id names what choosing it does.
        // SAFETY: menus this owns, read by position.
        let chosen = |menu, position| unsafe { GetMenuItemID(menu, position) } as usize;
        assert_eq!(choices[chosen(menu, 0) - 1].action(), TrayAction::Quit);
        assert_eq!(choices[chosen(submenu, 0) - 1].action(), group.test());
        assert_eq!(
            choices[chosen(submenu, 3) - 1].action(),
            group.select(&group.members[1])
        );
        // SAFETY: the menu this created; its submenu goes with it.
        unsafe {
            let _ = DestroyMenu(menu);
        }
    }

    #[test]
    fn menu_text_escapes_mnemonics_and_puts_latency_after_a_tab() {
        assert_eq!(menu_text("R&D", None), "R&&D");
        assert_eq!(menu_text("HK", Some("42 ms")), "HK\t42 ms");
    }

    #[test]
    fn tooltip_is_cut_to_what_the_shell_takes() {
        let long = "x".repeat(200);
        let tip = tip(&long);
        assert_eq!(tip[126], u16::from(b'x'));
        assert_eq!(tip[127], 0);
    }
}
