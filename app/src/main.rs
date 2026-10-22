mod export;
mod import;
mod store;
mod totp;
mod uri;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use gtk::glib::{self, timeout_add_local, ControlFlow};
use gtk::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use store::{SavedAccount, Store, StorePath};
use uri::{Account, Kind};

const APP_ID: &str = "io.github.teejer.LinAuth";

/// Per-row state kept so the 1s tick can refresh code + countdown.
struct RowState {
    account: Account,
    code_label: gtk::Label,
    progress: Option<gtk::ProgressBar>,
    last_window: RefCell<u64>,
}

struct AppState {
    store: RefCell<Store>,
    password: RefCell<Option<String>>,
    rows: RefCell<Vec<(gtk::ListBoxRow, RowState)>>,
    list: gtk::ListBox,
    toast_overlay: adw::ToastOverlay,
    store_path: StorePath,
    search: gtk::SearchEntry,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// "123 456" for readability.
fn group_code(code: &str) -> String {
    let mid = code.len() / 2;
    if code.len() % 2 == 0 && mid > 0 {
        format!("{} {}", &code[..mid], &code[mid..])
    } else {
        code.to_string()
    }
}

fn code_for(a: &Account, now: u64) -> String {
    match a.kind {
        Kind::Totp => totp::totp(&a.secret, now, a.period, a.digits, a.algorithm),
        Kind::Hotp => totp::hotp(&a.secret, a.counter, a.digits, a.algorithm),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "codes") {
        std::process::exit(cli_codes());
    }
    if args.iter().any(|a| a == "--install-autostart") {
        std::process::exit(install_autostart());
    }
    if let Some(pos) = args.iter().position(|a| a == "import") {
        let path = args.get(pos + 1).cloned().unwrap_or_default();
        std::process::exit(cli_import(&path));
    }
    if let Some(pos) = args.iter().position(|a| a == "export") {
        let path = args.get(pos + 1).cloned().unwrap_or_default();
        std::process::exit(cli_export(&path));
    }

    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run();
}

// ---------------------------------------------------------------- headless

fn cli_codes() -> i32 {
    let store_path = StorePath::new();
    let password = std::env::var("WINAUTH_PWD").ok();
    let store = match store_path.load(password.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot load account store: {e}");
            return 1;
        }
    };
    let now = now_unix();
    for sa in &store.accounts {
        let a = &sa.account;
        let code = code_for(a, now);
        let suffix = match a.kind {
            Kind::Totp => format!("  ({}s left)", totp::seconds_remaining(now, a.period)),
            Kind::Hotp => String::new(),
        };
        println!("{:<52} {}{suffix}", a.display_name(), group_code(&code));
    }
    0
}

/// CLI: `linauth import <backup.zip|txt>` — zip password from
/// WINAUTH_ZIP_PWD env; store saved encrypted if WINAUTH_STORE_PWD is set.
fn cli_import(path: &str) -> i32 {
    if path.is_empty() {
        eprintln!("usage: linauth import <backup.zip|backup.txt>");
        return 2;
    }
    let zip_pw = std::env::var("WINAUTH_ZIP_PWD").ok();
    let res = match import::import_file(Path::new(path), zip_pw.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("import failed: {e}");
            return 1;
        }
    };
    let store_path = StorePath::new();
    let mut store = match store_path.load(std::env::var("WINAUTH_STORE_PWD").ok().as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot load existing store: {e}");
            return 1;
        }
    };
    let mut added = 0usize;
    let mut updated = 0usize;
    for acc in res.accounts {
        match store
            .accounts
            .iter_mut()
            .find(|sa| sa.account.secret == acc.secret && sa.account.label == acc.label)
        {
            Some(existing) => {
                existing.account = acc;
                updated += 1;
            }
            None => {
                store.accounts.push(SavedAccount { account: acc, pinned: false });
                added += 1;
            }
        }
    }
    let store_pw = std::env::var("WINAUTH_STORE_PWD").ok();
    if let Err(e) = store_path.save(&store, store_pw.as_deref()) {
        eprintln!("cannot save store: {e}");
        return 1;
    }
    println!("imported {added}, updated {updated}");
    for (line, e) in res.errors {
        eprintln!("skipped line {line}: {e}");
    }
    0
}

/// CLI: `linauth export <backup.zip|backup.txt>` — WinAuth-compatible output;
/// zip encryption password from WINAUTH_ZIP_PWD, store read with optional
/// WINAUTH_STORE_PWD.
fn cli_export(path: &str) -> i32 {
    if path.is_empty() {
        eprintln!("usage: linauth export <backup.zip|backup.txt>");
        eprintln!("       (zip export requires the password in $WINAUTH_ZIP_PWD)");
        return 2;
    }
    let store_path = StorePath::new();
    let store = match store_path.load(std::env::var("WINAUTH_STORE_PWD").ok().as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot load account store: {e}");
            return 1;
        }
    };
    let accounts: Vec<Account> = store.accounts.iter().map(|sa| sa.account.clone()).collect();
    if accounts.is_empty() {
        eprintln!("account store is empty, nothing to export");
        return 1;
    }
    let p = Path::new(path);
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let res = if ext == "zip" {
        let pw = std::env::var("WINAUTH_ZIP_PWD").ok().filter(|p| !p.is_empty());
        match pw {
            Some(pw) => export::write_zip(p, &accounts, Some(&pw)),
            None => {
                eprintln!("zip export needs a password: set WINAUTH_ZIP_PWD or export to .txt");
                return 2;
            }
        }
    } else {
        export::write_txt(p, &accounts)
    };
    match res {
        Ok(()) => {
            println!("exported {} account(s) to {}", accounts.len(), path);
            0
        }
        Err(e) => {
            eprintln!("export failed: {e}");
            1
        }
    }
}

fn install_autostart() -> i32 {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "linauth".into());
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"));
    let _ = std::fs::create_dir_all(dir.join("autostart"));
    let desktop = format!(
        "[Desktop Entry]\nType=Application\nName=LinAuth\nExec={exe}\nIcon=io.github.teejer.LinAuth\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    );
    let path = dir.join("autostart/linauth.desktop");
    match std::fs::write(&path, desktop) {
        Ok(()) => {
            eprintln!("wrote {}", path.display());
            0
        }
        Err(e) => {
            eprintln!("failed: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------- UI

fn build_ui(app: &adw::Application) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Codes")
        .default_width(460)
        .default_height(600)
        .build();

    let header = gtk::HeaderBar::new();
    header.set_title_widget(Some(&adw::WindowTitle::new("Codes", "")));
    let import_btn = gtk::Button::builder()
        .icon_name("document-open-symbolic")
        .tooltip_text("Import WinAuth backup (.zip or .txt)")
        .build();
    let add_btn = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Add otpauth:// URI")
        .build();
    let export_btn = gtk::Button::builder()
        .icon_name("document-save-symbolic")
        .tooltip_text("Export backup (.zip restores in WinAuth too)")
        .build();
    header.pack_end(&import_btn);
    header.pack_end(&add_btn);
    header.pack_end(&export_btn);

    let search = gtk::SearchEntry::builder()
        .placeholder_text("Search accounts")
        .margin_start(18)
        .margin_end(18)
        .margin_top(6)
        .build();

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .margin_top(12)
        .margin_bottom(12)
        .build();

    let clamp = adw::Clamp::builder()
        .maximum_size(520)
        .child(&list)
        .margin_start(18)
        .margin_end(18)
        .build();

    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .vexpand(true)
        .child(&clamp)
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.add_top_bar(&search);
    toolbar.set_content(Some(&scroller));

    let toast_overlay = adw::ToastOverlay::new();
    toast_overlay.set_child(Some(&toolbar));
    window.set_content(Some(&toast_overlay));

    let state = Rc::new(AppState {
        store: RefCell::new(Store::default()),
        password: RefCell::new(None),
        rows: RefCell::new(Vec::new()),
        list: list.clone(),
        toast_overlay: toast_overlay.clone(),
        store_path: StorePath::new(),
        search: search.clone(),
    });

    // initial load (ask for password if the store is encrypted)
    if state.store_path.is_encrypted() {
        let s = state.clone();
        prompt_password(
            &window,
            "Unlock",
            "Your account store is encrypted.",
            "_Unlock",
            move |pw| {
                match s.store_path.load(Some(&pw)) {
                    Ok(st) => {
                        *s.store.borrow_mut() = st;
                        *s.password.borrow_mut() = Some(pw);
                        rebuild_rows(&s);
                    }
                    Err(e) => toast(&s, &e),
                }
                glib::Propagation::Stop
            },
        );
    } else {
        match state.store_path.load(None) {
            Ok(st) => {
                *state.store.borrow_mut() = st;
                rebuild_rows(&state);
            }
            Err(e) => toast(&state, &format!("cannot load accounts: {e}")),
        }
    }

    import_btn.connect_clicked({
        let s = state.clone();
        let w = window.clone();
        move |_| do_import(&s, &w)
    });
    add_btn.connect_clicked({
        let s = state.clone();
        let w = window.clone();
        move |_| prompt_uri(&s, &w)
    });
    export_btn.connect_clicked({
        let s = state.clone();
        let w = window.clone();
        move |_| do_export(&s, &w)
    });
    search.connect_search_changed({
        let s = state.clone();
        move |_| apply_filter(&s)
    });

    let s = state.clone();
    timeout_add_local(std::time::Duration::from_secs(1), move || {
        tick(&s);
        ControlFlow::Continue
    });

    window.present();
}

fn toast(state: &AppState, msg: &str) {
    state
        .toast_overlay
        .add_toast(adw::Toast::builder().title(msg).build());
}

fn make_row(state: &Rc<AppState>, acc: &Account) -> (gtk::ListBoxRow, RowState) {
    // deliberately NOT activatable: single-click must not copy (see gesture below)
    let row = gtk::ListBoxRow::builder().can_focus(true).build();
    row.set_tooltip_text(Some("Double-click to copy"));

    let hbox = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .margin_start(12)
        .margin_end(12)
        .margin_top(8)
        .margin_bottom(8)
        .build();

    let name = gtk::Label::builder()
        .label(&acc.display_name())
        .xalign(0.0)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .build();

    let sub = match acc.kind {
        Kind::Totp => format!("TOTP \u{b7} {} \u{b7} {}s", acc.algorithm.as_str(), acc.period),
        Kind::Hotp => format!("HOTP \u{b7} counter {}", acc.counter),
    };
    let sublabel = gtk::Label::builder().xalign(0.0).label(&sub).build();
    sublabel.add_css_class("dim-label");
    sublabel.add_css_class("caption");

    let text_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
    text_box.append(&name);
    text_box.append(&sublabel);

    let spacer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    spacer.set_hexpand(true);

    let progress = match acc.kind {
        Kind::Totp => {
            let p = gtk::ProgressBar::builder()
                .valign(gtk::Align::Center)
                .width_request(42)
                .build();
            hbox.append(&p.clone());
            Some(p)
        }
        Kind::Hotp => None,
    };

    let code_label = gtk::Label::builder().xalign(1.0).valign(gtk::Align::Center).build();
    code_label.add_css_class("title-2");
    code_label.add_css_class("numeric");

    hbox.prepend(&text_box);
    hbox.append(&spacer);
    hbox.append(&code_label);
    row.set_child(Some(&hbox));

    let copy_fn = {
        let s = state.clone();
        let acc2 = acc.clone();
        let row2 = row.clone();
        Rc::new(move || {
            let now = now_unix();
            let code = code_for(&acc2, now);
            row2.clipboard().set_text(&code);
            match acc2.kind {
                Kind::Totp => toast(&s, &format!("Copied code for {}", acc2.display_name())),
                Kind::Hotp => {
                    advance_hotp(&s, &acc2);
                    toast(&s, &format!("Copied & advanced counter for {}", acc2.display_name()));
                }
            }
        })
    };

    // double-click copies (single click stays inert on purpose)
    let click = gtk::GestureClick::builder().button(1).build();
    let cf = copy_fn.clone();
    click.connect_pressed(move |_g, n_press, _x, _y| {
        if n_press == 2 {
            cf();
        }
    });
    row.add_controller(click);

    // Enter on a focused row copies too, for keyboard users
    let keys = gtk::EventControllerKey::new();
    let cf = copy_fn.clone();
    keys.connect_key_pressed(move |_c, key, _hv, _state| {
        if matches!(key, gtk::gdk::Key::Return | gtk::gdk::Key::KP_Enter | gtk::gdk::Key::ISO_Enter) {
            cf();
            glib::Propagation::Stop
        } else {
            glib::Propagation::Proceed
        }
    });
    row.add_controller(keys);

    (
        row,
        RowState {
            account: acc.clone(),
            code_label,
            progress,
            last_window: RefCell::new(u64::MAX),
        },
    )
}

fn rebuild_rows(state: &Rc<AppState>) {
    let store = state.store.borrow();
    let mut rows: Vec<(gtk::ListBoxRow, RowState)> = Vec::with_capacity(store.accounts.len());
    // pinned first, then stable original order
    let mut accounts: Vec<&Account> = store.accounts.iter().map(|sa| &sa.account).collect();
    let pinned: Vec<&Account> = store.accounts.iter().filter(|sa| sa.pinned).map(|sa| &sa.account).collect();
    let unpinned: Vec<&Account> = store.accounts.iter().filter(|sa| !sa.pinned).map(|sa| &sa.account).collect();
    accounts.clear();
    accounts.extend(pinned);
    accounts.extend(unpinned);
    for acc in accounts {
        rows.push(make_row(state, acc));
    }
    drop(store);

    while let Some(child) = state.list.first_child() {
        state.list.remove(&child);
    }
    for (row, _) in &rows {
        state.list.append(row);
    }
    *state.rows.borrow_mut() = rows;
    apply_filter(state);
    tick(state);
}

fn advance_hotp(state: &Rc<AppState>, acc: &Account) {
    {
        let mut store = state.store.borrow_mut();
        for sa in store.accounts.iter_mut() {
            if sa.account.secret == acc.secret && sa.account.label == acc.label {
                sa.account.counter += 1;
                break;
            }
        }
    }
    let pw = state.password.borrow().clone();
    if let Err(e) = state.store_path.save(&state.store.borrow(), pw.as_deref()) {
        toast(state, &format!("could not save counter: {e}"));
    }
    rebuild_rows(state);
}

fn tick(state: &Rc<AppState>) {
    let now = now_unix();
    let rows = state.rows.borrow();
    for (_row, rs) in rows.iter() {
        let a = &rs.account;
        match a.kind {
            Kind::Totp => {
                let window = now / a.period;
                if window != *rs.last_window.borrow() {
                    rs.code_label.set_text(&group_code(&code_for(a, now)));
                    *rs.last_window.borrow_mut() = window;
                }
                if let Some(p) = &rs.progress {
                    p.set_fraction(totp::seconds_remaining(now, a.period) as f64 / a.period as f64);
                }
            }
            Kind::Hotp => {
                if *rs.last_window.borrow() == u64::MAX {
                    rs.code_label.set_text(&group_code(&code_for(a, now)));
                    *rs.last_window.borrow_mut() = 0;
                }
            }
        }
    }
}

fn apply_filter(state: &Rc<AppState>) {
    let q = state.search.text().to_lowercase();
    for (row, rs) in state.rows.borrow().iter() {
        let hay = rs.account.display_name().to_lowercase();
        row.set_visible(q.is_empty() || hay.contains(&q));
    }
}

// ----------------------------------------------------------------- dialogs

fn prompt_password<F>(window: &adw::ApplicationWindow, title: &str, body: &str, ok: &str, f: F)
where
    F: Fn(String) -> glib::Propagation + 'static,
{
    let dlg = adw::MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .heading(title)
        .body(body)
        .build();
    let entry = adw::PasswordEntryRow::builder().title("Password").build();
    let group = adw::PreferencesGroup::new();
    group.add(&entry);
    dlg.set_extra_child(Some(&group));
    dlg.add_response("cancel", "Cancel");
    dlg.add_response(ok, "ok");
    dlg.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    dlg.set_default_response(Some("ok"));
    dlg.set_close_response("cancel");
    dlg.connect_response(None, move |_, resp| {
        if resp == "ok" {
            let pw = entry.text().to_string();
            entry.set_text("");
            f(pw);
        }
    });
    dlg.present();
}

fn prompt_uri(state: &Rc<AppState>, window: &adw::ApplicationWindow) {
    let dlg = adw::MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .heading("Add account")
        .body("Paste an otpauth:// URI")
        .build();
    let entry = adw::EntryRow::builder()
        .title("otpauth URI")
        .build();
    let group = adw::PreferencesGroup::new();
    group.add(&entry);
    dlg.set_extra_child(Some(&group));
    dlg.add_response("cancel", "Cancel");
    dlg.add_response("add", "_Add");
    dlg.set_response_appearance("add", adw::ResponseAppearance::Suggested);
    dlg.set_default_response(Some("add"));
    dlg.set_close_response("cancel");
    let s = state.clone();
    dlg.connect_response(None, move |_, resp| {
        if resp != "add" {
            return;
        }
        let text = entry.text().to_string();
        match uri::parse_otpauth(&text) {
            Ok(acc) => {
                {
                    let mut store = s.store.borrow_mut();
                    store.accounts.push(SavedAccount { account: acc, pinned: false });
                }
                let pw = s.password.borrow().clone();
                match s.store_path.save(&s.store.borrow(), pw.as_deref()) {
                    Ok(()) => {
                        rebuild_rows(&s);
                        toast(&s, "Account added");
                    }
                    Err(e) => toast(&s, &format!("could not save: {e}")),
                }
            }
            Err(e) => toast(&s, &format!("bad URI: {e}")),
        }
    });
    dlg.present();
}

fn do_import(state: &Rc<AppState>, window: &adw::ApplicationWindow) {
    let dialog = gtk::FileDialog::builder().title("Import WinAuth backup").build();
    let s = state.clone();
    let w = window.clone();
    dialog.open(Some(window), gtk::gio::Cancellable::NONE, move |result| {
        if let Ok(file) = result {
            let path = file.path().unwrap_or_default();
            if path.as_os_str().is_empty() {
                toast(&s, "could not resolve chosen file");
                return;
            }
            import_from_path(&s, &w, &path);
        }
    });
}

fn import_from_path(state: &Rc<AppState>, window: &adw::ApplicationWindow, path: &Path) {
    let s = state.clone();
    let w = window.clone();
    let p = path.to_path_buf();
    if peek_zip_encrypted(&p) {
        prompt_password(
            &w,
            "Backup password",
            &format!(
                "{} is password protected.",
                p.file_name().unwrap_or_default().to_string_lossy()
            ),
            "_Import",
            move |pw| {
                finish_import(&s, &p, Some(&pw));
                glib::Propagation::Stop
            },
        );
    } else {
        finish_import(&s, &p, None);
    }
}

fn peek_zip_encrypted(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    // local file header: general purpose bit 0 => encrypted
    bytes.starts_with(b"PK\x03\x04") && bytes.len() > 8 && bytes[6] & 0x01 == 1
}

fn finish_import(state: &Rc<AppState>, path: &Path, zip_pw: Option<&str>) {
    match import::import_file(path, zip_pw) {
        Ok(res) => {
            let (added, updated) = {
                let mut store = state.store.borrow_mut();
                let mut added = 0usize;
                let mut updated = 0usize;
                for acc in res.accounts {
                    match store
                        .accounts
                        .iter_mut()
                        .find(|sa| sa.account.secret == acc.secret && sa.account.label == acc.label)
                    {
                        Some(existing) => {
                            existing.account = acc;
                            updated += 1;
                        }
                        None => {
                            store.accounts.push(SavedAccount { account: acc, pinned: false });
                            added += 1;
                        }
                    }
                }
                (added, updated)
            };
            let pw = state.password.borrow().clone();
            if let Err(e) = state.store_path.save(&state.store.borrow(), pw.as_deref()) {
                toast(state, &format!("import failed to save: {e}"));
                return;
            }
            rebuild_rows(state);
            let mut msg = format!("Imported {added} account(s)");
            if updated > 0 {
                msg += &format!(", updated {updated}");
            }
            if !res.errors.is_empty() {
                msg += &format!(" ({} line(s) skipped)", res.errors.len());
            }
            toast(state, &msg);
        }
        Err(e) => toast(state, &format!("import failed: {e}")),
    }
}

fn do_export(state: &Rc<AppState>, window: &adw::ApplicationWindow) {
    let accounts: Vec<Account> = state.store.borrow().accounts.iter().map(|sa| sa.account.clone()).collect();
    if accounts.is_empty() {
        toast(state, "No accounts to export");
        return;
    }
    let dialog = gtk::FileDialog::builder()
        .title("Export backup")
        .initial_name(&export::default_backup_name(&export::civil_date(now_unix())))
        .build();
    let s = state.clone();
    let w = window.clone();
    dialog.save(Some(window), gtk::gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let mut path = file.path().unwrap_or_default();
        if path.as_os_str().is_empty() {
            toast(&s, "could not resolve chosen file");
            return;
        }
        let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if ext.is_empty() {
            path.set_extension("zip");
        }
        if path.extension().map(|e| e.to_string_lossy().to_lowercase()).as_deref() == Some("txt") {
            match export::write_txt(&path, &accounts) {
                Ok(()) => toast(&s, &format!("Exported {} account(s)", accounts.len())),
                Err(e) => toast(&s, &format!("export failed: {e}")),
            }
        } else {
            prompt_export_password(&w, &s, path, accounts);
        }
    });
}

fn prompt_export_password(
    window: &adw::ApplicationWindow,
    state: &Rc<AppState>,
    path: PathBuf,
    accounts: Vec<Account>,
) {
    let dlg = adw::MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .heading("Backup password")
        .body("WinAuth-compatible ZipCrypto. Pick a password you will remember — it is the only copy.")
        .build();
    let entry = adw::PasswordEntryRow::builder().title("Password").build();
    let group = adw::PreferencesGroup::new();
    group.add(&entry);
    dlg.set_extra_child(Some(&group));
    dlg.add_response("cancel", "Cancel");
    dlg.add_response("plain", "_Unencrypted zip");
    dlg.add_response("ok", "_Export");
    dlg.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    dlg.set_default_response(Some("ok"));
    dlg.set_close_response("cancel");
    let s = state.clone();
    dlg.connect_response(None, move |_, resp| match resp {
        "ok" => {
            let pw = entry.text().to_string();
            entry.set_text("");
            if pw.is_empty() {
                toast(&s, "Password is empty \u{2014} use \u{201c}Unencrypted zip\u{201d} or Cancel");
                return;
            }
            match export::write_zip(&path, &accounts, Some(&pw)) {
                Ok(()) => toast(&s, &format!("Exported {} account(s), encrypted", accounts.len())),
                Err(e) => toast(&s, &format!("export failed: {e}")),
            }
        }
        "plain" => {
            entry.set_text("");
            match export::write_zip(&path, &accounts, None) {
                Ok(()) => toast(&s, &format!("Exported {} account(s), NOT encrypted", accounts.len())),
                Err(e) => toast(&s, &format!("export failed: {e}")),
            }
        }
        _ => {}
    });
    dlg.present();
}
