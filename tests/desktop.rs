use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crosswalk::collect::attribution::ExecutableIdentity;
use crosswalk::desktop::{DesktopEnv, DesktopNames, desktop_folders};

fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "crosswalk-desktop-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn entry(folder: &Path, file: &str, body: &str) {
    fs::create_dir_all(folder).unwrap();
    fs::write(folder.join(file), body).unwrap();
}

fn simple(name: &str, exec: &str) -> String {
    format!("[Desktop Entry]\nType=Application\nName={name}\nName[de]=Anders\nExec={exec} %U\n")
}

fn program(path: &str) -> ExecutableIdentity {
    ExecutableIdentity {
        path: path.into(),
        flatpak_app: None,
    }
}

fn name_of<'a>(names: &'a DesktopNames, path: &str) -> Option<&'a str> {
    names.name(&program(path))
}

#[test]
fn a_program_with_the_file_name_of_the_entrys_program_takes_its_name() {
    let root = scratch("file-name");
    let apps = root.join("apps");
    entry(&apps, "web.desktop", &simple("Web", "/opt/web/web"));
    let names = DesktopNames::load(&[apps], "");
    assert_eq!(name_of(&names, "/elsewhere/web"), Some("Web"));
    assert_eq!(name_of(&names, "/elsewhere/other"), None);
}

#[test]
fn a_program_in_the_folder_of_a_symlinked_exec_takes_its_name() {
    let root = scratch("symlink");
    let opt = root.join("opt/google/chrome");
    fs::create_dir_all(&opt).unwrap();
    fs::write(opt.join("google-chrome"), "").unwrap();
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    symlink(opt.join("google-chrome"), bin.join("google-chrome-stable")).unwrap();
    let apps = root.join("apps");
    let exec = bin.join("google-chrome-stable");
    entry(
        &apps,
        "chrome.desktop",
        &simple("Google Chrome", exec.to_str().unwrap()),
    );
    let names = DesktopNames::load(&[apps], "");
    let helper = opt.join("chrome");
    assert_eq!(
        name_of(&names, helper.to_str().unwrap()),
        Some("Google Chrome")
    );
}

#[test]
fn a_shared_folder_never_names_its_other_programs() {
    let root = scratch("shared");
    let apps = root.join("apps");
    entry(
        &apps,
        "portal.desktop",
        &simple("Portal", "/usr/lib/xdg-desktop-portal-gtk"),
    );
    entry(
        &apps,
        "tool.desktop",
        &simple("Tool", "/home/me/.local/bin/tool"),
    );
    let names = DesktopNames::load(&[apps], "");
    assert_eq!(name_of(&names, "/usr/lib/dconf-service"), None);
    assert_eq!(
        name_of(&names, "/usr/lib/xdg-desktop-portal-gtk"),
        Some("Portal")
    );
    assert_eq!(name_of(&names, "/home/me/.local/bin/other"), None);
}

#[test]
fn a_bare_exec_is_found_on_the_given_path() {
    let root = scratch("bare");
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let apps = root.join("apps");
    entry(&apps, "kitty.desktop", &simple("Kitty", "kitty"));
    let names = DesktopNames::load(std::slice::from_ref(&apps), "");
    assert_eq!(name_of(&names, "/elsewhere/kitty"), Some("Kitty"));
    fs::create_dir_all(root.join("kit")).unwrap();
    fs::write(root.join("kit/kitty"), "").unwrap();
    let path = format!("{}:{}", bin.display(), root.join("kit").display());
    let names = DesktopNames::load(&[apps], &path);
    let sibling = root.join("kit/kitten");
    assert_eq!(name_of(&names, sibling.to_str().unwrap()), Some("Kitty"));
}

#[test]
fn a_file_name_match_beats_a_folder_match() {
    let root = scratch("level");
    let apps = root.join("apps");
    entry(&apps, "a.desktop", &simple("Suite", "/opt/suite/launcher"));
    entry(&apps, "b.desktop", &simple("Editor", "/opt/other/editor"));
    let names = DesktopNames::load(&[apps], "");
    assert_eq!(name_of(&names, "/opt/suite/editor"), Some("Editor"));
}

#[test]
fn the_first_folders_entry_beats_a_later_one() {
    let root = scratch("order");
    let (user, system) = (root.join("user"), root.join("system"));
    entry(
        &system,
        "app.desktop",
        &simple("System App", "/opt/app/app"),
    );
    entry(&user, "app.desktop", &simple("User App", "/opt/app/app"));
    let names = DesktopNames::load(&[user, system], "");
    assert_eq!(name_of(&names, "/opt/app/app"), Some("User App"));
}

#[test]
fn a_hidden_entry_names_nothing() {
    let root = scratch("hidden");
    let apps = root.join("apps");
    let body = format!("{}Hidden=true\n", simple("Gone", "/opt/gone/gone"));
    entry(&apps, "gone.desktop", &body);
    let names = DesktopNames::load(&[apps], "");
    assert_eq!(name_of(&names, "/opt/gone/gone"), None);
}

#[test]
fn bad_entries_and_missing_folders_are_skipped() {
    let root = scratch("bad");
    let apps = root.join("apps");
    entry(&apps, "binary.desktop", "\u{0}\u{1}not an entry");
    entry(&apps, "no-name.desktop", "[Desktop Entry]\nExec=/opt/x/x\n");
    entry(&apps, "no-exec.desktop", "[Desktop Entry]\nName=Nothing\n");
    entry(&apps, "good.desktop", &simple("Good", "/opt/good/good"));
    let names = DesktopNames::load(&[root.join("missing"), apps], "");
    assert_eq!(name_of(&names, "/opt/good/good"), Some("Good"));
    assert_eq!(name_of(&names, "/opt/x/x"), None);
}

#[test]
fn an_entry_that_starts_a_launcher_names_no_program_by_path() {
    let root = scratch("launcher");
    let apps = root.join("apps");
    entry(&apps, "env.desktop", &simple("Env App", "env X=1 app"));
    entry(&apps, "sh.desktop", &simple("Shell App", "sh -c app"));
    entry(
        &apps,
        "flatpak.desktop",
        &simple("Flat App", "/usr/bin/flatpak run org.x.App"),
    );
    let names = DesktopNames::load(&[apps], "");
    assert_eq!(name_of(&names, "/usr/bin/env"), None);
    assert_eq!(name_of(&names, "/usr/bin/sh"), None);
    assert_eq!(name_of(&names, "/usr/bin/flatpak"), None);
}

fn folders<'a>(
    xdg_data_home: Option<&'a str>,
    xdg_data_dirs: Option<&'a str>,
    home: Option<&'a str>,
) -> DesktopEnv<'a> {
    DesktopEnv {
        xdg_data_home,
        xdg_data_dirs,
        home,
        sudo_user: None,
    }
}

fn paths(list: &[&str]) -> Vec<PathBuf> {
    list.iter().map(PathBuf::from).collect()
}

const FLATPAK: &str = "/var/lib/flatpak/exports/share/applications";

#[test]
fn unset_variables_give_the_default_folders() {
    let env = folders(None, None, Some("/home/ann"));
    assert_eq!(
        desktop_folders(&env, ""),
        paths(&[
            "/home/ann/.local/share/applications",
            "/usr/local/share/applications",
            "/usr/share/applications",
            FLATPAK,
        ])
    );
}

#[test]
fn set_variables_give_the_users_folder_first_then_each_data_dir_in_order() {
    let env = folders(Some("/data"), Some("/a:/b"), Some("/home/ann"));
    assert_eq!(
        desktop_folders(&env, ""),
        paths(&[
            "/data/applications",
            "/a/applications",
            "/b/applications",
            FLATPAK
        ])
    );
}

#[test]
fn the_sudo_users_folders_are_added_from_the_passwd_file() {
    let mut env = folders(None, None, Some("/root"));
    env.sudo_user = Some("ann");
    let passwd = "root:x:0:0:root:/root:/bin/bash\nann:x:1000:1000:Ann:/home/ann:/bin/fish\n";
    let found = desktop_folders(&env, passwd);
    assert_eq!(
        found[found.len() - 2..],
        paths(&[
            "/home/ann/.local/share/applications",
            "/home/ann/.local/share/flatpak/exports/share/applications",
        ])
    );
}

#[test]
fn a_sudo_user_missing_from_the_passwd_file_adds_nothing() {
    let mut env = folders(None, None, Some("/root"));
    env.sudo_user = Some("bob");
    let found = desktop_folders(&env, "ann:x:1000:1000:Ann:/home/ann:/bin/fish\n");
    assert_eq!(
        found,
        desktop_folders(&folders(None, None, Some("/root")), "")
    );
}

fn sandboxed(path: &str, app: &str) -> ExecutableIdentity {
    ExecutableIdentity {
        path: path.into(),
        flatpak_app: Some(app.into()),
    }
}

#[test]
fn a_flatpak_app_is_named_by_its_app_id_entry_over_a_path_match() {
    let root = scratch("flatpak");
    let apps = root.join("apps");
    entry(
        &apps,
        "a-other.desktop",
        &simple("Other", "/app/bin/dropbox"),
    );
    entry(
        &apps,
        "com.dropbox.Client.desktop",
        &simple("Dropbox", "flatpak run com.dropbox.Client"),
    );
    let names = DesktopNames::load(&[apps], "");
    assert_eq!(
        names.name(&sandboxed("/app/bin/dropbox", "com.dropbox.Client")),
        Some("Dropbox")
    );
}

#[test]
fn a_flatpak_app_without_its_entry_falls_back_to_path_matching() {
    let root = scratch("flatpak-fallback");
    let apps = root.join("apps");
    entry(&apps, "web.desktop", &simple("Web", "/opt/web/web"));
    let names = DesktopNames::load(&[apps], "");
    assert_eq!(
        names.name(&sandboxed("/opt/web/web", "org.missing.App")),
        Some("Web")
    );
    assert_eq!(names.name(&sandboxed("/opt/x/x", "org.missing.App")), None);
}

#[test]
fn a_no_display_entry_names_nothing_by_path_but_still_names_a_flatpak_app() {
    let root = scratch("no-display");
    let apps = root.join("apps");
    let hidden = |name: &str, exec: &str| format!("{}NoDisplay=true\n", simple(name, exec));
    entry(
        &apps,
        "claude-url-handler.desktop",
        &hidden(
            "Claude Code URL Handler",
            "/home/u/.local/share/claude/versions/2.1.296",
        ),
    );
    entry(
        &apps,
        "com.dropbox.Client.desktop",
        &hidden("Dropbox", "dropbox-launcher"),
    );
    let names = DesktopNames::load(&[apps], "");
    let claude = "/home/u/.local/share/claude/versions/2.1.296";
    assert_eq!(name_of(&names, claude), None);
    assert_eq!(
        name_of(&names, "/home/u/.local/share/claude/versions/2.1.300"),
        None
    );
    let flatpak = ExecutableIdentity {
        path: "/app/bin/dropbox".into(),
        flatpak_app: Some("com.dropbox.Client".to_owned()),
    };
    assert_eq!(names.name(&flatpak), Some("Dropbox"));
}

fn script_entry(root: &Path, script: &[u8]) -> Vec<PathBuf> {
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join("launch"), script).unwrap();
    let apps = root.join("apps");
    let exec = bin.join("launch");
    entry(&apps, "app.desktop", &simple("App", exec.to_str().unwrap()));
    vec![apps]
}

fn exec_script(last_line: &str) -> Vec<u8> {
    format!("#!/bin/bash\necho start\n{last_line} \"$@\"\n").into_bytes()
}

#[test]
fn a_scripts_exec_names_programs_beside_the_exec_target() {
    let root = scratch("wrapper");
    let chrome = root.join("opt/chrome");
    fs::create_dir_all(&chrome).unwrap();
    fs::write(chrome.join("google-chrome"), "").unwrap();
    let line = format!("exec {}/google-chrome $FLAGS", chrome.display());
    let apps = script_entry(&root, &exec_script(&line));
    let names = DesktopNames::load(&apps, "");
    let helper = chrome.join("chrome");
    assert_eq!(name_of(&names, helper.to_str().unwrap()), Some("App"));
}

#[test]
fn a_scripts_exec_target_is_followed_through_symlinks() {
    let root = scratch("wrapper-link");
    let real = root.join("versions/2.1.296");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("claude"), "").unwrap();
    symlink(real.join("claude"), root.join("current")).unwrap();
    let line = format!("exec {}", root.join("current").display());
    let apps = script_entry(&root, &exec_script(&line));
    let names = DesktopNames::load(&apps, "");
    let other = root.join("versions/2.1.296/claude");
    assert_eq!(name_of(&names, other.to_str().unwrap()), Some("App"));
}

#[test]
fn a_script_exec_that_adds_nothing_names_no_program() {
    let cases: [(&str, Vec<u8>); 5] = [
        (
            "too-big",
            [
                b"#!/bin/bash\n".to_vec(),
                vec![b'#'; 5000],
                b"\nexec /opt/x/prog\n".to_vec(),
            ]
            .concat(),
        ),
        ("binary", b"\x7fELF exec /opt/x/prog\n".to_vec()),
        ("no-exec", b"#!/bin/bash\necho /opt/x/prog\n".to_vec()),
        ("relative", b"#!/bin/bash\nexec ./prog\n".to_vec()),
        (
            "launcher",
            b"#!/bin/bash\nexec /usr/bin/env /opt/x/prog\n".to_vec(),
        ),
    ];
    for (label, script) in cases {
        let root = scratch(label);
        fs::create_dir_all(root.join("opt/x")).unwrap();
        fs::write(root.join("opt/x/prog"), "").unwrap();
        let apps = script_entry(&root, &script);
        let names = DesktopNames::load(&apps, "");
        assert_eq!(name_of(&names, "/opt/x/prog"), None, "{label}");
        assert_eq!(name_of(&names, "/opt/x/other"), None, "{label}");
    }
}

#[test]
fn a_scripts_exec_in_a_shared_folder_names_only_by_file_name() {
    let root = scratch("wrapper-shared");
    let line = "exec /usr/bin/tool";
    let apps = script_entry(&root, &exec_script(line));
    let names = DesktopNames::load(&apps, "");
    assert_eq!(name_of(&names, "/usr/bin/tool"), Some("App"));
    assert_eq!(name_of(&names, "/usr/bin/unrelated"), None);
}

#[test]
fn a_scripts_exec_line_is_found_before_trailing_lines() {
    let root = scratch("wrapper-trailing");
    let opt = root.join("opt/chrome");
    fs::create_dir_all(&opt).unwrap();
    fs::write(opt.join("google-chrome"), "").unwrap();
    let script = format!(
        "#!/bin/bash\nif true; then\n  exec {}/google-chrome \"$@\"\n  # not reached\n  exit 1\nfi\n",
        opt.display()
    );
    let apps = script_entry(&root, script.as_bytes());
    let names = DesktopNames::load(&apps, "");
    let helper = opt.join("chrome");
    assert_eq!(name_of(&names, helper.to_str().unwrap()), Some("App"));
}
