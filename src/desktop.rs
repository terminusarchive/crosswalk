//! The desktop-entry table: app names by the program each `.desktop` entry launches.

use std::{
    ffi::OsStr,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use crate::collect::attribution::ExecutableIdentity;

/// Folders that hold many unrelated programs, so a shared folder never names them.
const SHARED_FOLDERS: [&str; 8] = [
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/lib",
    "/usr/libexec",
];

const SYSTEM_FLATPAK_EXPORTS: &str = "/var/lib/flatpak/exports/share/applications";

/// Programs that only start another, so an entry led by one names nothing by path.
const LAUNCHERS: [&str; 7] = ["env", "sh", "bash", "dash", "zsh", "fish", "flatpak"];

/// The largest wrapper script whose `exec` is followed.
const MAX_SCRIPT_BYTES: u64 = 4096;

/// The environment values that decide where desktop entries live; a value
/// that is unset or empty is `None`.
#[derive(Debug, Default)]
pub struct DesktopEnv<'a> {
    pub xdg_data_home: Option<&'a str>,
    pub xdg_data_dirs: Option<&'a str>,
    pub home: Option<&'a str>,
    pub sudo_user: Option<&'a str>,
}

#[derive(Debug)]
struct Entry {
    name: String,
    /// The entry's file name without `.desktop`; a Flatpak app's ID.
    app_id: String,
    /// What the entry launches, and what a wrapper script launches in turn;
    /// empty when it starts a launcher or is `NoDisplay=true`, which no
    /// running program is matched against.
    programs: Vec<PathBuf>,
}

impl Entry {
    fn has_program_file_name(&self, file_name: Option<&OsStr>) -> bool {
        self.programs
            .iter()
            .any(|program| program.file_name() == file_name)
    }

    fn has_program_in(&self, folder: &Path) -> bool {
        self.programs
            .iter()
            .any(|program| program.parent() == Some(folder))
    }
}

#[derive(Debug, Default)]
pub struct DesktopNames {
    entries: Vec<Entry>,
}

impl DesktopNames {
    /// Reads the `*.desktop` files of the folders, earlier folders first. A
    /// folder or file that cannot be read, or lacks a `Name=` or `Exec=`, or is
    /// `Hidden=true`, is skipped; a `NoDisplay=true` one names only by app ID. A
    /// bare `Exec=` program is looked up on `path`, a `:`-separated list of
    /// folders.
    pub fn load(folders: &[PathBuf], path: &str) -> Self {
        let entries = folders
            .iter()
            .flat_map(|folder| desktop_files(folder))
            .filter_map(|file| read_entry(&file, path))
            .collect();
        Self { entries }
    }

    /// The name of the entry the program belongs to: the one named for its
    /// Flatpak app ID, else one whose program has the same file name, else one
    /// whose program is in the same folder, unless that folder is shared. The
    /// first such entry wins.
    pub fn name(&self, executable: &ExecutableIdentity) -> Option<&str> {
        let by_app_id = || {
            let app = executable.flatpak_app.as_deref()?;
            self.entries.iter().find(|entry| entry.app_id == app)
        };
        let by_file_name = self
            .entries
            .iter()
            .find(|entry| entry.has_program_file_name(executable.path.file_name()));
        let by_folder = || {
            let folder = executable.path.parent().filter(|f| !is_shared_folder(f))?;
            self.entries
                .iter()
                .find(|entry| entry.has_program_in(folder))
        };
        by_app_id()
            .or(by_file_name)
            .or_else(by_folder)
            .map(|entry| entry.name.as_str())
    }
}

/// The folders to read entries from, most important first: the user's data
/// folder, each data dir, the system Flatpak exports, then the `sudo` user's own
/// folders, whose home `passwd` (the text of `/etc/passwd`) gives by name.
pub fn desktop_folders(env: &DesktopEnv, passwd: &str) -> Vec<PathBuf> {
    let user_data = env
        .xdg_data_home
        .map(PathBuf::from)
        .or_else(|| env.home.map(|home| Path::new(home).join(".local/share")));
    let data_dirs = env.xdg_data_dirs.unwrap_or("/usr/local/share:/usr/share");
    let sudo_home = env.sudo_user.and_then(|user| home_in_passwd(passwd, user));
    let sudo_folders = sudo_home.into_iter().flat_map(|home| {
        [
            home.join(".local/share/applications"),
            home.join(".local/share/flatpak/exports/share/applications"),
        ]
    });
    user_data
        .into_iter()
        .chain(data_dirs.split(':').map(PathBuf::from))
        .map(|data| data.join("applications"))
        .chain([PathBuf::from(SYSTEM_FLATPAK_EXPORTS)])
        .chain(sudo_folders)
        .collect()
}

fn home_in_passwd(passwd: &str, user: &str) -> Option<PathBuf> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(user)).then(|| fields.nth(4).map(PathBuf::from))?
    })
}

fn desktop_files(folder: &Path) -> Vec<PathBuf> {
    let Ok(listing) = fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = listing
        .filter_map(|item| item.ok())
        .map(|item| item.path())
        .filter(|file| file.extension().is_some_and(|ext| ext == "desktop"))
        .collect();
    files.sort();
    files
}

fn read_entry(file: &Path, path: &str) -> Option<Entry> {
    let text = fs::read_to_string(file).ok()?;
    let mut fields = Fields::default();
    for line in text
        .lines()
        .skip_while(|line| line.trim() != "[Desktop Entry]")
        .skip(1)
        .take_while(|line| !line.starts_with('['))
    {
        fields.read_line(line);
    }
    if fields.hidden {
        return None;
    }
    let programs = fields
        .exec
        .filter(|exec| !fields.no_display && !is_launcher(Path::new(exec)))
        .map(|exec| resolve_program(&exec, path))
        .map(with_script_exec)
        .unwrap_or_default();
    Some(Entry {
        name: fields.name?,
        app_id: file.file_stem()?.to_string_lossy().into_owned(),
        programs,
    })
}

#[derive(Default)]
struct Fields {
    name: Option<String>,
    exec: Option<String>,
    hidden: bool,
    no_display: bool,
}

impl Fields {
    fn read_line(&mut self, line: &str) {
        match line.split_once('=') {
            Some(("Hidden", value)) => self.hidden = value.trim() == "true",
            Some(("NoDisplay", value)) => self.no_display = value.trim() == "true",
            Some(("Name", value)) => self.name = Some(value.trim().to_owned()),
            Some(("Exec", value)) => {
                self.exec = value
                    .split_whitespace()
                    .next()
                    .map(|word| word.trim_matches('"').to_owned());
            }
            _ => {}
        }
    }
}

/// The program an `Exec=` names: found on `path` when bare, symlinks followed
/// when it exists.
fn resolve_program(exec: &str, path: &str) -> PathBuf {
    let program = if exec.contains('/') {
        PathBuf::from(exec)
    } else {
        path.split(':')
            .map(|folder| Path::new(folder).join(exec))
            .find(|candidate| candidate.exists())
            .unwrap_or_else(|| PathBuf::from(exec))
    };
    fs::canonicalize(&program).unwrap_or(program)
}

/// The program, followed by the one its wrapper script ends by `exec`ing.
fn with_script_exec(program: PathBuf) -> Vec<PathBuf> {
    let exec_target = script_exec_target(&program);
    std::iter::once(program).chain(exec_target).collect()
}

/// The first absolute path on the last line that begins with `exec` of a `#!` text file of at
/// most `MAX_SCRIPT_BYTES`, symlinks followed; none when that is a launcher.
fn script_exec_target(script: &Path) -> Option<PathBuf> {
    let mut bytes = Vec::new();
    fs::File::open(script)
        .ok()?
        .take(MAX_SCRIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    if bytes.len() as u64 > MAX_SCRIPT_BYTES || !text.starts_with("#!") {
        return None;
    }
    let exec_line = text
        .lines()
        .map(str::trim_start)
        .rfind(|line| line.starts_with("exec "))?;
    let target = Path::new(exec_line.strip_prefix("exec ")?.split_whitespace().next()?);
    if !target.is_absolute() || is_launcher(target) {
        return None;
    }
    Some(fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf()))
}

fn is_shared_folder(folder: &Path) -> bool {
    SHARED_FOLDERS
        .iter()
        .any(|shared| folder == Path::new(shared))
        || folder.ends_with(".local/bin")
}

fn is_launcher(program: &Path) -> bool {
    program
        .file_name()
        .is_some_and(|name| LAUNCHERS.iter().any(|launcher| name == *launcher))
}
