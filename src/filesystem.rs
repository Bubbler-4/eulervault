use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use directories::ProjectDirs;

use crate::SOLUTIONS_FILE;
use crate::crypto::decrypt_bytes_from_path;
use crate::misc::{Settings, parse_solutions};
use crate::template::validate_filepath_pattern;

pub(crate) fn repo_path(relative: impl AsRef<Path>) -> PathBuf {
    env::current_dir()
        .expect("failed to read current directory")
        .join(relative)
}

pub(crate) fn resolve_path(path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_path(path)
    }
}

pub(crate) fn encrypted_name(name: &str) -> String {
    format!("{name}.asc")
}

pub(crate) fn encrypted_path_for_plaintext(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.asc", path.display()))
}

pub(crate) fn ensure_gitignore_entries(entries: &[String]) -> Result<()> {
    let path = repo_path(".gitignore");
    let mut content = if path.exists() {
        fs::read_to_string(&path)?
    } else {
        String::new()
    };
    let mut existing = content.lines().map(str::to_string).collect::<Vec<_>>();

    for entry in entries {
        if !existing.iter().any(|line| line == entry) {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(entry);
            content.push('\n');
            existing.push(entry.clone());
        }
    }
    fs::write(path, content)?;
    Ok(())
}

pub(crate) fn master_password_path() -> Result<PathBuf> {
    let project_dirs = ProjectDirs::from("", "", "eulervault")
        .ok_or_else(|| anyhow!("could not determine config directory"))?;
    let config_dir = project_dirs.config_dir();
    fs::create_dir_all(config_dir)?;
    Ok(config_dir.join("master_password.txt"))
}

pub(crate) fn write_master_password(password: &str) -> Result<()> {
    let path = master_password_path()?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(password.as_bytes())?;
    Ok(())
}

pub(crate) fn read_master_password() -> Result<String> {
    let path = master_password_path()?;
    if !path.exists() {
        bail!("master password file does not exist: {}", path.display());
    }
    let password = fs::read_to_string(path)?.trim().to_string();
    if password.is_empty() {
        bail!("master password file is empty");
    }
    Ok(password)
}

pub(crate) fn load_settings() -> Result<Settings> {
    let content = fs::read_to_string(repo_path(crate::SETTINGS_FILE))
        .context("failed to read eulervault.toml")?;
    let settings: Settings = toml::from_str(&content).context("failed to parse eulervault.toml")?;
    validate_filepath_pattern(&settings.filepath)?;
    Ok(settings)
}

pub(crate) fn load_solutions_bytes(master_password: &str) -> Result<Vec<u8>> {
    let plaintext = repo_path(SOLUTIONS_FILE);
    if plaintext.exists() {
        return fs::read(plaintext).map_err(Into::into);
    }
    let encrypted = repo_path(encrypted_name(SOLUTIONS_FILE));
    if encrypted.exists() {
        return decrypt_bytes_from_path(&encrypted, master_password);
    }
    Ok(Vec::new())
}

pub(crate) fn load_solutions_map(master_password: &str) -> Result<BTreeMap<u32, String>> {
    let bytes = load_solutions_bytes(master_password)?;
    if bytes.is_empty() {
        return Ok(BTreeMap::new());
    }
    parse_solutions(&String::from_utf8(bytes)?)
}

pub(crate) fn should_relock_solution_file(
    plaintext_path: &Path,
    encrypted_path: &Path,
) -> Result<bool> {
    let plaintext_metadata = fs::metadata(plaintext_path)
        .with_context(|| format!("failed to read metadata for {}", plaintext_path.display()))?;
    if !encrypted_path.exists() {
        return Ok(true);
    }
    let encrypted_metadata = fs::metadata(encrypted_path)
        .with_context(|| format!("failed to read metadata for {}", encrypted_path.display()))?;
    let plaintext_modified = plaintext_metadata.modified().with_context(|| {
        format!(
            "failed to read modified time for {}",
            plaintext_path.display()
        )
    })?;
    let encrypted_modified = encrypted_metadata.modified().with_context(|| {
        format!(
            "failed to read modified time for {}",
            encrypted_path.display()
        )
    })?;
    Ok(plaintext_modified > encrypted_modified)
}
