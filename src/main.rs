use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use dialoguer::{Input, Password as PasswordInput};
use directories::ProjectDirs;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};

use openpgp::crypto::{Password as OpenPgpPassword, SessionKey};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message};
use openpgp::types::SymmetricAlgorithm;

const SETTINGS_FILE: &str = "eulervault.toml";
const SOLUTIONS_FILE: &str = "solutions.txt";

#[derive(Parser)]
#[command(name = "eulervault")]
#[command(about = "Encrypt and share Project Euler solutions")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    New { problem: u32 },
    Set { problem: u32, solution: String },
    Update,
    Master,
    ChangeMasterPassword,
    Unlock { problem: u32, solution: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct Settings {
    filepath: String,
    template: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::New { problem } => cmd_new(problem),
        Commands::Set { problem, solution } => cmd_set(problem, &solution),
        Commands::Update => cmd_update(),
        Commands::Master => cmd_master(),
        Commands::ChangeMasterPassword => cmd_change_master_password(),
        Commands::Unlock { problem, solution } => cmd_unlock(problem, &solution),
    }
}

fn cmd_init() -> Result<()> {
    if repo_path(SETTINGS_FILE).exists() {
        bail!("Remove eulervault.toml to restart the init process");
    }

    let filepath = prompt_filepath_pattern()?;
    let master_password = prompt_new_password("master password")?;

    let settings = Settings {
        filepath,
        template: None,
    };
    let settings_toml = toml::to_string_pretty(&settings)?;
    fs::write(repo_path(SETTINGS_FILE), settings_toml)?;

    write_master_password(&master_password)?;

    let gitignore_pattern = filepath_pattern_to_glob(&settings.filepath);
    ensure_gitignore_entries(&[SOLUTIONS_FILE.to_string(), gitignore_pattern])?;

    let encrypted_solutions = repo_path(encrypted_name(SOLUTIONS_FILE));
    if !encrypted_solutions.exists() {
        encrypt_bytes_to_path(&[], &master_password, &encrypted_solutions)?;
    }

    Ok(())
}

fn cmd_new(problem: u32) -> Result<()> {
    let settings = load_settings()?;
    let path = render_solution_path(&settings.filepath, problem)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        bail!("solution file already exists: {}", path.display());
    }
    let content = if let Some(template_path) = settings.template.as_deref() {
        load_template_content(template_path, problem)?
    } else {
        Vec::new()
    };
    fs::write(&path, content)?;
    println!("{}", path.display());
    Ok(())
}

fn cmd_set(problem: u32, solution: &str) -> Result<()> {
    let settings = load_settings()?;
    let master_password = read_master_password()?;

    let mut solutions = load_solutions_map(&master_password)?;
    solutions.insert(problem, solution.to_string());
    let solutions_content = serialize_solutions(&solutions);
    let encrypted_solutions = repo_path(encrypted_name(SOLUTIONS_FILE));
    encrypt_bytes_to_path(
        solutions_content.as_bytes(),
        &master_password,
        &encrypted_solutions,
    )?;

    lock_solution_file(&settings, problem, solution)?;
    Ok(())
}

fn cmd_update() -> Result<()> {
    let settings = load_settings()?;
    let content = fs::read_to_string(repo_path(SOLUTIONS_FILE))
        .context("failed to read solutions.txt; run `eulervault master` first if needed")?;
    let solutions = parse_solutions(&content)?;
    for (problem, solution) in solutions {
        let plaintext_path = render_solution_path(&settings.filepath, problem)?;
        let encrypted_path = encrypted_path_for_plaintext(&plaintext_path);
        if should_relock_solution_file(&plaintext_path, &encrypted_path)? {
            lock_solution_file(&settings, problem, &solution)?;
        }
    }
    Ok(())
}

fn cmd_master() -> Result<()> {
    let settings = load_settings()?;
    let password = prompt_password("master password")?;

    let encrypted_solutions = repo_path(encrypted_name(SOLUTIONS_FILE));
    let decrypted = decrypt_bytes_from_path(&encrypted_solutions, &password)?;
    fs::write(repo_path(SOLUTIONS_FILE), &decrypted)?;
    let solutions = parse_solutions(&String::from_utf8(decrypted)?)?;

    for (problem, solution) in solutions {
        let plaintext = render_solution_path(&settings.filepath, problem)?;
        let encrypted = encrypted_path_for_plaintext(&plaintext);
        if !encrypted.exists() {
            continue;
        }
        let bytes = decrypt_bytes_from_path(&encrypted, &solution)
            .with_context(|| format!("failed to decrypt {}", encrypted.display()))?;
        if let Some(parent) = plaintext.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&plaintext, bytes)?;
    }

    write_master_password(&password)?;
    Ok(())
}

fn cmd_change_master_password() -> Result<()> {
    let old_password = read_master_password()?;
    let new_password = prompt_new_password("new master password")?;

    let solutions_bytes = load_solutions_bytes(&old_password)?;
    let encrypted_solutions = repo_path(encrypted_name(SOLUTIONS_FILE));
    encrypt_bytes_to_path(&solutions_bytes, &new_password, &encrypted_solutions)?;
    write_master_password(&new_password)?;
    Ok(())
}

fn cmd_unlock(problem: u32, solution: &str) -> Result<()> {
    let settings = load_settings()?;
    let plaintext = render_solution_path(&settings.filepath, problem)?;
    let encrypted = encrypted_path_for_plaintext(&plaintext);
    let decrypted = decrypt_bytes_from_path(&encrypted, solution)?;
    if let Some(parent) = plaintext.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&plaintext, decrypted)?;
    println!("{}", plaintext.display());
    Ok(())
}

fn lock_solution_file(settings: &Settings, problem: u32, solution: &str) -> Result<()> {
    let plaintext_path = render_solution_path(&settings.filepath, problem)?;
    if !plaintext_path.exists() {
        bail!(
            "solution file does not exist for problem {}: {}",
            problem,
            plaintext_path.display()
        );
    }
    let encrypted_path = encrypted_path_for_plaintext(&plaintext_path);
    let content = fs::read(&plaintext_path)
        .with_context(|| format!("failed to read {}", plaintext_path.display()))?;
    encrypt_bytes_to_path(&content, solution, &encrypted_path)?;
    Ok(())
}

fn should_relock_solution_file(plaintext_path: &Path, encrypted_path: &Path) -> Result<bool> {
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

fn load_settings() -> Result<Settings> {
    let content =
        fs::read_to_string(repo_path(SETTINGS_FILE)).context("failed to read eulervault.toml")?;
    let settings: Settings = toml::from_str(&content).context("failed to parse eulervault.toml")?;
    validate_filepath_pattern(&settings.filepath)?;
    Ok(settings)
}

fn validate_filepath_pattern(pattern: &str) -> Result<()> {
    if !pattern.contains("%p") && !pattern.contains("%P") {
        bail!("filepath pattern must contain %p or %P");
    }
    Ok(())
}

fn render_solution_path(pattern: &str, problem: u32) -> Result<PathBuf> {
    validate_filepath_pattern(pattern)?;
    let rendered = render_placeholders(pattern, problem);
    Ok(repo_path(&rendered))
}

fn render_placeholders(input: &str, problem: u32) -> String {
    let problem_group = (problem - 1) / 100 + 1;
    let problem_text = problem.to_string();
    let problem_padded = format!("{problem:04}");
    let problem_group_text = problem_group.to_string();

    let mut rendered = String::with_capacity(input.len().saturating_mul(2));
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            rendered.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('%') => {
                chars.next();
                rendered.push('%');
            }
            Some('p') => {
                chars.next();
                rendered.push_str(&problem_text);
            }
            Some('P') => {
                chars.next();
                rendered.push_str(&problem_padded);
            }
            Some('g') => {
                chars.next();
                rendered.push_str(&problem_group_text);
            }
            Some(other) => {
                chars.next();
                rendered.push('%');
                rendered.push(other);
            }
            None => rendered.push('%'),
        }
    }

    rendered
}

fn load_template_content(template_path: &str, problem: u32) -> Result<Vec<u8>> {
    let resolved_path = resolve_path(template_path);
    let template = fs::read_to_string(&resolved_path).with_context(|| {
        format!(
            "failed to read template file configured as {template_path} (resolved to {}); ensure the file exists and is readable",
            resolved_path.display()
        )
    })?;
    Ok(render_placeholders(&template, problem).into_bytes())
}

fn filepath_pattern_to_glob(pattern: &str) -> String {
    pattern
        .replace("%P", "*")
        .replace("%p", "*")
        .replace("%g", "*")
}

fn repo_path(relative: impl AsRef<Path>) -> PathBuf {
    env::current_dir()
        .expect("failed to read current directory")
        .join(relative)
}

fn resolve_path(path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_path(path)
    }
}

fn encrypted_name(name: &str) -> String {
    format!("{name}.asc")
}

fn encrypted_path_for_plaintext(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.asc", path.display()))
}

fn ensure_gitignore_entries(entries: &[String]) -> Result<()> {
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

fn prompt_filepath_pattern() -> Result<String> {
    Input::<String>::new()
        .with_prompt("solution filepath pattern (%p=problem, %P=4-digit problem, %g=problem group)")
        .validate_with(|input: &String| -> std::result::Result<(), String> {
            validate_filepath_pattern(input).map_err(|err| err.to_string())
        })
        .interact_text()
        .map_err(Into::into)
}

fn prompt_password(prompt: &str) -> Result<String> {
    PasswordInput::new()
        .with_prompt(prompt)
        .allow_empty_password(false)
        .interact()
        .map_err(Into::into)
}

fn prompt_new_password(prompt: &str) -> Result<String> {
    PasswordInput::new()
        .with_prompt(prompt)
        .with_confirmation("confirm password", "passwords mismatch")
        .allow_empty_password(false)
        .interact()
        .map_err(Into::into)
}

fn master_password_path() -> Result<PathBuf> {
    let project_dirs = ProjectDirs::from("", "", "eulervault")
        .ok_or_else(|| anyhow!("could not determine config directory"))?;
    let config_dir = project_dirs.config_dir();
    fs::create_dir_all(config_dir)?;
    Ok(config_dir.join("master_password.txt"))
}

fn write_master_password(password: &str) -> Result<()> {
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

fn read_master_password() -> Result<String> {
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

fn load_solutions_bytes(master_password: &str) -> Result<Vec<u8>> {
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

fn load_solutions_map(master_password: &str) -> Result<BTreeMap<u32, String>> {
    let bytes = load_solutions_bytes(master_password)?;
    if bytes.is_empty() {
        return Ok(BTreeMap::new());
    }
    parse_solutions(&String::from_utf8(bytes)?)
}

fn parse_solutions(content: &str) -> Result<BTreeMap<u32, String>> {
    let mut map = BTreeMap::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let (problem, solution) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid line {} in solutions.txt: {line}", idx + 1))?;
        let problem: u32 = problem
            .parse()
            .with_context(|| format!("invalid problem number in line {}", idx + 1))?;
        map.insert(problem, solution.to_string());
    }
    Ok(map)
}

fn serialize_solutions(map: &BTreeMap<u32, String>) -> String {
    let mut out = String::new();
    for (problem, solution) in map {
        out.push_str(&format!("{problem}={solution}\n"));
    }
    out
}

fn encrypt_bytes_to_path(plaintext: &[u8], password: &str, destination: &Path) -> Result<()> {
    let mut sink = Vec::<u8>::new();
    {
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).build()?;
        let message = Encryptor::with_passwords(
            message,
            std::iter::once(OpenPgpPassword::from(password.to_string())),
        )
        .symmetric_algo(SymmetricAlgorithm::AES256)
        .build()?;
        let mut literal = LiteralWriter::new(message).build()?;
        literal.write_all(plaintext)?;
        literal.finalize()?;
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(destination, sink)?;
    Ok(())
}

fn decrypt_bytes_from_path(source: &Path, password: &str) -> Result<Vec<u8>> {
    let ciphertext =
        fs::read(source).with_context(|| format!("failed to read {}", source.display()))?;
    let policy = StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(&ciphertext)?.with_policy(
        &policy,
        None,
        PasswordDecryptor::new(password),
    )?;
    let mut out = Vec::new();
    decryptor.read_to_end(&mut out)?;
    Ok(out)
}

struct PasswordDecryptor {
    password: OpenPgpPassword,
}

impl PasswordDecryptor {
    fn new(password: &str) -> Self {
        Self {
            password: OpenPgpPassword::from(password.to_string()),
        }
    }
}

impl VerificationHelper for PasswordDecryptor {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for PasswordDecryptor {
    fn decrypt(
        &mut self,
        _pkesks: &[openpgp::packet::PKESK],
        skesks: &[openpgp::packet::SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        for skesk in skesks {
            if let Ok((algo, sk)) = skesk.decrypt(&self.password)
                && decrypt(algo, &sk)
            {
                return Ok(None);
            }
        }
        Err(openpgp::Error::InvalidPassword.into())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::OpenOptions;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{render_placeholders, should_relock_solution_file};

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(path: PathBuf) -> Self {
            fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn set_modified_time(path: &std::path::Path, time: SystemTime) {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .expect("failed to open file for timestamp update");
        file.set_times(fs::FileTimes::new().set_modified(time))
            .expect("failed to set file timestamp");
    }

    #[test]
    fn render_placeholders_replaces_all_supported_tokens() {
        let rendered = render_placeholders("p=%p,P=%P,g=%g,percent=%%,other=%x,trailing=%", 123);
        assert_eq!(rendered, "p=123,P=0123,g=2,percent=%,other=%x,trailing=%");
    }

    #[test]
    fn should_relock_solution_file_uses_modification_times() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let temp_dir =
            TempDirGuard::new(std::env::temp_dir().join(format!("eulervault-test-{unique}")));

        let plaintext_path = temp_dir.path().join("solution.rs");
        let encrypted_path = temp_dir.path().join("solution.rs.asc");

        fs::write(&plaintext_path, "plain").expect("failed to write plaintext file");
        assert!(
            should_relock_solution_file(&plaintext_path, &encrypted_path)
                .expect("failed to evaluate relock condition"),
            "missing encrypted file should trigger relock"
        );

        fs::write(&encrypted_path, "cipher").expect("failed to write encrypted file");
        let base_time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        set_modified_time(&encrypted_path, base_time + Duration::from_secs(1));
        set_modified_time(&plaintext_path, base_time + Duration::from_secs(2));
        assert!(
            should_relock_solution_file(&plaintext_path, &encrypted_path)
                .expect("failed to evaluate relock condition"),
            "newer plaintext should trigger relock"
        );

        set_modified_time(&encrypted_path, base_time + Duration::from_secs(3));
        assert!(
            !should_relock_solution_file(&plaintext_path, &encrypted_path)
                .expect("failed to evaluate relock condition"),
            "newer encrypted file should skip relock"
        );
    }
}
