use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};

use openpgp::cert::prelude::*;
use openpgp::constants::SymmetricAlgorithm;
use openpgp::crypto::{Password, SessionKey};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message};
use openpgp::types::CipherSuite;

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
    Master,
    ChangeMasterPassword,
    Unlock { problem: u32, solution: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct Settings {
    filepath: String,
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
        Commands::Master => cmd_master(),
        Commands::ChangeMasterPassword => cmd_change_master_password(),
        Commands::Unlock { problem, solution } => cmd_unlock(problem, &solution),
    }
}

fn cmd_init() -> Result<()> {
    let filepath = prompt("solution filepath pattern: ")?;
    validate_filepath_pattern(&filepath)?;
    let master_password = prompt("master password: ")?;
    if master_password.is_empty() {
        bail!("master password must not be empty");
    }

    let settings = Settings { filepath };
    let settings_toml = toml::to_string_pretty(&settings)?;
    fs::write(repo_path(SETTINGS_FILE), settings_toml)?;

    write_master_password(&master_password)?;

    let gitignore_pattern = filepath_pattern_to_glob(&settings.filepath);
    ensure_gitignore_entries(&[SOLUTIONS_FILE.to_string(), gitignore_pattern])?;

    let encrypted_solutions = repo_path(&encrypted_name(SOLUTIONS_FILE));
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
    fs::write(&path, [])?;
    println!("{}", path.display());
    Ok(())
}

fn cmd_set(problem: u32, solution: &str) -> Result<()> {
    let settings = load_settings()?;
    let master_password = read_master_password()?;

    let mut solutions = load_solutions_map(&master_password)?;
    solutions.insert(problem, solution.to_string());
    let solutions_content = serialize_solutions(&solutions);
    let encrypted_solutions = repo_path(&encrypted_name(SOLUTIONS_FILE));
    encrypt_bytes_to_path(
        solutions_content.as_bytes(),
        &master_password,
        &encrypted_solutions,
    )?;
    remove_if_exists(&repo_path(SOLUTIONS_FILE))?;

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
    remove_if_exists(&plaintext_path)?;
    Ok(())
}

fn cmd_master() -> Result<()> {
    let settings = load_settings()?;
    let password = prompt("master password: ")?;
    if password.is_empty() {
        bail!("master password must not be empty");
    }

    let encrypted_solutions = repo_path(&encrypted_name(SOLUTIONS_FILE));
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
    let new_password = prompt("new master password: ")?;
    if new_password.is_empty() {
        bail!("new master password must not be empty");
    }

    let solutions_bytes = load_solutions_bytes(&old_password)?;
    let encrypted_solutions = repo_path(&encrypted_name(SOLUTIONS_FILE));
    encrypt_bytes_to_path(&solutions_bytes, &new_password, &encrypted_solutions)?;
    remove_if_exists(&repo_path(SOLUTIONS_FILE))?;
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
    let grid = (problem - 1) / 100 + 1;
    let rendered = pattern
        .replace("%P", &format!("{problem:04}"))
        .replace("%p", &problem.to_string())
        .replace("%g", &grid.to_string());
    Ok(repo_path(&rendered))
}

fn filepath_pattern_to_glob(pattern: &str) -> String {
    pattern
        .replace("%P", "*")
        .replace("%p", "*")
        .replace("%g", "*")
}

fn repo_path(relative: &str) -> PathBuf {
    env::current_dir()
        .expect("failed to read current directory")
        .join(relative)
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

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn master_password_path() -> Result<PathBuf> {
    let project_dirs = ProjectDirs::from("", "", "eulervault")
        .ok_or_else(|| anyhow!("could not determine config directory"))?;
    let config_dir = project_dirs.config_dir();
    fs::create_dir_all(config_dir)?;
    Ok(config_dir.join("master_password.txt"))
}

fn write_master_password(password: &str) -> Result<()> {
    fs::write(master_password_path()?, password)?;
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
    let encrypted = repo_path(&encrypted_name(SOLUTIONS_FILE));
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

fn remove_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn encrypt_bytes_to_path(plaintext: &[u8], password: &str, destination: &Path) -> Result<()> {
    let mut sink = Vec::<u8>::new();
    {
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).build()?;
        let message = Encryptor2::with_passwords(
            message,
            std::iter::once(Password::from(password.to_string())),
        )
        .cipher_suite(CipherSuite::P256)
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
    let mut decryptor = DecryptorBuilder::from_bytes(&ciphertext)?
        .with_policy(&policy, None, PasswordDecryptor::new(password))?;
    let mut out = Vec::new();
    decryptor.read_to_end(&mut out)?;
    Ok(out)
}

struct PasswordDecryptor {
    password: Password,
}

impl PasswordDecryptor {
    fn new(password: &str) -> Self {
        Self {
            password: Password::from(password.to_string()),
        }
    }
}

impl VerificationHelper for PasswordDecryptor {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
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
        mut decrypt: impl FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>> {
        for skesk in skesks {
            if let Ok((algo, sk)) = skesk.decrypt(&self.password) {
                if decrypt(algo, &sk) {
                    return Ok(None);
                }
            }
        }
        Err(openpgp::Error::InvalidPassword.into())
    }
}
