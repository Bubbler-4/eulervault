use std::fs;

use anyhow::{Context, Result, bail};

use crate::SOLUTIONS_FILE;
use crate::crypto::{decrypt_bytes_from_path, encrypt_bytes_to_path};
use crate::filesystem::{
    encrypted_name, encrypted_path_for_plaintext, ensure_gitignore_entries, load_settings,
    load_solutions_bytes, load_solutions_map, read_master_password, repo_path,
    should_relock_solution_file, write_master_password,
};
use crate::misc::{parse_solutions, serialize_solutions};
use crate::prompts::{prompt_filepath_pattern, prompt_new_password, prompt_password};
use crate::template::{filepath_pattern_to_glob, load_template_content, render_solution_path};

pub(crate) fn cmd_init() -> Result<()> {
    if repo_path(crate::SETTINGS_FILE).exists() {
        bail!("Remove eulervault.toml to restart the init process");
    }

    let filepath = prompt_filepath_pattern()?;
    let master_password = prompt_new_password("master password")?;

    let settings = crate::misc::Settings {
        filepath,
        template: None,
    };
    let settings_toml = toml::to_string_pretty(&settings)?;
    fs::write(repo_path(crate::SETTINGS_FILE), settings_toml)?;

    write_master_password(&master_password)?;

    let gitignore_pattern = filepath_pattern_to_glob(&settings.filepath);
    ensure_gitignore_entries(&[SOLUTIONS_FILE.to_string(), gitignore_pattern])?;

    let encrypted_solutions = repo_path(encrypted_name(SOLUTIONS_FILE));
    if !encrypted_solutions.exists() {
        encrypt_bytes_to_path(&[], &master_password, &encrypted_solutions)?;
    }

    Ok(())
}

pub(crate) fn cmd_new(problem: u32) -> Result<()> {
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

pub(crate) fn cmd_set(problem: u32, solution: &str) -> Result<()> {
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

pub(crate) fn cmd_update() -> Result<()> {
    let settings = load_settings()?;
    let master_password = read_master_password()?;
    let solutions = load_solutions_map(&master_password)?;
    for (problem, solution) in solutions {
        let plaintext_path = render_solution_path(&settings.filepath, problem)?;
        let encrypted_path = encrypted_path_for_plaintext(&plaintext_path);
        if should_relock_solution_file(&plaintext_path, &encrypted_path)? {
            lock_solution_file(&settings, problem, &solution)?;
        }
    }
    Ok(())
}

pub(crate) fn cmd_master() -> Result<()> {
    let settings = load_settings()?;
    let password = prompt_password("master password")?;

    let encrypted_solutions = repo_path(encrypted_name(SOLUTIONS_FILE));
    let decrypted = decrypt_bytes_from_path(&encrypted_solutions, &password)?;
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

pub(crate) fn cmd_change_master_password() -> Result<()> {
    let old_password = read_master_password()?;
    let new_password = prompt_new_password("new master password")?;

    let solutions_bytes = load_solutions_bytes(&old_password)?;
    let encrypted_solutions = repo_path(encrypted_name(SOLUTIONS_FILE));
    encrypt_bytes_to_path(&solutions_bytes, &new_password, &encrypted_solutions)?;
    write_master_password(&new_password)?;
    Ok(())
}

pub(crate) fn cmd_unlock(problem: u32, solution: &str) -> Result<()> {
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

fn lock_solution_file(
    settings: &crate::misc::Settings,
    problem: u32,
    solution: &str,
) -> Result<()> {
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
