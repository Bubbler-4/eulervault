use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

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
        test: None,
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
    cmd_set_many(&[(problem, solution.to_string())])
}

pub(crate) fn cmd_set_many(problem_solutions: &[(u32, String)]) -> Result<()> {
    let settings = load_settings()?;
    let master_password = read_master_password()?;

    let mut solutions = load_solutions_map(&master_password)?;
    let mut seen_problems = BTreeSet::new();
    let mut updates = Vec::new();
    for (problem, solution) in problem_solutions {
        if seen_problems.insert(*problem) {
            solutions.insert(*problem, solution.clone());
            updates.push(*problem);
        }
    }

    // Preflight check: verify all solution files can be locked before committing
    for problem in &updates {
        let plaintext_path = render_solution_path(&settings.filepath, *problem)?;
        if !plaintext_path.exists() {
            bail!(
                "solution file does not exist for problem {}: {}",
                problem,
                plaintext_path.display()
            );
        }
        fs::read(&plaintext_path)
            .with_context(|| format!("failed to read {}", plaintext_path.display()))?;
    }

    let solutions_content = serialize_solutions(&solutions);
    let encrypted_solutions = repo_path(encrypted_name(SOLUTIONS_FILE));
    encrypt_bytes_to_path(
        solutions_content.as_bytes(),
        &master_password,
        &encrypted_solutions,
    )?;

    for problem in updates {
        let solution = solutions
            .get(&problem)
            .expect("updated problem must exist in solutions map");
        lock_solution_file(&settings, problem, solution)?;
    }
    Ok(())
}

pub(crate) fn cmd_update(problem: Option<u32>) -> Result<()> {
    let settings = load_settings()?;
    let master_password = read_master_password()?;
    let solutions = load_solutions_map(&master_password)?;

    if let Some(problem) = problem {
        let solution = solutions
            .get(&problem)
            .ok_or_else(|| anyhow::anyhow!("solution key is not set for problem {problem}"))?;
        lock_solution_file(&settings, problem, solution)?;
        return Ok(());
    }

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

pub(crate) fn cmd_migrate() -> Result<()> {
    let mut settings = load_settings()?;
    let old_filepath = settings.filepath.clone();
    let new_filepath = prompt_filepath_pattern()?;

    let planned_moves = collect_migration_moves(&old_filepath, &new_filepath)?;
    for (from, to) in &planned_moves {
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(from, to)
            .with_context(|| format!("failed to move {} -> {}", from.display(), to.display()))?;
    }

    settings.filepath = new_filepath;
    let settings_toml = toml::to_string_pretty(&settings)?;
    fs::write(repo_path(crate::SETTINGS_FILE), settings_toml)?;

    let gitignore_pattern = filepath_pattern_to_glob(&settings.filepath);
    ensure_gitignore_entries(&[gitignore_pattern])?;

    println!("migrated {} files", planned_moves.len());
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

pub(crate) fn cmd_test(problem: u32) -> Result<()> {
    let settings = load_settings()?;
    let test_command = settings
        .test
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("`test` is not configured in eulervault.toml"))?;
    let rendered = crate::template::render_placeholders(test_command, problem);
    let status = std::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" })
        .args(if cfg!(windows) {
            ["/C", &rendered]
        } else {
            ["-c", &rendered]
        })
        .status()
        .with_context(|| format!("failed to run test command: {rendered}"))?;
    if !status.success() {
        anyhow::bail!("test command exited with {}", status);
    }
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
    ensure_encrypted_file_is_newer(&plaintext_path, &encrypted_path)?;
    Ok(())
}

fn ensure_encrypted_file_is_newer(
    plaintext_path: &std::path::Path,
    encrypted_path: &std::path::Path,
) -> Result<()> {
    let plaintext_modified = fs::metadata(plaintext_path)
        .with_context(|| format!("failed to read metadata for {}", plaintext_path.display()))?
        .modified()
        .with_context(|| {
            format!(
                "failed to read modified time for {}",
                plaintext_path.display()
            )
        })?;
    let candidate = plaintext_modified
        .checked_add(Duration::from_secs(1))
        .unwrap_or_else(SystemTime::now);
    let target_modified = SystemTime::now().max(candidate);
    let encrypted_file = OpenOptions::new()
        .write(true)
        .open(encrypted_path)
        .with_context(|| format!("failed to open {}", encrypted_path.display()))?;
    encrypted_file
        .set_times(fs::FileTimes::new().set_modified(target_modified))
        .with_context(|| {
            format!(
                "failed to set modified time for {}",
                encrypted_path.display()
            )
        })?;
    Ok(())
}

fn collect_migration_moves(old_filepath: &str, new_filepath: &str) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut planned_moves = Vec::new();
    for problem in 1..=9999 {
        let old_plaintext = render_solution_path(old_filepath, problem)?;
        let new_plaintext = render_solution_path(new_filepath, problem)?;
        let old_encrypted = encrypted_path_for_plaintext(&old_plaintext);
        let new_encrypted = encrypted_path_for_plaintext(&new_plaintext);
        for (old_path, new_path) in [
            (old_plaintext.clone(), new_plaintext.clone()),
            (old_encrypted, new_encrypted),
        ] {
            if old_path == new_path || !old_path.exists() {
                continue;
            }
            planned_moves.push((old_path, new_path));
        }
    }

    validate_migration_moves(&planned_moves)?;
    Ok(planned_moves)
}

fn validate_migration_moves(moves: &[(PathBuf, PathBuf)]) -> Result<()> {
    let old_paths = moves
        .iter()
        .map(|(old_path, _)| old_path.clone())
        .collect::<BTreeSet<_>>();
    let mut new_to_old = BTreeMap::<PathBuf, PathBuf>::new();

    for (old_path, new_path) in moves {
        if new_path != old_path && old_paths.contains(new_path) {
            bail!(
                "cannot migrate: destination path {} conflicts with existing source path {}",
                new_path.display(),
                old_path.display()
            );
        }
        if let Some(conflicting_old) = new_to_old.get(new_path) {
            if conflicting_old != old_path {
                bail!(
                    "cannot migrate: destination path {} is targeted by both {} and {}",
                    new_path.display(),
                    conflicting_old.display(),
                    old_path.display()
                );
            }
        } else {
            new_to_old.insert(new_path.clone(), old_path.clone());
        }
        if new_path.exists() && new_path != old_path && !old_paths.contains(new_path) {
            bail!(
                "cannot migrate: destination path already exists: {}",
                new_path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{collect_migration_moves, lock_solution_file, validate_migration_moves};

    #[test]
    fn lock_solution_file_sets_encrypted_mtime_newer_than_plaintext() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let temp_dir = env::temp_dir().join(format!("eulervault-lock-mtime-{unique}"));
        fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

        // Use absolute path instead of changing cwd
        let absolute_pattern = temp_dir.join("solutions/%p.txt");
        let settings = crate::misc::Settings {
            filepath: absolute_pattern.to_string_lossy().to_string(),
            template: None,
            test: None,
        };
        let plaintext = temp_dir.join("solutions/1.txt");
        fs::create_dir_all(plaintext.parent().expect("missing parent"))
            .expect("failed to create parent directory");
        fs::write(&plaintext, b"content").expect("failed to write plaintext");
        let password = format!("password-{unique}");

        lock_solution_file(&settings, 1, &password).expect("failed to lock solution file");

        let encrypted = temp_dir.join("solutions/1.txt.asc");
        let plaintext_modified = fs::metadata(&plaintext)
            .expect("failed to read plaintext metadata")
            .modified()
            .expect("failed to read plaintext modified time");
        let encrypted_modified = fs::metadata(&encrypted)
            .expect("failed to read encrypted metadata")
            .modified()
            .expect("failed to read encrypted modified time");
        assert!(
            encrypted_modified > plaintext_modified,
            "encrypted file should be newer than plaintext"
        );
    }

    #[test]
    fn collect_migration_moves_ignores_unchanged_and_missing_paths() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let temp_dir = env::temp_dir().join(format!("eulervault-migrate-plan-{unique}"));
        fs::create_dir_all(&temp_dir).expect("failed to create temp dir");

        let old_pattern = temp_dir.join("old/%P.rs");
        let new_pattern = temp_dir.join("new/%P.rs");
        let unchanged_pattern = temp_dir.join("same/%P.rs");

        let old_plaintext = temp_dir.join("old/0001.rs");
        let old_encrypted = temp_dir.join("old/0001.rs.asc");
        fs::create_dir_all(old_plaintext.parent().expect("missing parent"))
            .expect("failed to create old parent dir");
        fs::write(&old_plaintext, "plain").expect("failed to write plaintext");
        fs::write(&old_encrypted, "cipher").expect("failed to write encrypted");

        let moves = collect_migration_moves(
            &old_pattern.to_string_lossy(),
            &new_pattern.to_string_lossy(),
        )
        .expect("failed to collect migration moves");
        assert_eq!(moves.len(), 2, "expected plaintext and encrypted moves");
        let new_plaintext = temp_dir.join("new/0001.rs");
        let new_encrypted = temp_dir.join("new/0001.rs.asc");
        assert!(moves.iter().any(|(from, to)| {
            from == &old_plaintext && to == &new_plaintext
        }));
        assert!(moves.iter().any(|(from, to)| {
            from == &old_encrypted && to == &new_encrypted
        }));

        let no_moves = collect_migration_moves(
            &unchanged_pattern.to_string_lossy(),
            &unchanged_pattern.to_string_lossy(),
        )
        .expect("failed to collect unchanged migration moves");
        assert!(no_moves.is_empty(), "unchanged pattern should produce no moves");
    }

    #[test]
    fn validate_migration_moves_rejects_source_destination_conflicts() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let temp_dir = env::temp_dir().join(format!("eulervault-migrate-conflict-{unique}"));
        let moves = vec![
            (
                temp_dir.join("old-a"),
                temp_dir.join("new-b"),
            ),
            (
                temp_dir.join("new-b"),
                temp_dir.join("new-c"),
            ),
        ];
        let err = validate_migration_moves(&moves).expect_err("expected conflict error");
        assert!(
            err.to_string().contains("conflicts with existing source path"),
            "unexpected error: {err:#}"
        );
    }
}
