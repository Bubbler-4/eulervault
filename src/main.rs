use anyhow::{Result, anyhow};
use clap::{ArgAction, Parser, Subcommand};

mod command_handlers;
mod crypto;
mod filesystem;
mod misc;
mod prompts;
mod template;

pub(crate) const SETTINGS_FILE: &str = "eulervault.toml";
pub(crate) const SOLUTIONS_FILE: &str = "solutions.txt";

#[derive(Parser)]
#[command(name = "eulervault")]
#[command(about = "Encrypt and share Project Euler solutions")]
struct Cli {
    #[arg(long, value_parser = parse_set_pair, action = ArgAction::Append)]
    set: Vec<(u32, String)>,

    #[command(subcommand)]
    command: Option<Commands>,
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
    Test { problem: u32 },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    if !cli.set.is_empty() {
        if cli.command.is_some() {
            return Err(anyhow!(
                "`--set` cannot be used together with subcommands; use either `--set` inputs or a subcommand"
            ));
        }
        return command_handlers::cmd_set_many(&cli.set);
    }

    match cli.command.ok_or_else(|| {
        anyhow!("no command provided; use a subcommand or one or more `--set` options")
    })? {
        Commands::Init => command_handlers::cmd_init(),
        Commands::New { problem } => command_handlers::cmd_new(problem),
        Commands::Set { problem, solution } => command_handlers::cmd_set(problem, &solution),
        Commands::Update => command_handlers::cmd_update(),
        Commands::Master => command_handlers::cmd_master(),
        Commands::ChangeMasterPassword => command_handlers::cmd_change_master_password(),
        Commands::Unlock { problem, solution } => command_handlers::cmd_unlock(problem, &solution),
        Commands::Test { problem } => command_handlers::cmd_test(problem),
    }
}

fn parse_set_pair(value: &str) -> Result<(u32, String), String> {
    let (problem_raw, solution) = value
        .split_once('=')
        .ok_or_else(|| format!("invalid --set value `{value}`: expected problem=solution"))?;
    if solution.is_empty() {
        return Err(format!(
            "invalid --set value `{value}`: solution cannot be empty"
        ));
    }

    let problem = problem_raw.parse::<u32>().map_err(|_| {
        format!("invalid --set value `{value}`: problem must be a positive integer")
    })?;
    if problem == 0 {
        return Err(format!(
            "invalid --set value `{value}`: problem must be a positive integer"
        ));
    }
    Ok((problem, solution.to_string()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::OpenOptions;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::filesystem::should_relock_solution_file;
    use crate::template::render_placeholders;

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

    #[test]
    fn parse_set_pair_accepts_problem_solution() {
        assert_eq!(
            super::parse_set_pair("123=42").expect("failed to parse set pair"),
            (123, "42".to_string())
        );
    }

    #[test]
    fn parse_set_pair_rejects_invalid_inputs() {
        assert!(super::parse_set_pair("123").is_err());
        assert!(super::parse_set_pair("0=42").is_err());
        assert!(super::parse_set_pair("abc=42").is_err());
        assert!(super::parse_set_pair("1=").is_err());
    }
}
