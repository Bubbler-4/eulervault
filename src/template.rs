use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::filesystem::{repo_path, resolve_path};

pub(crate) fn validate_filepath_pattern(pattern: &str) -> Result<()> {
    if !pattern.contains("%p") && !pattern.contains("%P") {
        bail!("filepath pattern must contain %p or %P");
    }
    Ok(())
}

pub(crate) fn render_solution_path(pattern: &str, problem: u32) -> Result<PathBuf> {
    validate_filepath_pattern(pattern)?;
    let rendered = render_placeholders(pattern, problem);
    Ok(repo_path(&rendered))
}

pub(crate) fn render_placeholders(input: &str, problem: u32) -> String {
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

pub(crate) fn load_template_content(template_path: &str, problem: u32) -> Result<Vec<u8>> {
    let resolved_path = resolve_path(template_path);
    let template = fs::read_to_string(&resolved_path).with_context(|| {
        format!(
            "failed to read template file configured as {template_path} (resolved to {}); ensure the file exists and is readable",
            resolved_path.display()
        )
    })?;
    Ok(render_placeholders(&template, problem).into_bytes())
}

pub(crate) fn filepath_pattern_to_glob(pattern: &str) -> String {
    pattern
        .replace("%P", "*")
        .replace("%p", "*")
        .replace("%g", "*")
}
