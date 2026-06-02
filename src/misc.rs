use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Settings {
    pub(crate) filepath: String,
    pub(crate) template: Option<String>,
}

pub(crate) fn parse_solutions(content: &str) -> Result<BTreeMap<u32, String>> {
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

pub(crate) fn serialize_solutions(map: &BTreeMap<u32, String>) -> String {
    let mut out = String::new();
    for (problem, solution) in map {
        out.push_str(&format!("{problem}={solution}\n"));
    }
    out
}
