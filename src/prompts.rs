use anyhow::Result;
use dialoguer::{Input, Password as PasswordInput};

use crate::template::validate_filepath_pattern;

pub(crate) fn prompt_filepath_pattern() -> Result<String> {
    Input::<String>::new()
        .with_prompt("solution filepath pattern (%p=problem, %P=4-digit problem, %g=problem group)")
        .validate_with(|input: &String| -> std::result::Result<(), String> {
            validate_filepath_pattern(input).map_err(|err| err.to_string())
        })
        .interact_text()
        .map_err(Into::into)
}

pub(crate) fn prompt_password(prompt: &str) -> Result<String> {
    PasswordInput::new()
        .with_prompt(prompt)
        .allow_empty_password(false)
        .interact()
        .map_err(Into::into)
}

pub(crate) fn prompt_new_password(prompt: &str) -> Result<String> {
    PasswordInput::new()
        .with_prompt(prompt)
        .with_confirmation("confirm password", "passwords mismatch")
        .allow_empty_password(false)
        .interact()
        .map_err(Into::into)
}
