use crate::Mode;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Password, Select};
use std::fs;
use std::io;
use std::str::FromStr;

static THEME: std::sync::LazyLock<ColorfulTheme> = std::sync::LazyLock::new(ColorfulTheme::default);

/// Ask user to enter a value.
/// If `default` is [`Some`], suggest the value in the prompt.
pub fn ask_for_input<T>(message: &str, default: Option<T>) -> io::Result<T>
where
    T: Clone + FromStr + ToString,
    <T as FromStr>::Err: ToString,
{
    if crate::get_mode() == Mode::NonInteractive {
        return default
            .ok_or_else(|| io::Error::other("Expecting a user input in non-interactive mode"));
    }

    let mut input = Input::<T>::with_theme(&*THEME);
    input.with_prompt(message);
    if let Some(default) = default {
        input.show_default(true).default(default);
    }
    input.interact()
}

/// Ask if one wants to do something (yes/no)
pub fn ask_for_agreement(message: &str) -> io::Result<bool> {
    if crate::get_mode() == Mode::NonInteractive {
        return Err(io::Error::other(
            "Expecting a user input in non-interactive mode",
        ));
    }
    Confirm::with_theme(&*THEME)
        .with_prompt(message)
        .default(false)
        .show_default(true)
        .interact()
}

/// Ask user to enter a password in a secure way
pub fn ask_for_password(message: &str) -> io::Result<String> {
    if crate::get_mode() == Mode::NonInteractive {
        return Err(io::Error::other(
            "Expecting a user input in non-interactive mode",
        ));
    }
    Password::with_theme(&*THEME)
        .with_prompt(message)
        .interact()
}

/// Check if a file exists and if it does, ask if one wants to overwrite it
pub fn checked_overwrite(path: &str, message: &str) -> io::Result<bool> {
    if crate::get_mode() == Mode::NonInteractive
        || !fs::metadata(path).is_ok_and(|meta| meta.is_file())
    {
        return Ok(true);
    }
    ask_for_agreement(message)
}

/// Ask user to select a variant. Returns index of the selected variant.
pub fn select_index<S: Into<String>>(
    prompt: S,
    variants: &[&str],
    default: Option<usize>,
) -> io::Result<usize> {
    if variants.is_empty() || default.is_some_and(|index| index >= variants.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid selection options",
        ));
    }
    if crate::get_mode() == Mode::NonInteractive {
        return default
            .ok_or_else(|| io::Error::other("Expecting a user input in non-interactive mode"));
    }

    Select::with_theme(&*THEME)
        .with_prompt(prompt)
        .items(variants)
        .report(true)
        .default(default.unwrap_or_default())
        .interact_opt()?
        .ok_or_else(|| io::Error::new(io::ErrorKind::Interrupted, "None selected"))
}

/// Ask user to select a variant. Returns the selected variant.
pub fn select_variant<'a, S>(
    prompt: S,
    variants: &[&'a str],
    default: Option<usize>,
) -> io::Result<&'a str>
where
    S: Into<String>,
{
    let index = select_index(prompt, variants, default)?;
    variants
        .get(index)
        .copied()
        .ok_or_else(|| io::Error::other("Invalid selection index"))
}
