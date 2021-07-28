use crate::repl::ReplDriver;
use std::fmt;

/// A mock implementation of [`ReplDriver`].
///
/// # Example
///
/// Echo mode:
///
/// ```
/// use crypt_client::repl::{ReplDriver, MockDriver};
///
/// let mut driver = MockDriver::Echo;
/// assert_eq!(driver.prompt_line("..."), Ok("...".to_string()));
/// assert_eq!(driver.prompt_password("..."), Ok("...".to_string()));
/// ```
///
/// Single mock mode:
///
/// ```
/// use crypt_client::repl::{ReplDriver, MockDriver};
///
/// let mut driver = MockDriver::MockDefault("test".to_string());
/// assert_eq!(driver.prompt_line("..."), Ok("test".to_string()));
/// assert_eq!(driver.prompt_password("..."), Ok("test".to_string()));
/// ```
///
/// Individual mock mode:
///
/// ```
/// use crypt_client::repl::{ReplDriver, MockDriver};
///
/// let mut driver = MockDriver::MockAll { prompt: "This is a prompt".to_string(), password: "This is a password".to_string() };
/// assert_eq!(driver.prompt_line("..."), Ok("This is a prompt".to_string()));
/// assert_eq!(driver.prompt_password("..."), Ok("This is a password".to_string()));
/// ```
///
#[derive(Debug, Clone)]
pub enum MockDriver {
    Echo,
    MockDefault(String),
    MockAll {
        prompt: String,
        password: String,
    },
}

impl ReplDriver for MockDriver {
    type Error = ();

    fn print<T: fmt::Display>(&mut self, _s: T) {}

    fn eprint<T: fmt::Display>(&mut self, _s: T) {}

    fn clear_screen(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn prompt_line(&mut self, prompt: &str) -> Result<String, Self::Error> {
        match self {
            Self::Echo => Ok(prompt.to_string()),
            Self::MockDefault(prompt) | Self::MockAll { prompt, .. } => Ok(prompt.clone())
        }
    }

    fn prompt_password(&mut self, prompt: &str) -> Result<String, Self::Error> {
        match self {
            Self::Echo => Ok(prompt.to_string()),
            Self::MockDefault(prompt) => Ok(prompt.clone()),
            Self::MockAll { password, .. } => Ok(password.clone())
        }
    }
}
