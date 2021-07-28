use std::fmt;

/// An interface for prompting the user for input.
///
/// # Example
///
/// ```
/// use std::fmt;
/// use crypt_client::repl::ReplDriver;
///
/// struct DummyReplDriver;
///
/// impl ReplDriver for DummyReplDriver {
///     type Error = ();
///
///     fn print<T: fmt::Display>(&mut self, s: T) {
///         print!("{}", s);
///     }
///
///     fn eprint<T: fmt::Display>(&mut self, s: T) {
///         eprint!("{}", s);
///     }
///
///     fn clear_screen(&mut self) -> Result<(), Self::Error> {}
///
///     fn prompt_line(&mut self, prompt: &str) -> Result<String, Self::Error> {
///         Ok("Not gonna ask the user".to_string())
///     }
///
///     fn prompt_password(&mut self, prompt: &str) -> Result<String, Self::Error> {
///         Ok("Not gonna ask the user".to_string())
///     }
/// }
///
/// let mut driver = DummyReplDriver;
/// assert_eq!(driver.prompt_line("..."), Ok("Not gonna ask the user".to_string()));
/// assert_eq!(driver.prompt_password("..."), Ok("Not gonna ask the user".to_string()));
/// ```
///
pub trait ReplDriver {
    type Error;

    fn print<T: fmt::Display>(&mut self, s: T);

    fn eprint<T: fmt::Display>(&mut self, s: T);

    fn clear_screen(&mut self) -> Result<(), Self::Error>;

    fn prompt_line(&mut self, prompt: &str) -> Result<String, Self::Error>;

    fn prompt_password(&mut self, prompt: &str) -> Result<String, Self::Error>;
}

/// An implementation of [`ReplDriver`] using `rustyline`, `rpassword` and `clearscreen`.
///
/// # Example
///
/// ```no_run
/// use crypt_client::repl::{ReplDriver, RustyLineReplDriver};
///
/// let mut driver = RustyLineReplDriver::default();
/// assert_eq!(driver.prompt_line("...").unwrap(), "Some input".to_string());
/// assert_eq!(driver.prompt_password("...").unwrap(), "A password".to_string());
/// ```
pub struct RustyLineReplDriver {
    rl: rustyline::Editor<()>,
}

impl Default for RustyLineReplDriver {
    fn default() -> Self {
        let config = rustyline::Config::builder()
            .max_history_size(50)
            .history_ignore_dups(true)
            .history_ignore_space(true)
            .completion_type(rustyline::CompletionType::Circular)
            .completion_prompt_limit(10)
            .edit_mode(rustyline::EditMode::Vi)
            .auto_add_history(false)
            .bell_style(rustyline::config::BellStyle::Visible)
            .color_mode(rustyline::ColorMode::Enabled)
            .tab_stop(4)
            .check_cursor_position(true)
            .indent_size(2)
            .bracketed_paste(true)
            .build();
        Self { rl: rustyline::Editor::with_config(config) }
    }
}

#[derive(Debug)]
pub enum RustyLineDriverError {
    RustyLine(rustyline::error::ReadlineError),
    ClearScreen(clearscreen::Error),
    Io(std::io::Error),
}

impl fmt::Display for RustyLineDriverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::RustyLine(error) => write!(f, "{}", error),
            Self::ClearScreen(error) => write!(f, "{:?}", error),
            Self::Io(error) => write!(f, "{}", error)
        }
    }
}

impl std::error::Error for RustyLineDriverError {}

impl From<rustyline::error::ReadlineError> for RustyLineDriverError {
    fn from(error: rustyline::error::ReadlineError) -> Self {
        Self::RustyLine(error)
    }
}

impl From<clearscreen::Error> for RustyLineDriverError {
    fn from(error: clearscreen::Error) -> Self {
        Self::ClearScreen(error)
    }
}

impl From<std::io::Error> for RustyLineDriverError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl ReplDriver for RustyLineReplDriver {
    type Error = RustyLineDriverError;

    fn print<T: fmt::Display>(&mut self, s: T) {
        print!("{}", s);
    }

    fn eprint<T: fmt::Display>(&mut self, s: T) {
        eprint!("{}", s);
    }

    fn clear_screen(&mut self) -> Result<(), Self::Error> {
        clearscreen::clear()?;
        Ok(())
    }

    fn prompt_line(&mut self, prompt: &str) -> Result<String, Self::Error> {
        let line = self.rl.readline(prompt)?;
        self.rl.add_history_entry(line.as_str());
        Ok(line)
    }

    fn prompt_password(&mut self, prompt: &str) -> Result<String, Self::Error> {
        let password = rpassword::read_password_from_tty(Some(prompt))?;
        Ok(password)
    }
}
