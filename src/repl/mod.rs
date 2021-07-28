use crate::file::{UnlockedFile, CryptFile, CryptFileError};
use std::convert::TryFrom;
use std::collections::HashMap;

mod driver;
mod parser;

#[cfg(feature = "dummy-drivers")]
mod dummy_drivers;

pub use driver::*;
pub use parser::*;

#[cfg(feature = "dummy-drivers")]
pub use dummy_drivers::*;
use std::path::PathBuf;

pub const USAGE_TEXT: &str = "Crypt REPL usage:
| Command                              | Description                                                   |
|--------------------------------------|---------------------------------------------------------------|
| clear                                | Clear the screen                                              |
| help                                 | Print this help dialog                                        |
| exit <code> [--no-save]              | Exit the REPL                                                 |
| crypt list                           | List all unsaved crypts                                       |
| crypt unlock <alias> <filepath>      | Read and decrypt the specified file using the specified alias |
| crypt lock <alias>                   | Encrypt and write the file mapped to the specified alias      |
| crypt data <alias> list              | List all keys                                                 |
| crypt data <alias> get <key>         | Print the value of the specified key                          |
| crypt data <alias> set <key> <value> | Set the specified key/value pair                              |
| crypt data <alias> delete <key>      | Delete the specified key                                      |
";

/// Uses a [`ReplDriver`] to prompt for input, parse that input into a [`ReplCommand`], act on
/// that command and output the result.
pub struct Repl<D> {
    driver: D,
    open_files: HashMap<String, (String, CryptFile<UnlockedFile>)>,
}

impl<D> Repl<D> {
    fn unlock_file(&mut self, alias: String, filepath: impl Into<PathBuf>, password: String) -> Result<(), CryptFileError> {
        let file = CryptFile::new(filepath.into());
        let file = file.unlock(password.as_str())?;
        self.open_files.insert(alias, (password, file));
        Ok(())
    }

    fn lock_file(&mut self, alias: impl AsRef<str>) -> Result<bool, CryptFileError> {
        let alias = alias.as_ref();
        let (password, file) = match self.open_files.remove(alias) {
            Some(file) => file,
            None => {
                return Ok(false);
            }
        };
        return match file.lock(password.as_str()) {
            Ok(_) => Ok(true),
            Err((file, error)) => {
                self.open_files.insert(alias.to_string(), (password, file));
                Err(error)
            }
        };
    }

    fn lock_all_files(&mut self) -> Result<(), HashMap<String, CryptFileError>> {
        let (error_files, errors) = std::mem::take(&mut self.open_files)
            .into_iter()
            .filter_map(|(alias, (password, file))| match file.lock(password.as_str()) {
                Ok(_) => None,
                Err((file, error)) => Some((alias, password, file, error))
            })
            .fold((HashMap::new(), HashMap::new()), |mut acc, (alias, password, file, error)| {
                acc.0.insert(alias.clone(), (password, file));
                acc.1.insert(alias, error);
                acc
            });
        if error_files.is_empty() {
            Ok(())
        } else {
            self.open_files = error_files;
            Err(errors)
        }
    }
}

impl<D: ReplDriver> Repl<D> {
    /// Creates a new [`Repl`] with `driver`.
    ///
    /// # Example
    ///
    /// ```
    /// use crypt_client::repl::{ReplDriver, MockDriver, Repl};
    ///
    /// let repl = Repl::new(MockDriver::Echo);
    /// ```
    ///
    pub fn new(driver: D) -> Self {
        Self { driver, open_files: HashMap::new() }
    }

    /// Execute a command.
    ///
    /// # Example
    ///
    /// ```
    /// use crypt_client::repl::{ReplDriver, MockDriver, Repl, ReplCommand};
    ///
    /// let mut repl = Repl::new(MockDriver::Echo);
    /// let command = ReplCommand::ClearScreen;
    /// repl.execute_command(&command).unwrap();
    /// ```
    ///
    pub fn execute_command(&mut self, command: &ReplCommand) -> Result<(), D::Error> {
        println!("Executing command: {:?}", command);
        match command {
            ReplCommand::ClearScreen => {
                self.driver.clear_screen()?;
            }
            ReplCommand::Help => {
                self.print_usage();
            }
            ReplCommand::Exit(ReplExitCommand { no_save, .. }) => {
                if !*no_save && !self.open_files.is_empty() {
                    self.driver.print(format!("Attempting to lock {} open files\n", self.open_files.len()));
                    if let Err(errors) = self.lock_all_files() {
                        self.driver.eprint(format!("Failed to lock {} files:\n", errors.len()));
                        for (alias, error) in errors {
                            self.driver.eprint(format!("  {}: {}\n", alias, error));
                        }
                    }
                }
            }
            ReplCommand::Crypt(ReplCryptCommand::List) => {
                self.driver.print(format!("{} files are currently open:\n", self.open_files.len()));
                for (alias, (_, file)) in self.open_files.iter() {
                    self.driver.eprint(format!("  {}: {}\n", alias, file.filepath().display()));
                }
            }
            ReplCommand::Crypt(ReplCryptCommand::Unlock { alias, filepath }) => {
                let password = self.driver.prompt_password("Enter password for file: ")?;
                if let Err(error) = self.unlock_file(alias.to_string(), filepath.to_string(), password) {
                    self.driver.eprint(format!("Failed to unlock file: {}\n", error));
                }
            }
            ReplCommand::Crypt(ReplCryptCommand::Lock { alias }) => {
                self.driver.print("Attempting to lock file...\n");
                if let Err(error) = self.lock_file(alias) {
                    self.driver.eprint(format!("Failed to lock file: {}\n", error));
                }
            }
            ReplCommand::Crypt(ReplCryptCommand::Data { alias, cmd }) => {
                match cmd {
                    ReplMapCommand::List => match self.open_files.get((*alias).as_ref()) {
                        Some((_, file)) => {
                            self.driver.print("Listing data:\n");
                            for (key, value) in file.data() {
                                self.driver.print(format!("  {}={}\n", key, value));
                            }
                        }
                        None => self.driver.eprint(format!("No files are open with the alias: {}\n", alias))
                    },
                    ReplMapCommand::Get { key } => match self.open_files.get((*alias).as_ref()) {
                        Some((_, file)) => {
                            match file.data().get((*key).as_ref()) {
                                Some(value) => self.driver.print(format!("{}\n", value)),
                                None => self.driver.eprint("Key doesn't exist\n")
                            }
                        }
                        None => self.driver.eprint(format!("No files are open with the alias: {}\n", alias))
                    },
                    ReplMapCommand::Set {key, value} => match self.open_files.get_mut((*alias).as_ref()) {
                        Some((_, file)) => {
                            file.data_mut().insert(key.to_string(), value.to_string());
                        }
                        None => self.driver.eprint(format!("No files are open with the alias: {}\n", alias))
                    },
                    ReplMapCommand::Delete {key} => match self.open_files.get_mut((*alias).as_ref()) {
                        Some((_, file)) => {
                            file.data_mut().remove((*key).as_ref());
                        }
                        None => self.driver.eprint(format!("No files are open with the alias: {}\n", alias))
                    }
                }
            }
        }
        Ok(())
    }

    /// Prompt for, parse, and execute a single command.
    ///
    /// If the command entered is `exit <code> [--no-save]`, all open files will be saved unless
    /// the `--no-save` flag is present, then the parsed [`ReplExitCommand`] will be returned.
    ///
    /// All other commands will be executed internally and [`None`] will be returned.
    ///
    /// # Example
    ///
    /// ```
    /// use crypt_client::repl::{ReplDriver, MockDriver, Repl, ReplExitCommand};
    ///
    /// let mut repl = Repl::new(MockDriver::MockDefault("exit 1 --no-save".to_string()));
    /// if let Some(ReplExitCommand { code, no_save }) = repl.tick().unwrap() {
    ///     print!("Exiting with code {}, ", code);
    ///     if no_save {
    ///         println!("without saving");
    ///     } else {
    ///         println!("after saving");
    ///         // Code to save anything that needs saving
    ///     }
    ///     // std::process::exit(code);
    /// }
    /// ```
    ///
    pub fn tick(&mut self) -> Result<Option<ReplExitCommand>, D::Error> {
        let command_str = self.driver.prompt_line("> ")?;
        let command = match ReplCommand::try_from(command_str.as_str()) {
            Ok(command) => command,
            Err(error) => {
                let context = nom::error::convert_error(command_str.as_str(), error);
                let error_message = format!("Invalid command:\n{}\n", context);
                self.driver.eprint(error_message);
                return Ok(None);
            }
        };
        self.execute_command(&command)?;
        match command {
            ReplCommand::Exit(exit_command) => Ok(Some(exit_command)),
            _ => Ok(None)
        }
    }

    /// Calls [`tick()`] in a loop until it returns a [`ReplExitCommand`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use crypt_client::repl::{ReplDriver, MockDriver, Repl, ReplExitCommand};
    ///
    /// let mut repl = Repl::new(MockDriver::MockDefault("exit 1 --no-save".to_string()));
    /// let ReplExitCommand { code, no_save } = repl.run().unwrap();
    /// print!("Exiting with code {}, ", code);
    /// if no_save {
    ///     println!("without saving");
    /// } else {
    ///     println!("after saving");
    ///     // Code to save anything that needs saving
    /// }
    /// std::process::exit(code);
    /// ```
    ///
    pub fn run(&mut self) -> Result<ReplExitCommand, D::Error> {
        loop {
            if let Some(exit_command) = self.tick()? {
                return Ok(exit_command);
            }
        }
    }

    /// Calls [`tick()`] in a loop until it returns a [`ReplExitCommand`], then calls
    /// [`std::process:exit`] with the exit code.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use crypt_client::repl::{ReplDriver, MockDriver, Repl};
    ///
    /// let mut repl = Repl::new(MockDriver::MockDefault("exit 1 --no-save".to_string()));
    /// repl.run_loop().unwrap();
    /// ```
    ///
    pub fn run_loop(&mut self) -> Result<!, D::Error> {
        let ReplExitCommand { code, .. } = self.run()?;
        std::process::exit(code);
    }

    /// Prints REPL commands and usage.
    pub fn print_usage(&mut self) {
        self.driver.print(USAGE_TEXT);
    }
}
