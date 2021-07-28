use std::borrow::Cow;
use std::convert::TryFrom;
use nom::{IResult, Err};
use nom::bytes::complete::{tag, take_till, take};
use nom::error::{ParseError, VerboseError, ContextError, context};
use nom::sequence::{delimited, preceded, terminated, tuple, separated_pair};
use nom::character::complete::{char, digit1, none_of, multispace1};
use nom::branch::alt;
use nom::combinator::{value, map, opt};
use nom::multi::fold_many0;

/// Parse a quoted string.
///
/// # Example
///
/// ```
/// use std::borrow::Cow;
/// use nom::error::{VerboseError, convert_error};
/// use crypt_client::repl::parse_quoted_str;
///
/// let data = "'This is a quoted string. Look I can escape \\''";
/// let result = parse_quoted_str::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", Cow::Borrowed("This is a quoted string. Look I can escape '"))));
/// ```
///
pub fn parse_quoted_str<'a, E: ParseError<&'a str> + ContextError<&'a str>>(input: &'a str) -> IResult<&'a str, Cow<'a, str>, E> {
    #[inline]
    fn parse_quoted_inner<'a, E: ParseError<&'a str> + ContextError<&'a str>>(input: &'a str) -> IResult<&'a str, String, E> {
        context(
            "quoted string inner",
            fold_many0(
                tuple((none_of("\\'"), opt(preceded(char('\\'), take(1_usize))))),
                String::with_capacity(input.len()),
                |mut acc, (s, escaped)| {
                    acc.push(s);
                    if let Some(escaped) = escaped {
                        acc.push_str(escaped);
                    }
                    acc
                },
            ),
        )(input)
    }

    let esc_or_empty = alt((map(parse_quoted_inner, Cow::Owned), map(tag(""), Cow::Borrowed)));
    context(
        "quoted string",
        delimited(tag("'"), esc_or_empty, tag("'")),
    )(input)
}

/// Parse an unquoted string. Parsing ends at the first space (`' '`).
///
/// # Example
///
/// ```
/// use nom::error::VerboseError;
/// use crypt_client::repl::parse_unquoted_str;
///
/// let data = "This_is_an_unquoted_string Whoops!";
/// let result = parse_unquoted_str::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok((" Whoops!", "This_is_an_unquoted_string")));
/// ```
///
pub fn parse_unquoted_str<'a, E: ParseError<&'a str> + ContextError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    context(
        "unquoted string",
        take_till(|c| c == ' '),
    )(input)
}

/// Parse a quoted or unquoted string.
///
/// # Example
///
/// ```
/// use std::borrow::Cow;
/// use nom::error::VerboseError;
/// use crypt_client::repl::parse_str;
///
/// let data = "'This is a quoted string. Look I can escape \\''";
/// let result = parse_str::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", Cow::Borrowed("This is a quoted string. Look I can escape '"))));
///
/// let data = "This_is_an_unquoted_string Whoops!";
/// let result = parse_str::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok((" Whoops!", Cow::Borrowed("This_is_an_unquoted_string"))));
/// ```
///
pub fn parse_str<'a, E: ParseError<&'a str> + ContextError<&'a str>>(input: &'a str) -> IResult<&'a str, Cow<'a, str>, E> {
    context(
        "string",
        alt((
            parse_quoted_str,
            map(parse_unquoted_str, Cow::Borrowed)
        )),
    )(input)
}

/// Parse an integer into a i32 value.
///
/// # Example
///
/// ```
/// use nom::error::VerboseError;
/// use crypt_client::repl::parse_i32;
///
/// let data = "123 ...";
/// let result = parse_i32::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok((" ...", 123)));
/// ```
///
pub fn parse_i32<'a, E: ParseError<&'a str> + ContextError<&'a str>>(input: &'a str) -> IResult<&'a str, i32, E> {
    context(
        "number",
        |input: &'a str| {
            let (next, num_str) = digit1(input)?;
            match num_str.parse::<i32>() {
                Ok(result) => Ok((next, result)),
                Err(_) => Err(nom::Err::Error(E::from_error_kind(input, nom::error::ErrorKind::Digit)))
            }
        },
    )(input)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReplMapCommand<'a> {
    /// ```list```
    List,
    /// ```get <key>```
    Get {
        key: Cow<'a, str>,
    },
    /// ```set <key> <value>```
    Set {
        key: Cow<'a, str>,
        value: Cow<'a, str>,
    },
    /// ```delete <key>```
    Delete {
        key: Cow<'a, str>,
    },
}

/// Parse a map command.
///
/// # Example
///
/// ```
/// use std::borrow::Cow;
/// use nom::error::VerboseError;
/// use crypt_client::repl::{ReplMapCommand, parse_map_command};
///
/// let data = "list ...";
/// let result = parse_map_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok((" ...", ReplMapCommand::List)));
///
/// let data = "get <key>";
/// let result = parse_map_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplMapCommand::Get { key: Cow::Borrowed("<key>") })));
///
/// let data = "set <key> <value>";
/// let result = parse_map_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplMapCommand::Set {
///     key: Cow::Borrowed("<key>"),
///     value: Cow::Borrowed("<value>")
/// })));
///
/// let data = "delete <key>";
/// let result = parse_map_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplMapCommand::Delete { key: Cow::Borrowed("<key>") })));
/// ```
///
pub fn parse_map_command<'a, E>(input: &'a str) -> IResult<&'a str, ReplMapCommand<'a>, E>
    where E: ParseError<&'a str> + ContextError<&'a str>
{
    context(
        "map command",
        alt((
            value(ReplMapCommand::List, tag("list")),
            map(preceded(terminated(tag("get"), multispace1), parse_str), |s| ReplMapCommand::Get { key: s }),
            map(preceded(terminated(tag("set"), multispace1), separated_pair(parse_str, multispace1, parse_str)), |s| ReplMapCommand::Set { key: s.0, value: s.1 }),
            map(preceded(terminated(tag("delete"), multispace1), parse_str), |s| ReplMapCommand::Delete { key: s }),
        )),
    )(input)
}

impl<'a> TryFrom<&'a str> for ReplMapCommand<'a> {
    type Error = VerboseError<&'a str>;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let (_, command) = parse_map_command(s)
            .map_err(|e| match e {
                Err::Error(e) | Err::Failure(e) => e,
                Err::Incomplete(_) => VerboseError { errors: Vec::new() }
            })?;
        Ok(command)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReplCryptCommand<'a> {
    /// ```list```
    List,
    /// ```unlock <alias> <filepath>```
    Unlock {
        alias: Cow<'a, str>,
        filepath: Cow<'a, str>,
    },
    /// ```lock <alias>```
    Lock {
        alias: Cow<'a, str>,
    },
    /// ```data <alias> <map command>```
    Data {
        alias: Cow<'a, str>,
        cmd: ReplMapCommand<'a>,
    },
}

/// Parse a crypt command.
///
/// # Example
///
/// ```
/// use std::borrow::Cow;
/// use nom::error::VerboseError;
/// use crypt_client::repl::{ReplCryptCommand, ReplMapCommand, parse_crypt_command};
///
/// let data = "list ...";
/// let result = parse_crypt_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok((" ...", ReplCryptCommand::List)));
///
/// let data = "unlock <alias> ./file.ext";
/// let result = parse_crypt_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplCryptCommand::Unlock {
///     alias: Cow::Borrowed("<alias>"),
///     filepath: Cow::Borrowed("./file.ext")
/// })));
///
/// let data = "lock <alias>";
/// let result = parse_crypt_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplCryptCommand::Lock { alias: Cow::Borrowed("<alias>") })));
///
/// let data = "data <alias> set <key> <value>";
/// let result = parse_crypt_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplCryptCommand::Data {
///     alias: Cow::Borrowed("<alias>"),
///     cmd: ReplMapCommand::Set { key: Cow::Borrowed("<key>"), value: Cow::Borrowed("<value>") }
/// })));
/// ```
///
pub fn parse_crypt_command<'a, E>(input: &'a str) -> IResult<&'a str, ReplCryptCommand<'a>, E>
    where E: ParseError<&'a str> + ContextError<&'a str>
{
    context(
        "crypt command",
        alt((
            value(ReplCryptCommand::List, tag("list")),
            map(preceded(tag("unlock"), preceded(multispace1, separated_pair(parse_str, multispace1, parse_str))), |s| ReplCryptCommand::Unlock { alias: s.0, filepath: s.1 }),
            map(preceded(tag("lock"), preceded(multispace1, parse_str)), |s| ReplCryptCommand::Lock { alias: s }),
            map(preceded(tag("data"), preceded(multispace1, separated_pair(parse_str, multispace1, parse_map_command))), |s| ReplCryptCommand::Data { alias: s.0, cmd: s.1 }),
        )),
    )(input)
}

impl<'a> TryFrom<&'a str> for ReplCryptCommand<'a> {
    type Error = VerboseError<&'a str>;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let (_, command) = parse_crypt_command(s)
            .map_err(|e| match e {
                Err::Error(e) | Err::Failure(e) => e,
                Err::Incomplete(_) => VerboseError { errors: Vec::new() }
            })?;
        Ok(command)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReplExitCommand {
    pub code: i32,
    pub no_save: bool,
}

impl Default for ReplExitCommand {
    fn default() -> Self {
        Self { code: 0, no_save: false }
    }
}

/// Parse an exit command.
///
/// # Example
///
/// ```
/// use nom::error::VerboseError;
/// use crypt_client::repl::{ReplExitCommand, parse_exit_command};
///
/// let data = "0";
/// let result = parse_exit_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplExitCommand { code: 0, no_save: false })));
///
/// let data = "0 --no-save";
/// let result = parse_exit_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplExitCommand { code: 0, no_save: true })));
///
/// let data = "50";
/// let result = parse_exit_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplExitCommand { code: 50, no_save: false })));
///
/// let data = "50 --no-save";
/// let result = parse_exit_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplExitCommand { code: 50, no_save: true })));
/// ```
///
pub fn parse_exit_command<'a, E>(input: &'a str) -> IResult<&'a str, ReplExitCommand, E>
    where E: ParseError<&'a str> + ContextError<&'a str>
{
    context(
        "exit command",
        map(
            tuple((parse_i32, opt(preceded(multispace1, value(true, tag("--no-save")))))),
            |(code, force)| ReplExitCommand { code, no_save: force.unwrap_or(false) },
        ),
    )(input)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReplCommand<'a> {
    ClearScreen,
    Help,
    Exit(ReplExitCommand),
    Crypt(ReplCryptCommand<'a>),
}

/// Parse a REPL command.
///
/// # Example
///
/// ```
/// use std::borrow::Cow;
/// use nom::error::VerboseError;
/// use crypt_client::repl::{ReplCommand, ReplExitCommand, ReplMapCommand, ReplCryptCommand, parse_command};
///
/// let data = "clear";
/// let result = parse_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplCommand::ClearScreen)));
///
/// let data = "exit 50";
/// let result = parse_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplCommand::Exit(ReplExitCommand { code: 50, no_save: false }))));
///
/// let data = "exit 0 --no-save";
/// let result = parse_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplCommand::Exit(ReplExitCommand { code: 0, no_save: true }))));
///
/// let data = "crypt unlock <alias> C:\\Users\\<username>\\file.ext";
/// let result = parse_command::<VerboseError<&str>>(data);
/// assert_eq!(result, Ok(("", ReplCommand::Crypt(ReplCryptCommand::Unlock {
///     alias: Cow::Borrowed("<alias>"),
///     filepath: Cow::Borrowed("C:\\Users\\<username>\\file.ext")
/// }))));
/// ```
///
pub fn parse_command<'a, E>(input: &'a str) -> IResult<&'a str, ReplCommand<'a>, E>
    where E: ParseError<&'a str> + ContextError<&'a str>
{
    context(
        "repl command",
        alt((
            value(ReplCommand::ClearScreen, tag("clear")),
            value(ReplCommand::Help, tag("help")),
            map(preceded(tag("exit"), preceded(multispace1, parse_exit_command)), ReplCommand::Exit),
            map(preceded(tag("crypt"), preceded(multispace1, parse_crypt_command)), ReplCommand::Crypt)
        )),
    )(input)
}

impl<'a> TryFrom<&'a str> for ReplCommand<'a> {
    type Error = VerboseError<&'a str>;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let (_, command) = parse_command(s)
            .map_err(|e| match e {
                Err::Error(e) | Err::Failure(e) => e,
                Err::Incomplete(_) => VerboseError { errors: Vec::new() }
            })?;
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_unquoted_str() {
        assert_eq!(parse_unquoted_str::<VerboseError<&str>>(""), Ok(("", "")));
        assert_eq!(parse_unquoted_str::<VerboseError<&str>>("abc123"), Ok(("", "abc123")));
        assert_eq!(parse_unquoted_str::<VerboseError<&str>>("abc12\\'3"), Ok(("", "abc12\\'3")));
        assert_eq!(parse_unquoted_str::<VerboseError<&str>>("abc12'3"), Ok(("", "abc12'3")));
    }

    #[test]
    fn test_parse_quoted_str() {
        assert_eq!(parse_quoted_str::<VerboseError<&str>>("''"), Ok(("", Cow::Borrowed(""))));
        assert_eq!(parse_quoted_str::<VerboseError<&str>>("'abc123'"), Ok(("", Cow::Borrowed("abc123"))));
        assert_eq!(parse_quoted_str::<VerboseError<&str>>("'abc12\\'3'"), Ok(("", Cow::Borrowed("abc12'3"))));
    }

    #[test]
    fn test_parse_str() {
        assert_eq!(parse_str::<VerboseError<&str>>(""), Ok(("", Cow::Borrowed(""))));
        assert_eq!(parse_str::<VerboseError<&str>>("''"), Ok(("", Cow::Borrowed(""))));
        assert_eq!(parse_str::<VerboseError<&str>>("abc123"), Ok(("", Cow::Borrowed("abc123"))));
        assert_eq!(parse_str::<VerboseError<&str>>("'abc123'"), Ok(("", Cow::Borrowed("abc123"))));
        assert_eq!(parse_str::<VerboseError<&str>>("'abc123 def'"), Ok(("", Cow::Borrowed("abc123 def"))));
        assert_eq!(parse_str::<VerboseError<&str>>("abc123 def"), Ok((" def", Cow::Borrowed("abc123"))));
    }

    #[test]
    fn test_parse_map_command() {
        assert_eq!(parse_map_command::<VerboseError<&str>>("list"), Ok(("", ReplMapCommand::List)));
        assert_eq!(parse_map_command::<VerboseError<&str>>("get abc"), Ok(("", ReplMapCommand::Get { key: Cow::Borrowed("abc") })));
        assert_eq!(parse_map_command::<VerboseError<&str>>("get 'abc d'"), Ok(("", ReplMapCommand::Get { key: Cow::Borrowed("abc d") })));
    }
}
