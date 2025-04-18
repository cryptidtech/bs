use crate::{
    subcmds::{config, plog},
    Command,
};
use colored::Colorize;
use rustyline::{
    completion::{Completer, FilenameCompleter, Pair},
    highlight::{CmdKind, Highlighter, MatchingBracketHighlighter},
    hint::{Hint, Hinter},
    history::DefaultHistory,
    validate::MatchingBracketValidator,
    Completer, Context, Helper, Validator,
};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io::Cursor,
    iter,
    path::PathBuf,
    str::CharIndices,
};

/// The REPL parser.
struct Parser<'a> {
    s: &'a str,
    it: iter::Peekable<CharIndices<'a>>,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Parser {
            s,
            it: s.char_indices().peekable(),
        }
    }

    fn parse_command(s: &'a str) -> Result<Command, String> {
        let mut parser = Self::new(s);

        let Some(command) = parser.command()? else {
            return Err("No command found".to_string());
        };

        // TODO: would be better to be able to specify what are the
        // TODO: expected commands, subcommands, and parameters
        // TODO: maybe pass in closures to handle it similar to Iterator::map
        match command {
            "config" => {
                let Some(subcmd) = parser.command()? else {
                    return Ok(Command::Config { cmd: None });
                };
                match subcmd {
                    "open" => Ok(Command::Config {
                        cmd: Some(config::Command::Print),
                    }),
                    _ => Ok(Command::Config { cmd: None }),
                }
            }
            "plog" => {
                let Some(subcmd) = parser.command()? else {
                    return Err("Missing required subcommand found for plog command".to_string());
                };

                match subcmd {
                    "close" => Ok(Command::Plog {
                        cmd: Box::new(plog::Command::Close),
                    }),
                    "fork" => Ok(Command::Plog {
                        cmd: Box::new(plog::Command::Fork),
                    }),
                    "merge" => Ok(Command::Plog {
                        cmd: Box::new(plog::Command::Merge),
                    }),
                    "open" => {
                        let mut map = HashMap::new();
                        while let Some((key, value)) = parser.parameter()? {
                            map.insert(key, value);
                        }

                        let key_ops = parse_vec_string_value(
                            map.get("key-op")
                                .ok_or("Missing key-op parameter".to_string())?,
                        )?;
                        let string_ops = parse_vec_string_value(
                            map.get("string-op")
                                .ok_or("Missing string-op parameter".to_string())?,
                        )?;
                        let file_ops = parse_vec_string_value(
                            map.get("file-op")
                                .ok_or("Missing file-op parameter".to_string())?,
                        )?;
                        let lock_script_path = PathBuf::from(
                            map.get("lock")
                                .ok_or("Missing lock parameter".to_string())?,
                        );
                        let unlock_script_path = PathBuf::from(
                            map.get("unlock")
                                .ok_or("Missing unlock parameter".to_string())?,
                        );
                        let output = map.get("output").map(PathBuf::from);

                        Ok(Command::Plog {
                            cmd: Box::new(plog::Command::Open {
                                pub_key_params: map
                                    .get("pub-key")
                                    .cloned()
                                    .unwrap_or("eddsa".to_string()),
                                key_ops,
                                string_ops,
                                file_ops,
                                vlad_params: map
                                    .get("vlad")
                                    .cloned()
                                    .ok_or("Missing vlad parameter".to_string())?,
                                entry_key_codec: map
                                    .get("entry-key")
                                    .cloned()
                                    .unwrap_or("eddsa".to_string()),
                                lock_script_path,
                                unlock_script_path,
                                output,
                            }),
                        })
                    }
                    "print" => {
                        let mut map = HashMap::new();
                        while let Some((key, value)) = parser.parameter()? {
                            map.insert(key, value);
                        }

                        let input = map.get("input").map(PathBuf::from);
                        Ok(Command::Plog {
                            cmd: Box::new(plog::Command::Print { input }),
                        })
                    }
                    "update" => {
                        let mut map = HashMap::new();
                        while let Some((key, value)) = parser.parameter()? {
                            map.insert(key, value);
                        }

                        let delete_ops = parse_vec_string_value(
                            map.get("delete-op")
                                .ok_or("Missing delete-op parameter".to_string())?,
                        )?;
                        let key_ops = parse_vec_string_value(
                            map.get("key-op")
                                .ok_or("Missing key-op parameter".to_string())?,
                        )?;
                        let string_ops = parse_vec_string_value(
                            map.get("string-op")
                                .ok_or("Missing string-op parameter".to_string())?,
                        )?;
                        let file_ops = parse_vec_string_value(
                            map.get("file-op")
                                .ok_or("Missing file-op parameter".to_string())?,
                        )?;
                        let lock_script_path = PathBuf::from(
                            map.get("lock")
                                .ok_or("Missing lock parameter".to_string())?,
                        );
                        let unlock_script_path = PathBuf::from(
                            map.get("unlock")
                                .ok_or("Missing unlock parameter".to_string())?,
                        );
                        let entry_signing_key = PathBuf::from(
                            map.get("entry-signing-key")
                                .ok_or("Missing entry-signing-key parameter".to_string())?,
                        );
                        let input = map.get("input").map(PathBuf::from);
                        let output = map.get("output").map(PathBuf::from);

                        Ok(Command::Plog {
                            cmd: Box::new(plog::Command::Update {
                                delete_ops,
                                key_ops,
                                string_ops,
                                file_ops,
                                entry_signing_key,
                                input,
                                lock_script_path,
                                unlock_script_path,
                                output,
                            }),
                        })
                    }
                    _ => Err(format!("Unknown subcommand for plog command: {}", subcmd)),
                }
            }
            _ => Err(format!("Unknown command: {}", command)),
        }
    }

    fn command(&mut self) -> Result<Option<&'a str>, String> {
        self.skip_ws();
        Ok(self.keyword())
    }

    fn parameter(&mut self) -> Result<Option<(&'a str, String)>, String> {
        self.skip_ws();

        let Some(keyword) = self.keyword() else {
            return Ok(None);
        };
        self.skip_ws();
        self.consume('=')?;
        self.skip_ws();
        let value = self.value()?;

        Ok(Some((keyword, value)))
    }

    fn skip_ws(&mut self) {
        self.take_while(char::is_whitespace);
    }

    fn take_while<F>(&mut self, f: F) -> &'a str
    where
        F: Fn(char) -> bool,
    {
        let Some(&(start, _)) = self.it.peek() else {
            return "";
        };

        loop {
            match self.it.peek() {
                Some(&(_, c)) if f(c) => {
                    self.it.next();
                }
                Some(&(i, _)) => return &self.s[start..i],
                None => return &self.s[start..],
            }
        }
    }

    fn consume(&mut self, target: char) -> Result<(), String> {
        match self.it.next() {
            Some((_, c)) if c == target => Ok(()),
            Some((i, c)) => Err(format!(
                "unexpected character at index {}: Expected '{}', found '{}'",
                i, target, c
            )),
            None => Err(format!("Expected '{}', found EOF", target)),
        }
    }

    fn consume_if(&mut self, target: char) -> bool {
        match self.it.peek() {
            Some(&(_, c)) if c == target => {
                self.it.next();
                true
            }
            _ => false,
        }
    }

    fn keyword(&mut self) -> Option<&'a str> {
        let s = self.take_while(|c| !matches!(c, c if c.is_whitespace() || c == '='));

        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    fn value(&mut self) -> Result<String, String> {
        let value = if self.consume_if('\'') {
            let value = self.quoted_value()?;
            self.consume('\'')?;
            value
        } else if self.consume_if('"') {
            let value = self.double_quoted_value()?;
            self.consume('"')?;
            value
        } else {
            self.simple_value()?
        };
        Ok(value)
    }

    fn simple_value(&mut self) -> Result<String, String> {
        let mut value = String::new();

        while let Some(&(_, c)) = self.it.peek() {
            if c.is_whitespace() {
                break;
            }

            self.it.next();

            if c == '\\' {
                if let Some((_, c2)) = self.it.next() {
                    value.push(c2);
                }
            } else {
                value.push(c);
            }
        }

        if value.is_empty() {
            Err("Unexpected EOF".to_string())
        } else {
            Ok(value)
        }
    }

    fn quoted_value(&mut self) -> Result<String, String> {
        self.handle_quote_value('\'', "Unexpected EOF while parsing quoted value")
    }

    fn double_quoted_value(&mut self) -> Result<String, String> {
        self.handle_quote_value('"', "Unexpected EOF while parsing double quoted value")
    }

    fn handle_quote_value(
        &mut self,
        terminator: char,
        failure_msg: &str,
    ) -> Result<String, String> {
        let mut value = String::new();

        while let Some(&(_, c)) = self.it.peek() {
            if c == terminator {
                return Ok(value);
            }

            self.it.next();

            if c == '\\' {
                if let Some((_, c2)) = self.it.next() {
                    value.push(c2);
                }
            } else {
                value.push(c);
            }
        }

        Err(failure_msg.to_string())
    }
}

fn parse_vec_string_value(s: &str) -> Result<Vec<String>, String> {
    let mut vec = Vec::new();
    let mut reader = csv::Reader::from_reader(Cursor::new(s));
    for result in reader.records() {
        let record = result.map_err(|e| e.to_string())?;
        for field in record.iter() {
            vec.push(field.to_string());
        }
    }
    Ok(vec)
}

/// A REPL for the command line
#[derive(Helper, rustyline::Hinter, Completer, Validator)]
pub struct ReplHelper {
    #[rustyline(Completer)]
    completer: BsHinter,
    highlighter: MatchingBracketHighlighter,
    #[rustyline(Validator)]
    validator: MatchingBracketValidator,
    #[rustyline(Hinter)]
    hinter: BsHinter,
    colored_prompt: String,
}

impl Highlighter for ReplHelper {
    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        self.highlighter.highlight(line, pos)
    }

    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        default: bool,
    ) -> Cow<'b, str> {
        if default {
            Cow::Borrowed(&self.colored_prompt)
        } else {
            Cow::Borrowed(prompt)
        }
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Cow::Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
    }

    fn highlight_char(&self, line: &str, pos: usize, forced: CmdKind) -> bool {
        self.highlighter.highlight_char(line, pos, forced)
    }
}

impl Default for ReplHelper {
    fn default() -> Self {
        Self {
            completer: BsHinter::default(),
            highlighter: MatchingBracketHighlighter::new(),
            validator: MatchingBracketValidator::new(),
            hinter: BsHinter::default(),
            colored_prompt: "".to_string(),
        }
    }
}

impl ReplHelper {
    /// Run the REPL
    pub fn read() -> ReplHelperIterator {
        let config = rustyline::Config::builder()
            .history_ignore_space(true)
            .completion_type(rustyline::CompletionType::List)
            .edit_mode(rustyline::EditMode::Emacs)
            .build();

        let h = Self::default();
        let mut rl = rustyline::Editor::with_config(config).expect("to create editor");
        rl.set_helper(Some(h));
        rl.helper_mut().expect("to get helper").colored_prompt = "bs>".green().to_string();

        help();
        ReplHelperIterator { rl }
    }
}

/// An iterator for the REPL that yields commands
/// as long as the user doesn't quit
pub struct ReplHelperIterator {
    rl: rustyline::Editor<ReplHelper, DefaultHistory>,
}

impl Iterator for ReplHelperIterator {
    type Item = Command;

    fn next(&mut self) -> Option<Self::Item> {
        let mut input;
        loop {
            let readline = self.rl.readline("bs> ");
            match readline {
                Ok(line) => {
                    self.rl
                        .add_history_entry(line.as_str())
                        .expect("to add history");
                    input = line;
                }
                Err(rustyline::error::ReadlineError::Interrupted) => {
                    println!("CTRL-C");
                    break;
                }
                Err(rustyline::error::ReadlineError::Eof) => {
                    println!("CTRL-D");
                    break;
                }
                Err(err) => {
                    println!("Error: {:?}", err);
                    break;
                }
            }
            input = input.trim().to_string();
            if input.is_empty() {
                continue;
            }
            self.rl
                .add_history_entry(input.as_str())
                .expect("to add history");
            let mut parser = Parser::new(&input);
            parser.skip_ws();
            match parser.simple_value() {
                Err(_) => {}
                Ok(word) => match word.as_str() {
                    "config" | "plog" => match Parser::parse_command(&input) {
                        Ok(command) => {
                            return Some(command);
                        }
                        Err(err) => {
                            eprintln!("Error parsing command: {}", err);
                        }
                    },
                    "help" => {
                        help();
                    }
                    "quit" => {
                        break;
                    }
                    _ => eprintln!("Unknown command: {}", word),
                },
            }
        }
        None
    }
}

/// A hinter for the command line
pub struct BsHinter {
    hints: HashSet<CommandHint>,
    file_completer: FilenameCompleter,
}

impl Hinter for BsHinter {
    type Hint = CommandHint;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<Self::Hint> {
        if line.is_empty() || pos < line.len() {
            return None;
        }

        self.hints
            .iter()
            .filter_map(|hint| {
                if hint.display.starts_with(line) {
                    Some(hint.suffix(pos))
                } else {
                    None
                }
            })
            .next()
    }
}

impl Completer for BsHinter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, mut candidates) = self.file_completer.complete(line, pos, ctx)?;
        let prefix = &line[..pos];
        let mut additional = self
            .hints
            .iter()
            .filter_map(|h| {
                if h.display.starts_with(prefix) {
                    Some(h.into())
                } else {
                    None
                }
            })
            .collect::<Vec<Pair>>();
        candidates.append(&mut additional);
        #[allow(clippy::unnecessary_sort_by)]
        candidates.sort_by(|a, b| a.display.cmp(&b.display));
        Ok((start, candidates))
    }
}

impl Default for BsHinter {
    fn default() -> Self {
        let mut hints = HashSet::<CommandHint>::with_capacity(50);
        hints.insert("config".into());
        hints.insert("open".into());
        hints.insert("plog".into());
        hints.insert("close".into());
        hints.insert("fork".into());
        hints.insert("merge".into());
        hints.insert("print".into());
        hints.insert("update".into());
        hints.insert("key-op".into());
        hints.insert("string-op".into());
        hints.insert("file-op".into());
        hints.insert("delete-op".into());
        hints.insert("lock".into());
        hints.insert("unlock".into());
        hints.insert("vlad".into());
        hints.insert("pub-key".into());
        hints.insert("entry-key".into());
        hints.insert("entry-signing-key".into());
        hints.insert("input".into());
        hints.insert("output".into());
        Self {
            hints,
            file_completer: FilenameCompleter::new(),
        }
    }
}

/// A hint for a command.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct CommandHint {
    display: String,
    complete_up_to: usize,
}

impl Hint for CommandHint {
    fn display(&self) -> &str {
        &self.display
    }

    fn completion(&self) -> Option<&str> {
        if self.complete_up_to < self.display.len() {
            Some(&self.display[self.complete_up_to..])
        } else {
            None
        }
    }
}

impl From<CommandHint> for Pair {
    fn from(hint: CommandHint) -> Self {
        Pair::from(&hint)
    }
}

impl From<&CommandHint> for Pair {
    fn from(hint: &CommandHint) -> Self {
        Pair {
            display: hint.display.clone(),
            replacement: hint.display.clone(),
        }
    }
}

impl From<&str> for CommandHint {
    fn from(s: &str) -> Self {
        CommandHint::new(s)
    }
}

impl CommandHint {
    fn new(display: &str) -> Self {
        Self {
            display: display.to_string(),
            complete_up_to: display.len(),
        }
    }

    fn suffix(&self, strip_chars: usize) -> Self {
        Self {
            display: self.display[strip_chars..].to_owned(),
            complete_up_to: self.complete_up_to.saturating_sub(strip_chars),
        }
    }
}

fn help() {
    println!(
        r#"Commands:
config <subcommand> [parameters]
plot <subcommand> [parameters]
help
quit

Config Subcommands:
open

Plog Subcommands:
close
fork
merge
open [key-op=STRING_COMMA_SEPARATED_LIST] [string-op=STRING_COMMA_SEPARATED_LIST] [file-op=STRING_COMMA_SEPARATED_LIST] [vlad=STRING] [pub-key=STRING] [entry-key=STRING] [lock=PATH_TO_SCRIPT] [unlock=PATH_TO_SCRIPT] [output=PATH_TO_FILE]
print [input=PATH_TO_FILE]
update [key-op=STRING_COMMA_SEPARATED_LIST] [string-op=STRING_COMMA_SEPARATED_LIST] [file-op=STRING_COMMA_SEPARATED_LIST] [delete-op=STRING_COMMA_SEPARATED_LIST] [entry-signing-key=PATH_TO_FILE] [input=PATH_TO_FILE] [lock=PATH_TO_SCRIPT] [unlock=PATH_TO_SCRIPT] [output=PATH_TO_FILE]
"#
    )
}
