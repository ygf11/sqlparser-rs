// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! SQL Tokenizer
//!
//! The tokenizer (a.k.a. lexer) converts a string into a sequence of tokens.
//!
//! The tokens then form the input for the parser, which outputs an Abstract Syntax Tree (AST).

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::fmt;
use core::iter::Peekable;
use core::str::CharIndices;
use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::dialect::Dialect;
use crate::dialect::SnowflakeDialect;
use crate::keywords::{Keyword, ALL_KEYWORDS, ALL_KEYWORDS_INDEX};

/// SQL Token enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Token {
    /// An end-of-file marker, not a real token
    EOF,
    /// A keyword (like SELECT) or an optionally quoted SQL identifier
    Word(Word),
    /// An unsigned numeric literal
    Number(String, bool),
    /// A character that could not be tokenized
    Char(char),
    /// Single quoted string: i.e: 'string'
    SingleQuotedString(String),
    BackQuotedString(String),
    AtString(String),
    /// "National" string literal: i.e: N'string'
    NationalStringLiteral(String),
    /// Hexadecimal string literal: i.e.: X'deadbeef'
    HexStringLiteral(String),
    /// Comma
    Comma,
    /// Whitespace (space, tab, etc)
    Whitespace(Whitespace),
    /// Double equals sign `==`
    DoubleEq,
    /// Equality operator `=`
    Eq,
    /// Not Equals operator `<>` (or `!=` in some dialects)
    Neq,
    /// Less Than operator `<`
    Lt,
    /// Greater Than operator `>`
    Gt,
    /// Less Than Or Equals operator `<=`
    LtEq,
    /// Greater Than Or Equals operator `>=`
    GtEq,
    /// Spaceship operator <=>
    Spaceship,
    /// Plus operator `+`
    Plus,
    /// Minus operator `-`
    Minus,
    /// Multiplication operator `*`
    Mul,
    /// Division operator `/`
    Divide,
    /// Modulo Operator `%`
    Mod,
    /// String concatenation `||`
    StringConcat,
    /// Left parenthesis `(`
    LParen,
    /// Right parenthesis `)`
    RParen,
    /// Period (used for compound identifiers or projections into nested types)
    Period,
    /// Colon `:`
    Colon,
    /// DoubleColon `::` (used for casting in postgresql)
    DoubleColon,
    /// SemiColon `;` used as separator for COPY and payload
    SemiColon,
    /// Backslash `\` used in terminating the COPY payload with `\.`
    Backslash,
    /// Left bracket `[`
    LBracket,
    /// Right bracket `]`
    RBracket,
    /// Ampersand `&`
    Ampersand,
    /// Pipe `|`
    Pipe,
    /// Caret `^`
    Caret,
    /// Left brace `{`
    LBrace,
    /// Right brace `}`
    RBrace,
    /// Right Arrow `=>`
    RArrow,
    /// Sharp `#` used for PostgreSQL Bitwise XOR operator
    Sharp,
    /// Tilde `~` used for PostgreSQL Bitwise NOT operator or case sensitive match regular expression operator
    Tilde,
    /// `~*` , a case insensitive match regular expression operator in PostgreSQL
    TildeAsterisk,
    /// `!~` , a case sensitive not match regular expression operator in PostgreSQL
    ExclamationMarkTilde,
    /// `!~*` , a case insensitive not match regular expression operator in PostgreSQL
    ExclamationMarkTildeAsterisk,
    /// `<<`, a bitwise shift left operator in PostgreSQL
    ShiftLeft,
    /// `>>`, a bitwise shift right operator in PostgreSQL
    ShiftRight,
    /// Exclamation Mark `!` used for PostgreSQL factorial operator
    ExclamationMark,
    /// Double Exclamation Mark `!!` used for PostgreSQL prefix factorial operator
    DoubleExclamationMark,
    // AtSign `@` used for PostgreSQL abs operator
    AtSign,
    /// `|/`, a square root math operator in PostgreSQL
    PGSquareRoot,
    /// `||/` , a cube root math operator in PostgreSQL
    PGCubeRoot,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Token::EOF => f.write_str("EOF"),
            Token::Word(ref w) => write!(f, "{}", w),
            Token::Number(ref n, l) => write!(f, "{}{long}", n, long = if *l { "L" } else { "" }),
            Token::Char(ref c) => write!(f, "{}", c),
            Token::SingleQuotedString(ref s) => write!(f, "'{}'", s),
            Token::BackQuotedString(ref s) => write!(f, "`{}`", s),
            Token::AtString(ref s) => write!(f, "@{}", s),
            Token::NationalStringLiteral(ref s) => write!(f, "N'{}'", s),
            Token::HexStringLiteral(ref s) => write!(f, "X'{}'", s),
            Token::Comma => f.write_str(","),
            Token::Whitespace(ws) => write!(f, "{}", ws),
            Token::DoubleEq => f.write_str("=="),
            Token::Spaceship => f.write_str("<=>"),
            Token::Eq => f.write_str("="),
            Token::Neq => f.write_str("<>"),
            Token::Lt => f.write_str("<"),
            Token::Gt => f.write_str(">"),
            Token::LtEq => f.write_str("<="),
            Token::GtEq => f.write_str(">="),
            Token::Plus => f.write_str("+"),
            Token::Minus => f.write_str("-"),
            Token::Mul => f.write_str("*"),
            Token::Divide => f.write_str("/"),
            Token::StringConcat => f.write_str("||"),
            Token::Mod => f.write_str("%"),
            Token::LParen => f.write_str("("),
            Token::RParen => f.write_str(")"),
            Token::Period => f.write_str("."),
            Token::Colon => f.write_str(":"),
            Token::DoubleColon => f.write_str("::"),
            Token::SemiColon => f.write_str(";"),
            Token::Backslash => f.write_str("\\"),
            Token::LBracket => f.write_str("["),
            Token::RBracket => f.write_str("]"),
            Token::Ampersand => f.write_str("&"),
            Token::Caret => f.write_str("^"),
            Token::Pipe => f.write_str("|"),
            Token::LBrace => f.write_str("{"),
            Token::RBrace => f.write_str("}"),
            Token::RArrow => f.write_str("=>"),
            Token::Sharp => f.write_str("#"),
            Token::ExclamationMark => f.write_str("!"),
            Token::DoubleExclamationMark => f.write_str("!!"),
            Token::Tilde => f.write_str("~"),
            Token::TildeAsterisk => f.write_str("~*"),
            Token::ExclamationMarkTilde => f.write_str("!~"),
            Token::ExclamationMarkTildeAsterisk => f.write_str("!~*"),
            Token::AtSign => f.write_str("@"),
            Token::ShiftLeft => f.write_str("<<"),
            Token::ShiftRight => f.write_str(">>"),
            Token::PGSquareRoot => f.write_str("|/"),
            Token::PGCubeRoot => f.write_str("||/"),
        }
    }
}

impl Token {
    pub fn make_keyword(keyword: &str) -> Self {
        Token::make_word(keyword, None)
    }

    pub fn make_word(word: &str, quote_style: Option<char>) -> Self {
        let word_uppercase = word.to_uppercase();
        Token::Word(Word {
            value: word.to_string(),
            quote_style,
            keyword: if quote_style == None {
                let keyword = ALL_KEYWORDS.binary_search(&word_uppercase.as_str());
                keyword.map_or(Keyword::NoKeyword, |x| ALL_KEYWORDS_INDEX[x])
            } else {
                Keyword::NoKeyword
            },
        })
    }
}

/// A keyword (like SELECT) or an optionally quoted SQL identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Word {
    /// The value of the token, without the enclosing quotes, and with the
    /// escape sequences (if any) processed (TODO: escapes are not handled)
    pub value: String,
    /// An identifier can be "quoted" (&lt;delimited identifier> in ANSI parlance).
    /// The standard and most implementations allow using double quotes for this,
    /// but some implementations support other quoting styles as well (e.g. \[MS SQL])
    pub quote_style: Option<char>,
    /// If the word was not quoted and it matched one of the known keywords,
    /// this will have one of the values from dialect::keywords, otherwise empty
    pub keyword: Keyword,
}

impl fmt::Display for Word {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.quote_style {
            Some(s) if s == '"' || s == '[' || s == '`' || s == '\'' => {
                write!(f, "{}{}{}", s, self.value, Word::matching_end_quote(s))
            }
            None => f.write_str(&self.value),
            _ => panic!("Unexpected quote_style!"),
        }
    }
}

impl Word {
    fn matching_end_quote(ch: char) -> char {
        match ch {
            '"' => '"', // ANSI and most dialects
            '[' => ']', // MS SQL
            '`' => '`', // MySQL
            '\'' => '\'',
            _ => panic!("unexpected quoting style!"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Whitespace {
    Space,
    Newline,
    Tab,
    SingleLineComment { comment: String, prefix: String },
    MultiLineComment(String),
}

impl fmt::Display for Whitespace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Whitespace::Space => f.write_str(" "),
            Whitespace::Newline => f.write_str("\n"),
            Whitespace::Tab => f.write_str("\t"),
            Whitespace::SingleLineComment { prefix, comment } => write!(f, "{}{}", prefix, comment),
            Whitespace::MultiLineComment(s) => write!(f, "/*{}*/", s),
        }
    }
}

/// Tokenizer error
#[derive(Debug, PartialEq)]
pub struct TokenizerError {
    pub message: String,
    pub line: u64,
    pub col: u64,
}

impl fmt::Display for TokenizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at Line: {}, Column {}",
            self.message, self.line, self.col
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TokenizerError {}

/// The token's position in query.
/// Start contains the left char, and end does not contains char.
/// For example, `Insert into values (1,2,3)`
/// `Insert`'s position is [0, 6).
/// `into`'s position is [7, 11).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenWithPosition {
    pub token: Token,
    pub start: QueryOffset,
    pub end: QueryOffset,
}

impl TokenWithPosition {
    fn create_values_token(token: Token, start: QueryOffset, end: QueryOffset) -> Self {
        TokenWithPosition { token, start, end }
    }

    fn create_semi_colon(start: QueryOffset, end: QueryOffset) -> Self {
        TokenWithPosition {
            token: Token::SemiColon,
            start,
            end,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum QueryOffset {
    Normal(u64),
    EOF,
}

impl fmt::Display for QueryOffset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QueryOffset::Normal(offset) => write!(f, "{}", offset),
            QueryOffset::EOF => write!(f, "eof"),
        }
    }
}

pub type ValuesInfo = (QueryOffset, QueryOffset);

/// Help to find the end token of the values.
/// State machine:
///                                         comma
///                      |<---------------------------------------|
///                      |                                        |
///                      |                                        |
/// input ----------> RowStart ------------> LParen ----------> RParen ----------------> End
///         values       |      left paren           right paren          other token
///                      |
///                      |--------------> Error(Fail Fast)
///                         other token
enum ValuesState {
    RowStart,
    LParen,
    RParen,
    End,
}

struct ValuesStateToken {
    pub token: Token,
    pub token_start: QueryOffset,
    pub token_end: QueryOffset,
    pub state: ValuesState,
}

/// SQL Tokenizer
pub struct Tokenizer<'a> {
    dialect: &'a dyn Dialect,
    query: &'a str,
    line: u64,
    col: u64,

    // help find valus end
    values_state: Option<ValuesState>,
}

impl<'a> Tokenizer<'a> {
    /// Create a new SQL tokenizer for the specified SQL statement
    pub fn new(dialect: &'a dyn Dialect, query: &'a str) -> Self {
        Self {
            dialect,
            query,
            line: 1,
            col: 1,
            values_state: None,
        }
    }

    /// Tokenize the statement and produce a vector of tokens
    pub fn tokenize(
        &mut self,
    ) -> Result<(Vec<Token>, HashMap<usize, TokenWithPosition>), TokenizerError> {
        // let mut peekable = self.query.chars().peekable();
        let mut peekable = self.query.char_indices().peekable();

        let mut tokens: Vec<Token> = vec![];

        let mut position_map = HashMap::new();

        let mut last_token_end_pos = 0usize;

        // let mut values_state = None;

        while let Some((token, (start, end))) = self.next_token_with_position(&mut peekable)? {
            match &token {
                Token::Whitespace(Whitespace::Newline) => {
                    self.line += 1;
                    self.col = 1;
                }

                Token::Whitespace(Whitespace::Tab) => self.col += 4,
                Token::Word(w) if w.quote_style == None => self.col += w.value.len() as u64,
                Token::Word(w) if w.quote_style != None => self.col += w.value.len() as u64 + 2,
                Token::Number(s, _) => self.col += s.len() as u64,
                Token::SingleQuotedString(s) => self.col += s.len() as u64,
                Token::AtString(s) => self.col += s.len() as u64,
                _ => self.col += 1,
            }
            // 保存values的位置
            // 前进values状态机
            tokens.push(token);
        }
        Ok((tokens, position_map))
    }

    fn advance_values_state(
        &self,
        token: &Token,
        start: QueryOffset,
        end: QueryOffset,
        chars: &mut Peekable<CharIndices<'_>>,
        pos_map: &mut HashMap<usize, TokenWithPosition>,
        values_state: &mut Option<ValuesStateToken>,
    ) {
        // Skip whitespace
        if let Token::Whitespace(_) = token {
            return;
        }

        match (token, &values_state) {
            (Token::Word(w), None) if w.keyword == Keyword::VALUES => {
                let new_value_state = ValuesStateToken {
                    token: token.clone(),
                    token_start: start,
                    token_end: end,
                    state: ValuesState::RowStart,
                };

                *values_state = Some(new_value_state);
            },
            (Token::Word(w), Some(_)) if w.keyword == Keyword::VALUES => {
                // fallback to expr
                unreachable!()
            },
            _ => unreachable!(),
        };

        // Start new values
        // if matches!(token, Token::Word(w) if w.keyword == Keyword::VALUES) && values_state.is_none()
        // {
        //     let new_value_state = ValuesStateToken {
        //         token: token.clone(),
        //         token_start: start,
        //         token_end: end,
        //         state: ValuesState::RowStart,
        //     };

        //     *values_state = Some(new_value_state);
        //     return;
        // }

        // let next_state = match values_state.unwrap().state {
        //     ValuesState::RowStart => {
        //         if token == &Token::LParen {
        //             ValuesState::LParen;
        //         } else {
        //             // Empty values
        //             ValuesState::End;

        //             // save position
        //         }
        //     }
        //     ValuesState::LParen => {
        //         if token == &Token::RParen {
        //             ValuesState::RParen;
        //         } else {
        //             ValuesState::LParen;
        //             // error
        //         }
        //     }
        //     ValuesState::RParen => {
        //         if token == &Token::Comma {
        //             ValuesState::RowStart;
        //         } else {
        //             // save position
        //         }
        //     }
        //     ValuesState::End => {
        //         if matches!(token, Token::Word(w) if w.keyword == Keyword::VALUES) {
        //             *values_state = ValuesState::RowStart;
        //         }
        //     }
        // }
    }

    /// Record the token's position. It is a wrapper of next_token().
    /// For the start and end, it is a left closed and right open interval, like [start, end).
    fn next_token_with_position(
        &mut self,
        chars: &mut Peekable<CharIndices<'_>>,
    ) -> Result<Option<(Token, ValuesInfo)>, TokenizerError> {
        let start = get_current_idx(chars);
        if start == QueryOffset::EOF {
            return Ok(None);
        }

        let token = self.next_token(chars)?;
        if let Some(token) = token {
            let end = get_current_idx(chars);
            Ok(Some((token, (start, end))))
        } else {
            // reach eof
            Ok(None)
        }
    }

    /// Get the next token or return None
    fn next_token(
        &self,
        chars: &mut Peekable<CharIndices<'_>>,
    ) -> Result<Option<Token>, TokenizerError> {
        //println!("next_token: {:?}", chars.peek());
        match chars.peek() {
            Some((pos, ch)) => {
                let pos = *pos;
                match *ch {
                    ' ' => self.consume_and_return(chars, Token::Whitespace(Whitespace::Space)),
                    '\t' => self.consume_and_return(chars, Token::Whitespace(Whitespace::Tab)),
                    '\n' => self.consume_and_return(chars, Token::Whitespace(Whitespace::Newline)),
                    '\r' => {
                        // Emit a single Whitespace::Newline token for \r and \r\n
                        chars.next();
                        if let Some((_, '\n')) = chars.peek() {
                            chars.next();
                        }
                        Ok(Some(Token::Whitespace(Whitespace::Newline)))
                    }
                    'N' => {
                        chars.next(); // consume, to check the next char
                        match chars.peek() {
                            Some((_, '\'')) => {
                                // N'...' - a <national character string literal>
                                let s = self.tokenize_single_quoted_string(chars)?;
                                Ok(Some(Token::NationalStringLiteral(s)))
                            }
                            _ => {
                                // regular identifier starting with an "N"
                                let s = self.tokenize_word('N', chars);
                                Ok(Some(Token::make_word(&s, None)))
                            }
                        }
                    }
                    // The spec only allows an uppercase 'X' to introduce a hex
                    // string, but PostgreSQL, at least, allows a lowercase 'x' too.
                    x @ 'x' | x @ 'X' => {
                        chars.next(); // consume, to check the next char
                        match chars.peek() {
                            Some((_, '\'')) => {
                                // X'...' - a <binary string literal>
                                let s = self.tokenize_single_quoted_string(chars)?;
                                Ok(Some(Token::HexStringLiteral(s)))
                            }
                            _ => {
                                // regular identifier starting with an "X"
                                let s = self.tokenize_word(x, chars);
                                Ok(Some(Token::make_word(&s, None)))
                            }
                        }
                    }
                    // identifier or keyword
                    ch if self.dialect.is_identifier_start(ch) => {
                        chars.next(); // consume the first char
                        let s = self.tokenize_word(ch, chars);

                        if s.chars().all(|x| ('0'..='9').contains(&x) || x == '.') {
                            let mut s =
                                peeking_take_while(&mut s.char_indices().peekable(), |ch| {
                                    matches!(ch, '0'..='9' | '.')
                                });
                            let s2 = peeking_take_while(chars, |ch| matches!(ch, '0'..='9' | '.'));
                            s += s2.as_str();
                            return Ok(Some(Token::Number(s, false)));
                        }

                        // let token = Token::make_word(&s, None);
                        // Self::save_token_position(
                        //     position_map,
                        //     &token,
                        //     token_idx,
                        //     chars,
                        //     pos as u64,
                        // );

                        Ok(Some(Token::make_word(&s, None)))
                    }
                    // string
                    '\'' => {
                        let s = self.tokenize_single_quoted_string(chars)?;
                        Ok(Some(Token::SingleQuotedString(s)))
                    }
                    // string
                    '`' => {
                        let s = self.tokenize_back_quoted_string(chars)?;
                        Ok(Some(Token::BackQuotedString(s)))
                    }
                    // at string, not pg @
                    '@' if dialect_of!(self is SnowflakeDialect) => {
                        let s = self.tokenize_at_string(chars)?;
                        Ok(Some(Token::AtString(s)))
                    }
                    // delimited (quoted) identifier
                    quote_start if self.dialect.is_delimited_identifier_start(quote_start) => {
                        chars.next(); // consume the opening quote
                        let quote_end = Word::matching_end_quote(quote_start);
                        let s = peeking_take_while(chars, |ch| ch != quote_end);

                        if matches!(chars.next(), Some((_, end)) if end == quote_end) {
                            Ok(Some(Token::make_word(&s, Some(quote_start))))
                        } else {
                            self.tokenizer_error(format!(
                                "Expected close delimiter '{}' before EOF.",
                                quote_end
                            ))
                        }
                    }
                    // numbers and period
                    '0'..='9' | '.' => {
                        let mut s = peeking_take_while(chars, |ch| matches!(ch, '0'..='9'));

                        // match binary literal that starts with 0x
                        if matches!(chars.peek(), Some((_, x)) if s == "0" && x == &'x') {
                            chars.next();
                            let s2 = peeking_take_while(
                                chars,
                                |ch| matches!(ch, '0'..='9' | 'A'..='F' | 'a'..='f'),
                            );
                            return Ok(Some(Token::HexStringLiteral(s2)));
                        }

                        // match one period
                        if let Some((_, c)) = chars.peek() {
                            if c == &'.' {
                                s.push('.');
                                chars.next();
                            }
                        }
                        s += &peeking_take_while(chars, |ch| matches!(ch, '0'..='9'));

                        // No number -> Token::Period
                        if s == "." {
                            return Ok(Some(Token::Period));
                        }

                        let long = if matches!(chars.peek(), Some((_, l)) if l == &'L') {
                            chars.next();
                            true
                        } else {
                            false
                        };

                        Ok(Some(Token::Number(s, long)))
                    }
                    // punctuation
                    '(' => self.consume_and_return(chars, Token::LParen),
                    ')' => self.consume_and_return(chars, Token::RParen),
                    ',' => self.consume_and_return(chars, Token::Comma),
                    // operators
                    '-' => {
                        chars.next(); // consume the '-'
                        match chars.peek() {
                            Some((_, '-')) => {
                                chars.next(); // consume the second '-', starting a single-line comment
                                let comment = self.tokenize_single_line_comment(chars);
                                Ok(Some(Token::Whitespace(Whitespace::SingleLineComment {
                                    prefix: "--".to_owned(),
                                    comment,
                                })))
                            }
                            // a regular '-' operator
                            _ => Ok(Some(Token::Minus)),
                        }
                    }
                    '/' => {
                        chars.next(); // consume the '/'
                        match chars.peek() {
                            Some((_, '*')) => {
                                chars.next(); // consume the '*', starting a multi-line comment
                                self.tokenize_multiline_comment(chars)
                            }
                            Some((_, '/')) if dialect_of!(self is SnowflakeDialect) => {
                                chars.next(); // consume the second '/', starting a snowflake single-line comment
                                let comment = self.tokenize_single_line_comment(chars);
                                Ok(Some(Token::Whitespace(Whitespace::SingleLineComment {
                                    prefix: "//".to_owned(),
                                    comment,
                                })))
                            }
                            // a regular '/' operator
                            _ => Ok(Some(Token::Divide)),
                        }
                    }
                    '+' => self.consume_and_return(chars, Token::Plus),
                    '*' => self.consume_and_return(chars, Token::Mul),
                    '%' => self.consume_and_return(chars, Token::Mod),
                    '|' => {
                        chars.next(); // consume the '|'
                        match chars.peek() {
                            Some((_, '/')) => self.consume_and_return(chars, Token::PGSquareRoot),
                            Some((_, '|')) => {
                                chars.next(); // consume the second '|'
                                match chars.peek() {
                                    Some((_, '/')) => {
                                        self.consume_and_return(chars, Token::PGCubeRoot)
                                    }
                                    _ => Ok(Some(Token::StringConcat)),
                                }
                            }
                            // Bitshift '|' operator
                            _ => Ok(Some(Token::Pipe)),
                        }
                    }
                    '=' => {
                        chars.next(); // consume
                        match chars.peek() {
                            Some((_, '>')) => self.consume_and_return(chars, Token::RArrow),
                            _ => Ok(Some(Token::Eq)),
                        }
                    }
                    '!' => {
                        chars.next(); // consume
                        match chars.peek() {
                            Some((_, '=')) => self.consume_and_return(chars, Token::Neq),
                            Some((_, '!')) => {
                                self.consume_and_return(chars, Token::DoubleExclamationMark)
                            }
                            Some((_, '~')) => {
                                chars.next();
                                match chars.peek() {
                                    Some((_, '*')) => self.consume_and_return(
                                        chars,
                                        Token::ExclamationMarkTildeAsterisk,
                                    ),
                                    _ => Ok(Some(Token::ExclamationMarkTilde)),
                                }
                            }
                            _ => Ok(Some(Token::ExclamationMark)),
                        }
                    }
                    '<' => {
                        chars.next(); // consume
                        match chars.peek() {
                            Some((_, '=')) => {
                                chars.next();
                                match chars.peek() {
                                    Some((_, '>')) => {
                                        self.consume_and_return(chars, Token::Spaceship)
                                    }
                                    _ => Ok(Some(Token::LtEq)),
                                }
                            }
                            Some((_, '>')) => self.consume_and_return(chars, Token::Neq),
                            Some((_, '<')) => self.consume_and_return(chars, Token::ShiftLeft),
                            _ => Ok(Some(Token::Lt)),
                        }
                    }
                    '>' => {
                        chars.next(); // consume
                        match chars.peek() {
                            Some((_, '=')) => self.consume_and_return(chars, Token::GtEq),
                            Some((_, '>')) => self.consume_and_return(chars, Token::ShiftRight),
                            _ => Ok(Some(Token::Gt)),
                        }
                    }
                    ':' => {
                        chars.next();
                        match chars.peek() {
                            Some((_, ':')) => self.consume_and_return(chars, Token::DoubleColon),
                            _ => Ok(Some(Token::Colon)),
                        }
                    }
                    ';' => self.consume_and_return(chars, Token::SemiColon),
                    '\\' => self.consume_and_return(chars, Token::Backslash),
                    '[' => self.consume_and_return(chars, Token::LBracket),
                    ']' => self.consume_and_return(chars, Token::RBracket),
                    '&' => self.consume_and_return(chars, Token::Ampersand),
                    '^' => self.consume_and_return(chars, Token::Caret),
                    '{' => self.consume_and_return(chars, Token::LBrace),
                    '}' => self.consume_and_return(chars, Token::RBrace),
                    '#' if dialect_of!(self is SnowflakeDialect) => {
                        chars.next(); // consume the '#', starting a snowflake single-line comment
                        let comment = self.tokenize_single_line_comment(chars);
                        Ok(Some(Token::Whitespace(Whitespace::SingleLineComment {
                            prefix: "#".to_owned(),
                            comment,
                        })))
                    }
                    '~' => {
                        chars.next(); // consume
                        match chars.peek() {
                            Some((_, '*')) => self.consume_and_return(chars, Token::TildeAsterisk),
                            _ => Ok(Some(Token::Tilde)),
                        }
                    }
                    '#' => self.consume_and_return(chars, Token::Sharp),
                    '@' => self.consume_and_return(chars, Token::AtSign),
                    other => self.consume_and_return(chars, Token::Char(other)),
                }
            }
            None => Ok(None),
        }
    }

    fn tokenizer_error<R>(&self, message: impl Into<String>) -> Result<R, TokenizerError> {
        Err(TokenizerError {
            message: message.into(),
            col: self.col,
            line: self.line,
        })
    }

    // Consume characters until newline
    fn tokenize_single_line_comment(&self, chars: &mut Peekable<CharIndices<'_>>) -> String {
        let mut comment = peeking_take_while(chars, |ch| ch != '\n');
        if let Some((_, ch)) = chars.next() {
            assert_eq!(ch, '\n');
            comment.push(ch);
        }
        comment
    }

    /// Tokenize an identifier or keyword, after the first char is already consumed.
    fn tokenize_word(&self, first_char: char, chars: &mut Peekable<CharIndices<'_>>) -> String {
        let mut s = first_char.to_string();
        s.push_str(&peeking_take_while(chars, |ch| {
            self.dialect.is_identifier_part(ch)
        }));
        s
    }

    /// Read a single quoted string, starting with the opening quote.
    fn tokenize_single_quoted_string(
        &self,
        chars: &mut Peekable<CharIndices<'_>>,
    ) -> Result<String, TokenizerError> {
        let mut s = String::new();
        chars.next(); // consume the opening quote
        while let Some((_, ch)) = chars.next() {
            match ch {
                '\'' => {
                    let escaped_quote = chars.peek().map(|(_, c)| *c == '\'').unwrap_or(false);
                    if escaped_quote {
                        s.push('\'');
                        chars.next();
                    } else {
                        return Ok(s);
                    }
                }
                '\\' => {
                    if let Some((_, c)) = chars.next() {
                        match c {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            'b' => s.push('\u{08}'),
                            '0' => s.push('\0'),
                            '\'' => s.push('\''),
                            '\\' => s.push('\\'),
                            '\"' => s.push('\"'),
                            _ => {
                                s.push('\\');
                                s.push(c);
                            }
                        }
                    }
                }
                _ => {
                    s.push(ch);
                }
            }
        }
        self.tokenizer_error("Unterminated string literal")
    }

    fn tokenize_back_quoted_string(
        &self,
        chars: &mut Peekable<CharIndices<'_>>,
    ) -> Result<String, TokenizerError> {
        let mut s = String::new();
        chars.next(); // consume the opening quote
        while let Some((_, ch)) = chars.peek() {
            let ch = *ch;
            match ch {
                '`' => {
                    chars.next(); // consume
                    return Ok(s);
                }
                _ => {
                    chars.next(); // consume
                    s.push(ch);
                }
            }
        }
        self.tokenizer_error("Unterminated string literal")
    }

    fn tokenize_at_string(
        &self,
        chars: &mut Peekable<CharIndices<'_>>,
    ) -> Result<String, TokenizerError> {
        let mut s = String::new();
        chars.next(); // consume the opening quote
        while let Some((_, ch)) = chars.peek() {
            let ch = *ch;
            match ch {
                '\n' | '\t' | '\r' | ' ' => {
                    return Ok(s);
                }
                _ => {
                    chars.next(); // consume
                    s.push(ch);
                }
            }
        }
        Ok(s)
    }

    fn tokenize_multiline_comment(
        &self,
        chars: &mut Peekable<CharIndices<'_>>,
    ) -> Result<Option<Token>, TokenizerError> {
        let mut s = String::new();
        let mut maybe_closing_comment = false;
        // TODO: deal with nested comments
        loop {
            match chars.next() {
                Some((_, ch)) => {
                    if maybe_closing_comment {
                        if ch == '/' {
                            break Ok(Some(Token::Whitespace(Whitespace::MultiLineComment(s))));
                        } else {
                            s.push('*');
                        }
                    }
                    maybe_closing_comment = ch == '*';
                    if !maybe_closing_comment {
                        s.push(ch);
                    }
                }
                None => break self.tokenizer_error("Unexpected EOF while in a multi-line comment"),
            }
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn consume_and_return(
        &self,
        chars: &mut Peekable<CharIndices<'_>>,
        t: Token,
    ) -> Result<Option<Token>, TokenizerError> {
        chars.next();
        Ok(Some(t))
    }

    fn try_save_values_info(
        values_map: &mut HashMap<usize, ValuesInfo>,
        values_idx: usize,
        values_info: ValuesInfo,
    ) {
    }

    /// Save token-idx to its position in a map.
    /// Current only support save Values.
    fn save_token_position(
        position_map: &mut HashMap<usize, TokenWithPosition>,
        token: &Token,
        token_idx: usize,
        chars: &mut Peekable<CharIndices<'_>>,
        token_start: u64,
    ) {
        if token == &Token::RParen
            || matches!(token, Token::Word(w) if w.keyword == Keyword::VALUES)
        {
            let end = chars
                .peek()
                .map(|(end, _)| QueryOffset::Normal(*end as u64))
                .unwrap_or(QueryOffset::EOF);
            let token_with_position = TokenWithPosition {
                token: token.clone(),
                start: QueryOffset::Normal(token_start),
                end,
            };

            position_map.insert(token_idx, token_with_position);
        }
    }
}

/// Read from `chars` until `predicate` returns `false` or EOF is hit.
/// Return the characters read as String, and keep the first non-matching
/// char available as `chars.next()`.
fn peeking_take_while(
    chars: &mut Peekable<CharIndices<'_>>,
    mut predicate: impl FnMut(char) -> bool,
) -> String {
    let mut s = String::new();
    while let Some((_, ch)) = chars.peek() {
        let ch = *ch;
        if predicate(ch) {
            chars.next(); // consume
            s.push(ch);
        } else {
            break;
        }
    }

    s
}

fn get_current_idx(chars: &mut Peekable<CharIndices<'_>>) -> QueryOffset {
    match chars.peek() {
        Some((idx, _)) => QueryOffset::Normal(*idx as u64),
        None => QueryOffset::EOF,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialect::{GenericDialect, MsSqlDialect};

    #[test]
    fn tokenizer_error_impl() {
        let err = TokenizerError {
            message: "test".into(),
            line: 1,
            col: 1,
        };
        #[cfg(feature = "std")]
        {
            use std::error::Error;
            assert!(err.source().is_none());
        }
        assert_eq!(err.to_string(), "test at Line: 1, Column 1");
    }

    #[test]
    fn tokenize_select_1() {
        let sql = String::from("SELECT 1");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::Number(String::from("1"), false),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_select_float() {
        let sql = String::from("SELECT .1");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::Number(String::from(".1"), false),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_scalar_function() {
        let sql = String::from("SELECT sqrt(1)");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("sqrt", None),
            Token::LParen,
            Token::Number(String::from("1"), false),
            Token::RParen,
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_string_string_concat() {
        let sql = String::from("SELECT 'a' || 'b'");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::SingleQuotedString(String::from("a")),
            Token::Whitespace(Whitespace::Space),
            Token::StringConcat,
            Token::Whitespace(Whitespace::Space),
            Token::SingleQuotedString(String::from("b")),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }
    #[test]
    fn tokenize_bitwise_op() {
        let sql = String::from("SELECT one | two ^ three");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("one", None),
            Token::Whitespace(Whitespace::Space),
            Token::Pipe,
            Token::Whitespace(Whitespace::Space),
            Token::make_word("two", None),
            Token::Whitespace(Whitespace::Space),
            Token::Caret,
            Token::Whitespace(Whitespace::Space),
            Token::make_word("three", None),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_logical_xor() {
        let sql =
            String::from("SELECT true XOR true, false XOR false, true XOR false, false XOR true");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("true"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("XOR"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("true"),
            Token::Comma,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("false"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("XOR"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("false"),
            Token::Comma,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("true"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("XOR"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("false"),
            Token::Comma,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("false"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("XOR"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("true"),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_simple_select() {
        let sql = String::from("SELECT * FROM customer WHERE id = 1 LIMIT 5");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::Mul,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("FROM"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("customer", None),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("WHERE"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("id", None),
            Token::Whitespace(Whitespace::Space),
            Token::Eq,
            Token::Whitespace(Whitespace::Space),
            Token::Number(String::from("1"), false),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("LIMIT"),
            Token::Whitespace(Whitespace::Space),
            Token::Number(String::from("5"), false),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_explain_select() {
        let sql = String::from("EXPLAIN SELECT * FROM customer WHERE id = 1");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("EXPLAIN"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::Mul,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("FROM"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("customer", None),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("WHERE"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("id", None),
            Token::Whitespace(Whitespace::Space),
            Token::Eq,
            Token::Whitespace(Whitespace::Space),
            Token::Number(String::from("1"), false),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_explain_analyze_select() {
        let sql = String::from("EXPLAIN ANALYZE SELECT * FROM customer WHERE id = 1");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("EXPLAIN"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("ANALYZE"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::Mul,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("FROM"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("customer", None),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("WHERE"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("id", None),
            Token::Whitespace(Whitespace::Space),
            Token::Eq,
            Token::Whitespace(Whitespace::Space),
            Token::Number(String::from("1"), false),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_string_predicate() {
        let sql = String::from("SELECT * FROM customer WHERE salary != 'Not Provided'");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::Mul,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("FROM"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("customer", None),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("WHERE"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("salary", None),
            Token::Whitespace(Whitespace::Space),
            Token::Neq,
            Token::Whitespace(Whitespace::Space),
            Token::SingleQuotedString(String::from("Not Provided")),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_invalid_string() {
        let sql = String::from("\nمصطفىh");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        // println!("tokens: {:#?}", tokens);
        let expected = vec![
            Token::Whitespace(Whitespace::Newline),
            Token::Char('م'),
            Token::Char('ص'),
            Token::Char('ط'),
            Token::Char('ف'),
            Token::Char('ى'),
            Token::make_word("h", None),
        ];
        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_newline_in_string_literal() {
        let sql = String::from("'foo\r\nbar\nbaz'");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![Token::SingleQuotedString("foo\r\nbar\nbaz".to_string())];
        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_unterminated_string_literal() {
        let sql = String::from("select 'foo");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        assert_eq!(
            tokenizer.tokenize(),
            Err(TokenizerError {
                message: "Unterminated string literal".to_string(),
                line: 1,
                col: 8
            })
        );
    }

    #[test]
    fn tokenize_invalid_string_cols() {
        let sql = String::from("\n\nSELECT * FROM table\tمصطفىh");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        // println!("tokens: {:#?}", tokens);
        let expected = vec![
            Token::Whitespace(Whitespace::Newline),
            Token::Whitespace(Whitespace::Newline),
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::Mul,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("FROM"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("table"),
            Token::Whitespace(Whitespace::Tab),
            Token::Char('م'),
            Token::Char('ص'),
            Token::Char('ط'),
            Token::Char('ف'),
            Token::Char('ى'),
            Token::make_word("h", None),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_right_arrow() {
        let sql = String::from("FUNCTION(key=>value)");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::make_word("FUNCTION", None),
            Token::LParen,
            Token::make_word("key", None),
            Token::RArrow,
            Token::make_word("value", None),
            Token::RParen,
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_is_null() {
        let sql = String::from("a IS NULL");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();

        let expected = vec![
            Token::make_word("a", None),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("IS"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("NULL"),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_comment() {
        let sql = String::from("0--this is a comment\n1");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::Number("0".to_string(), false),
            Token::Whitespace(Whitespace::SingleLineComment {
                prefix: "--".to_string(),
                comment: "this is a comment\n".to_string(),
            }),
            Token::Number("1".to_string(), false),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_comment_at_eof() {
        let sql = String::from("--this is a comment");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![Token::Whitespace(Whitespace::SingleLineComment {
            prefix: "--".to_string(),
            comment: "this is a comment".to_string(),
        })];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_multiline_comment() {
        let sql = String::from("0/*multi-line\n* /comment*/1");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::Number("0".to_string(), false),
            Token::Whitespace(Whitespace::MultiLineComment(
                "multi-line\n* /comment".to_string(),
            )),
            Token::Number("1".to_string(), false),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_multiline_comment_with_even_asterisks() {
        let sql = String::from("\n/** Comment **/\n");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::Whitespace(Whitespace::Newline),
            Token::Whitespace(Whitespace::MultiLineComment("* Comment *".to_string())),
            Token::Whitespace(Whitespace::Newline),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_mismatched_quotes() {
        let sql = String::from("\"foo");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        assert_eq!(
            tokenizer.tokenize(),
            Err(TokenizerError {
                message: "Expected close delimiter '\"' before EOF.".to_string(),
                line: 1,
                col: 1
            })
        );
    }

    #[test]
    fn tokenize_newlines() {
        let sql = String::from("line1\nline2\rline3\r\nline4\r");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::make_word("line1", None),
            Token::Whitespace(Whitespace::Newline),
            Token::make_word("line2", None),
            Token::Whitespace(Whitespace::Newline),
            Token::make_word("line3", None),
            Token::Whitespace(Whitespace::Newline),
            Token::make_word("line4", None),
            Token::Whitespace(Whitespace::Newline),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_at_string() {
        let sql = String::from("list @abc/a/b/c\nd");

        let dialect = SnowflakeDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::make_word("list", None),
            Token::Whitespace(Whitespace::Space),
            Token::AtString("abc/a/b/c".to_string()),
            Token::Whitespace(Whitespace::Newline),
            Token::make_word("d", None),
        ];
        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());

        let sql = String::from("list @abc/e/f/g");

        let dialect = SnowflakeDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::make_word("list", None),
            Token::Whitespace(Whitespace::Space),
            Token::AtString("abc/e/f/g".to_string()),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_mssql_top() {
        let sql = "SELECT TOP 5 [bar] FROM foo";
        let dialect = MsSqlDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("TOP"),
            Token::Whitespace(Whitespace::Space),
            Token::Number(String::from("5"), false),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("bar", Some('[')),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("FROM"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("foo", None),
        ];
        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_pg_regex_match() {
        let sql = "SELECT col ~ '^a', col ~* '^a', col !~ '^a', col !~* '^a'";
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::make_keyword("SELECT"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("col", None),
            Token::Whitespace(Whitespace::Space),
            Token::Tilde,
            Token::Whitespace(Whitespace::Space),
            Token::SingleQuotedString("^a".into()),
            Token::Comma,
            Token::Whitespace(Whitespace::Space),
            Token::make_word("col", None),
            Token::Whitespace(Whitespace::Space),
            Token::TildeAsterisk,
            Token::Whitespace(Whitespace::Space),
            Token::SingleQuotedString("^a".into()),
            Token::Comma,
            Token::Whitespace(Whitespace::Space),
            Token::make_word("col", None),
            Token::Whitespace(Whitespace::Space),
            Token::ExclamationMarkTilde,
            Token::Whitespace(Whitespace::Space),
            Token::SingleQuotedString("^a".into()),
            Token::Comma,
            Token::Whitespace(Whitespace::Space),
            Token::make_word("col", None),
            Token::Whitespace(Whitespace::Space),
            Token::ExclamationMarkTildeAsterisk,
            Token::Whitespace(Whitespace::Space),
            Token::SingleQuotedString("^a".into()),
        ];

        compare(expected, tokens);
        assert_eq!(pos_map, HashMap::default());
    }

    #[test]
    fn tokenize_simple_values_position() {
        let sql = "values (1,2,3)";
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::make_keyword("values"),
            Token::Whitespace(Whitespace::Space),
            Token::LParen,
            Token::Number(String::from("1"), false),
            Token::Comma,
            Token::Number(String::from("2"), false),
            Token::Comma,
            Token::Number(String::from("3"), false),
            Token::RParen,
        ];

        compare(expected, tokens);
        let expected_pos_map: HashMap<usize, TokenWithPosition> = HashMap::from([(
            0,
            TokenWithPosition::create_values_token(
                Token::make_word("values", None),
                QueryOffset::Normal(0),
                QueryOffset::Normal(6),
            ),
        )]);
        assert_eq!(pos_map, expected_pos_map);
    }

    #[test]
    fn tokenize_space_start_values_position() {
        let sql = " values (1,2,3)";
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("values"),
            Token::Whitespace(Whitespace::Space),
            Token::LParen,
            Token::Number(String::from("1"), false),
            Token::Comma,
            Token::Number(String::from("2"), false),
            Token::Comma,
            Token::Number(String::from("3"), false),
            Token::RParen,
        ];

        compare(expected, tokens);
        let expected_pos_map: HashMap<usize, TokenWithPosition> = HashMap::from([(
            1,
            TokenWithPosition::create_values_token(
                Token::make_keyword("values"),
                QueryOffset::Normal(1),
                QueryOffset::Normal(7),
            ),
        )]);
        assert_eq!(pos_map, expected_pos_map);
    }

    #[test]
    fn tokenize_values_end_position() {
        let sql = "insert into () values";
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::make_keyword("insert"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("into", None),
            Token::Whitespace(Whitespace::Space),
            Token::LParen,
            Token::RParen,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("values"),
        ];

        compare(expected, tokens);
        let expected_pos_map: HashMap<usize, TokenWithPosition> = HashMap::from([(
            7,
            TokenWithPosition::create_values_token(
                Token::make_keyword("values"),
                QueryOffset::Normal(15),
                QueryOffset::EOF,
            ),
        )]);
        assert_eq!(pos_map, expected_pos_map);
    }

    #[test]
    fn tokenize_semi_colon_and_values_position() {
        let sql = "insert into t values (1); select 1";
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, sql);
        let (tokens, pos_map) = tokenizer.tokenize().unwrap();
        let expected = vec![
            Token::make_keyword("insert"),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("into"),
            Token::Whitespace(Whitespace::Space),
            Token::make_word("t", None),
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("values"),
            Token::Whitespace(Whitespace::Space),
            Token::LParen,
            Token::Number(String::from("1"), false),
            Token::RParen,
            Token::SemiColon,
            Token::Whitespace(Whitespace::Space),
            Token::make_keyword("select"),
            Token::Whitespace(Whitespace::Space),
            Token::Number(String::from("1"), false),
        ];

        compare(expected, tokens);
        let expected_pos_map: HashMap<usize, TokenWithPosition> = HashMap::from([(
            6,
            TokenWithPosition::create_values_token(
                Token::make_keyword("values"),
                QueryOffset::Normal(14),
                QueryOffset::Normal(20),
            ),
        )]);
        assert_eq!(pos_map, expected_pos_map);
    }

    fn compare(expected: Vec<Token>, actual: Vec<Token>) {
        //println!("------------------------------");
        //println!("tokens   = {:?}", actual);
        //println!("expected = {:?}", expected);
        //println!("------------------------------");
        assert_eq!(expected, actual);
    }
}
