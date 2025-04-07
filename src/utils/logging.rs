// src/utils/logging.rs

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    sync::Mutex,
    fmt,
    path::Path,
    time::SystemTime,
};
use chrono::Local;
use lazy_static::lazy_static;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

lazy_static! {
    static ref LOG_FILE: Mutex<Option<File>> = Mutex::new(None);
    static ref LOG_LEVEL: Mutex<LogLevel> = Mutex::new(LogLevel::Error);
    static ref LOG_CONSOLE: Mutex<bool> = Mutex::new(false);
    static ref LOG_COLOR_SPEC: Mutex<ColorSpec> = Mutex::new(ColorSpec::new());
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum LogLevel {
    None = 0,
    Error,
    Warning,
    Info,
    Debug,
    Trace,
}

impl From<u8> for LogLevel {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Error,
            2 => Self::Warning,
            3 => Self::Info,
            4 => Self::Debug,
            5 => Self::Trace,
            _ => Self::Error,
        }
    }
}

pub fn init_logging(
    filename: Option<&str>, 
    level: LogLevel, 
    console: bool
) -> io::Result<()> {
    let mut file = LOG_FILE.lock().unwrap();
    if let Some(name) = filename {
        *file = Some(OpenOptions::new()
            .create(true)
            .append(true)
            .open(name)?);
    }
    
    *LOG_LEVEL.lock().unwrap() = level;
    *LOG_CONSOLE.lock().unwrap() = console;
    Ok(())
}

pub fn log_message(
    level: LogLevel,
    file: &str,
    line: u32,
    func: &str,
    message: &fmt::Arguments
) {
    if level < *LOG_LEVEL.lock().unwrap() {
        return;
    }

    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut output = format!(
        "[{}] [{}:{}] [{}] ",
        timestamp,
        file,
        line,
        func
    );

    let color = match level {
        LogLevel::Error => Color::Red,
        LogLevel::Warning => Color::Yellow,
        LogLevel::Info => Color::Green,
        LogLevel::Debug => Color::Blue,
        LogLevel::Trace => Color::Cyan,
        _ => Color::White,
    };

    output.push_str(&format!("{}", message));
    
    if let Some(ref mut f) = *LOG_FILE.lock().unwrap() {
        writeln!(f, "{}", output).unwrap();
        f.flush().unwrap();
    }

    if *LOG_CONSOLE.lock().unwrap() {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        stdout.set_color(ColorSpec::new().set_fg(Some(color))).unwrap();
        writeln!(stdout, "{}", output).unwrap();
        stdout.reset().unwrap();
    }
}

pub fn flush_logging() {
    if let Some(ref mut f) = *LOG_FILE.lock().unwrap() {
        f.flush().unwrap();
    }
}

pub fn close_logging() {
    *LOG_FILE.lock().unwrap() = None;
}

pub fn rotate_logs<P: AsRef<Path>>(
    filename: P, 
    max_size: u64
) -> io::Result<bool> {
    let path = filename.as_ref();
    if !path.exists() {
        return Ok(false);
    }

    let metadata = std::fs::metadata(path)?;
    if metadata.len() < max_size {
        return Ok(false);
    }

    let new_name = format!(
        "{}.{}",
        path.display(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    std::fs::rename(path, new_name)?;
    Ok(true)
}

#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)*) => {{
        $crate::utils::logging::log_message(
            $level,
            file!(),
            line!(),
            function_name!(),
            &format_args!($($arg)*)
        )
    }};
}