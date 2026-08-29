use std::fmt::Arguments;

const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";

pub(crate) fn status(code: u16, message: Arguments<'_>) {
    let color = match code {
        200..=399 => GREEN,
        400..=499 => YELLOW,
        _ => RED,
    };
    write(color, message);
}

pub(crate) fn success(message: Arguments<'_>) {
    write(GREEN, message);
}

pub(crate) fn warning(message: Arguments<'_>) {
    write(YELLOW, message);
}

pub(crate) fn error(message: Arguments<'_>) {
    write(RED, message);
}

fn write(color: &str, message: Arguments<'_>) {
    if std::env::var_os("NO_COLOR").is_some() {
        eprintln!("{message}");
    } else {
        eprintln!("{color}{message}{RESET}");
    }
}
