use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

struct Options {
    runner: PathBuf,
    initial_files: PathBuf,
    program: OsString,
    environment: Vec<OsString>,
    arguments: Vec<OsString>,
}

fn usage() -> &'static str {
    "Usage: litebox [--runner PATH] --initial-files ROOTFS.tar \
     [--env NAME=VALUE]... --program /linux/path [--] [ARG]..."
}

fn default_runner(own_exe: &std::path::Path) -> PathBuf {
    let directory = own_exe
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let friendly = directory.join("litebox-runner.exe");
    if friendly.is_file() {
        friendly
    } else {
        directory.join("litebox_runner_linux_on_windows_userland.exe")
    }
}

fn parse() -> Result<Options, String> {
    let own_exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut runner = default_runner(&own_exe);
    let mut initial_files = None;
    let mut program = None;
    let mut environment = Vec::new();
    let mut arguments = Vec::new();
    let mut input = std::env::args_os().skip(1);

    while let Some(argument) = input.next() {
        if argument == "--" {
            arguments.extend(input);
            break;
        }
        match argument.to_str() {
            Some("--runner") => {
                runner = PathBuf::from(input.next().ok_or("missing value for --runner")?);
            }
            Some("--initial-files") => {
                initial_files = Some(PathBuf::from(
                    input.next().ok_or("missing value for --initial-files")?,
                ));
            }
            Some("--program") => program = Some(input.next().ok_or("missing value for --program")?),
            Some("--env") => {
                let value = input.next().ok_or("missing value for --env")?;
                let text = value.to_string_lossy();
                let Some((name, _)) = text.split_once('=') else {
                    return Err("--env requires NAME=VALUE".into());
                };
                if name.is_empty()
                    || !name.bytes().enumerate().all(|(index, byte)| {
                        byte == b'_'
                            || byte.is_ascii_alphabetic()
                            || (index > 0 && byte.is_ascii_digit())
                    })
                {
                    return Err(format!("invalid environment name: {name}"));
                }
                environment.push(value);
            }
            Some("-h" | "--help") => return Err(usage().into()),
            Some(flag) if flag.starts_with('-') => return Err(format!("unknown option: {flag}")),
            _ => arguments.push(argument),
        }
    }

    let initial_files = initial_files.ok_or("--initial-files is required")?;
    let program = program.ok_or("--program is required")?;
    if !runner.is_file() {
        return Err(format!("runner not found: {}", runner.display()));
    }
    if !initial_files.is_file() {
        return Err(format!(
            "initial-files TAR not found: {}",
            initial_files.display()
        ));
    }
    Ok(Options {
        runner,
        initial_files,
        program,
        environment,
        arguments,
    })
}

fn run(options: Options) -> Result<ExitCode, String> {
    let mut command = Command::new(options.runner);
    command.arg("--initial-files").arg(options.initial_files);
    for item in options.environment {
        command.arg("--env").arg(item);
    }
    command.arg(options.program).args(options.arguments);
    let status = command.status().map_err(|error| error.to_string())?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn main() -> ExitCode {
    if std::env::args_os().len() == 1 {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }
    if std::env::args_os()
        .skip(1)
        .any(|arg| arg == "-h" || arg == "--help")
    {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }
    match parse().and_then(run) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}\n{}", usage());
            ExitCode::FAILURE
        }
    }
}
