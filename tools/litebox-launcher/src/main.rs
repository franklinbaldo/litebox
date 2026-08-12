use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use age::secrecy::ExposeSecret;

struct Options {
    runner: PathBuf,
    initial_files: InitialFiles,
    program: OsString,
    environment: Vec<OsString>,
    arguments: Vec<OsString>,
}

enum InitialFiles {
    Plain(PathBuf),
    Age(PathBuf),
}

fn usage() -> &'static str {
    "Usage:\n  litebox [--runner PATH] (--initial-files ROOTFS.tar | \
     --encrypted-initial-files ROOTFS.tar.age) \
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

fn encrypt_usage() -> &'static str {
    "Usage: litebox encrypt --input ROOTFS.tar --output ROOTFS.tar.age"
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
                if initial_files.is_some() {
                    return Err("choose only one initial-files option".into());
                }
                initial_files = Some(InitialFiles::Plain(PathBuf::from(
                    input.next().ok_or("missing value for --initial-files")?,
                )));
            }
            Some("--encrypted-initial-files") => {
                if initial_files.is_some() {
                    return Err("choose only one initial-files option".into());
                }
                initial_files = Some(InitialFiles::Age(PathBuf::from(
                    input
                        .next()
                        .ok_or("missing value for --encrypted-initial-files")?,
                )));
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
    let initial_files_path = match &initial_files {
        InitialFiles::Plain(path) | InitialFiles::Age(path) => path,
    };
    if !initial_files_path.is_file() {
        return Err(format!(
            "initial-files TAR not found: {}",
            initial_files_path.display()
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

fn prompt_passphrase(prompt: &str) -> Result<age::secrecy::SecretString, String> {
    let value = rpassword::prompt_password(prompt).map_err(|error| error.to_string())?;
    if value.is_empty() {
        return Err("passphrase must not be empty".into());
    }
    Ok(age::secrecy::SecretString::from(value))
}

fn encrypt_tar(input: PathBuf, output: PathBuf) -> Result<(), String> {
    if !input.is_file() {
        return Err(format!("input TAR not found: {}", input.display()));
    }
    if output.exists() {
        return Err(format!("output already exists: {}", output.display()));
    }
    let passphrase = prompt_passphrase("Passphrase: ")?;
    let confirmation = prompt_passphrase("Confirm passphrase: ")?;
    if passphrase.expose_secret() != confirmation.expose_secret() {
        return Err("passphrases do not match".into());
    }

    let result = (|| {
        let source = File::open(&input).map_err(|error| error.to_string())?;
        let destination = File::create(&output).map_err(|error| error.to_string())?;
        encrypt_stream(
            BufReader::new(source),
            BufWriter::new(destination),
            passphrase,
        )
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&output);
        return Err(error);
    }
    Ok(())
}

fn encrypt_stream(
    mut source: impl Read,
    destination: impl Write,
    passphrase: age::secrecy::SecretString,
) -> Result<(), String> {
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut encrypted = encryptor
        .wrap_output(destination)
        .map_err(|error| error.to_string())?;
    std::io::copy(&mut source, &mut encrypted).map_err(|error| error.to_string())?;
    encrypted.finish().map_err(|error| error.to_string())?;
    Ok(())
}

fn parse_encrypt() -> Result<(PathBuf, PathBuf), String> {
    let mut input = None;
    let mut output = None;
    let mut arguments = std::env::args_os().skip(2);
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--input") => {
                input = Some(PathBuf::from(
                    arguments.next().ok_or("missing --input value")?,
                ))
            }
            Some("--output") => {
                output = Some(PathBuf::from(
                    arguments.next().ok_or("missing --output value")?,
                ));
            }
            Some("-h" | "--help") => return Err(encrypt_usage().into()),
            Some(value) => return Err(format!("unknown encrypt option: {value}")),
            None => return Err("encrypt options must be valid Unicode".into()),
        }
    }
    Ok((
        input.ok_or("--input is required")?,
        output.ok_or("--output is required")?,
    ))
}

fn decrypt_tar(input: &PathBuf) -> Result<tempfile::NamedTempFile, String> {
    let passphrase = prompt_passphrase("Passphrase: ")?;
    let source = File::open(input).map_err(|error| error.to_string())?;
    let mut temporary = tempfile::Builder::new()
        .prefix("litebox-")
        .suffix(".tar")
        .tempfile()
        .map_err(|error| error.to_string())?;
    decrypt_stream(BufReader::new(source), temporary.as_file_mut(), passphrase)?;
    temporary
        .as_file_mut()
        .flush()
        .map_err(|error| error.to_string())?;
    Ok(temporary)
}

fn decrypt_stream(
    source: impl Read,
    mut destination: impl Write,
    passphrase: age::secrecy::SecretString,
) -> Result<(), String> {
    let identity = age::scrypt::Identity::new(passphrase);
    let decryptor = age::Decryptor::new(source).map_err(|error| error.to_string())?;
    let mut decrypted = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|error| error.to_string())?;
    std::io::copy(&mut decrypted, &mut destination).map_err(|error| error.to_string())?;
    Ok(())
}

fn run(options: Options) -> Result<ExitCode, String> {
    let temporary;
    let initial_files = match &options.initial_files {
        InitialFiles::Plain(path) => path.as_path(),
        InitialFiles::Age(path) => {
            temporary = decrypt_tar(path)?;
            temporary.path()
        }
    };
    let mut command = Command::new(options.runner);
    command.arg("--initial-files").arg(initial_files);
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
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("encrypt")) {
        return match parse_encrypt().and_then(|(input, output)| encrypt_tar(input, output)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("{message}\n{}", encrypt_usage());
                ExitCode::FAILURE
            }
        };
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

#[cfg(test)]
mod tests {
    use super::{decrypt_stream, encrypt_stream};
    use age::secrecy::SecretString;

    #[test]
    fn age_round_trip_preserves_tar_bytes() {
        let plaintext = b"ustar test bytes\0\x01\x02";
        let mut encrypted = Vec::new();
        encrypt_stream(
            plaintext.as_slice(),
            &mut encrypted,
            SecretString::from("correct horse battery staple".to_owned()),
        )
        .unwrap();
        assert_ne!(encrypted, plaintext);

        let mut decrypted = Vec::new();
        decrypt_stream(
            encrypted.as_slice(),
            &mut decrypted,
            SecretString::from("correct horse battery staple".to_owned()),
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let mut encrypted = Vec::new();
        encrypt_stream(
            b"secret".as_slice(),
            &mut encrypted,
            SecretString::from("right passphrase".to_owned()),
        )
        .unwrap();

        let result = decrypt_stream(
            encrypted.as_slice(),
            Vec::new(),
            SecretString::from("wrong passphrase".to_owned()),
        );
        assert!(result.is_err());
    }
}
