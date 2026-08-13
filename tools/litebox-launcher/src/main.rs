use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use age::secrecy::ExposeSecret;
use clap::{Args, CommandFactory, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "litebox",
    version,
    about = "Run and manage LiteBox Linux filesystems"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a Linux program from a TAR filesystem.
    Run(RunArgs),
    /// Build, inspect, or encrypt filesystem images.
    Image(ImageArgs),
    /// Inspect hardware capabilities supported by this backend.
    Hardware(HardwareArgs),
    /// Rewrite syscall instructions in a Linux ELF.
    Rewrite(RewriteArgs),
    /// Check whether the local installation is usable.
    Doctor,
    /// Print LiteBox tool versions.
    Version,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent CLI switches, not application state.
struct RunArgs {
    /// Toy hardware capability. May be repeated or comma-separated.
    #[arg(long, value_delimiter = ',', default_value = "none")]
    hardware: Vec<String>,
    /// Pass NAME=VALUE to the Linux program. May be repeated.
    #[arg(short = 'e', long = "env", value_parser = validate_environment)]
    environment: Vec<String>,
    /// Forward the entire Windows environment. This may disclose credentials.
    #[arg(long)]
    forward_env: bool,
    /// Enable unstable runner behavior.
    #[arg(short = 'Z', long)]
    unstable: bool,
    /// Treat IMAGE as a passphrase-encrypted age file.
    #[arg(long, conflicts_with = "plain")]
    encrypted: bool,
    /// Treat IMAGE as a plaintext TAR even if its name ends in .age.
    #[arg(long, conflicts_with = "encrypted")]
    plain: bool,
    /// TAR or passphrase-encrypted TAR filesystem.
    image: PathBuf,
    /// Linux executable path inside IMAGE.
    program: String,
    /// Arguments passed to PROGRAM.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    arguments: Vec<String>,
}

#[derive(Args, Debug)]
struct ImageArgs {
    #[command(subcommand)]
    command: ImageCommand,
}

#[derive(Args, Debug)]
struct HardwareArgs {
    #[command(subcommand)]
    command: HardwareCommand,
}

#[derive(Subcommand, Debug)]
enum HardwareCommand {
    /// Show inherent, available, and unavailable hardware capabilities.
    Inspect {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ImageCommand {
    /// Build a TAR filesystem from a public OCI image.
    Build(ImageBuildArgs),
    /// List entries in a plaintext TAR filesystem.
    Inspect(ImageInspectArgs),
    /// Encrypt a TAR with an age passphrase.
    Encrypt(ImageEncryptArgs),
}

#[derive(Args, Debug)]
struct ImageBuildArgs {
    /// Public OCI image reference, for example docker.io/library/alpine:3.22.
    #[arg(long)]
    oci: String,
    /// Destination TAR path.
    #[arg(short, long)]
    output: PathBuf,
    /// Print detailed packaging output.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Args, Debug)]
struct ImageInspectArgs {
    /// Plaintext TAR to inspect.
    image: PathBuf,
}

#[derive(Args, Debug)]
struct ImageEncryptArgs {
    /// Plaintext input TAR.
    input: PathBuf,
    /// Encrypted output file. Defaults to INPUT.age.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct RewriteArgs {
    /// Linux ELF input file.
    input: PathBuf,
    /// Rewritten output file. Defaults to INPUT.hooked.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Override the trampoline address.
    #[arg(long)]
    trampoline_addr: Option<u64>,
}

fn validate_environment(value: &str) -> Result<String, String> {
    let Some((name, _)) = value.split_once('=') else {
        return Err("expected NAME=VALUE".into());
    };
    if name.is_empty()
        || !name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
    {
        return Err(format!("invalid environment name: {name}"));
    }
    Ok(value.to_owned())
}

fn prompt_passphrase(prompt: &str) -> Result<age::secrecy::SecretString, String> {
    let value = rpassword::prompt_password(prompt).map_err(|error| error.to_string())?;
    if value.is_empty() {
        return Err("passphrase must not be empty".into());
    }
    Ok(age::secrecy::SecretString::from(value))
}

fn encrypt_image(args: ImageEncryptArgs) -> Result<(), String> {
    if !args.input.is_file() {
        return Err(format!("input TAR not found: {}", args.input.display()));
    }
    let output = args.output.unwrap_or_else(|| {
        let mut name = args.input.as_os_str().to_owned();
        name.push(".age");
        PathBuf::from(name)
    });
    if output.exists() {
        return Err(format!("output already exists: {}", output.display()));
    }
    let passphrase = prompt_passphrase("Passphrase: ")?;
    let confirmation = prompt_passphrase("Confirm passphrase: ")?;
    if passphrase.expose_secret() != confirmation.expose_secret() {
        return Err("passphrases do not match".into());
    }
    let result = (|| {
        let source = File::open(&args.input).map_err(|error| error.to_string())?;
        let destination = File::create(&output).map_err(|error| error.to_string())?;
        encrypt_stream(
            BufReader::new(source),
            BufWriter::new(destination),
            passphrase,
        )
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(output);
        return Err(error);
    }
    println!("Encrypted image created: {}", output.display());
    Ok(())
}

fn encrypt_stream(
    mut source: impl Read,
    destination: impl Write,
    passphrase: age::secrecy::SecretString,
) -> Result<(), String> {
    let mut encrypted = age::Encryptor::with_user_passphrase(passphrase)
        .wrap_output(destination)
        .map_err(|error| error.to_string())?;
    std::io::copy(&mut source, &mut encrypted).map_err(|error| error.to_string())?;
    encrypted.finish().map_err(|error| error.to_string())?;
    Ok(())
}

fn decrypt_image(input: &Path) -> Result<tempfile::NamedTempFile, String> {
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

fn run(args: RunArgs) -> Result<(), String> {
    if !args.image.is_file() {
        return Err(format!("image not found: {}", args.image.display()));
    }
    let hardware_capabilities = resolve_hardware(&args.hardware)?;
    let encrypted =
        args.encrypted || (!args.plain && args.image.extension().is_some_and(|x| x == "age"));
    let temporary;
    let image = if encrypted {
        temporary = decrypt_image(&args.image)?;
        temporary.path().to_owned()
    } else {
        args.image
    };
    let mut program_and_arguments = vec![args.program];
    program_and_arguments.extend(args.arguments);
    litebox_runner_linux_on_windows_userland::run(
        litebox_runner_linux_on_windows_userland::CliArgs {
            program_and_arguments,
            environment_variables: args.environment,
            forward_environment_variables: args.forward_env,
            unstable: args.unstable,
            initial_files: image,
            hardware_capabilities,
        },
    )
    .map_err(|error| format!("runner failed: {error:#}"))
}

fn resolve_hardware(
    requested: &[String],
) -> Result<Vec<litebox_runner_linux_on_windows_userland::hardware::HardwareCapability>, String> {
    use litebox_runner_linux_on_windows_userland::hardware;

    if requested.len() != 1 && requested.iter().any(|value| value == "none") {
        return Err("hardware 'none' cannot be combined with other capabilities".into());
    }
    if requested.len() != 1
        && requested
            .iter()
            .any(|value| matches!(value.as_str(), "safe" | "host"))
    {
        return Err("hardware profiles cannot be combined with explicit capabilities".into());
    }
    if requested == ["none"] {
        return Ok(Vec::new());
    }
    if requested == ["safe"] {
        return Ok(hardware::safe_capabilities());
    }
    if requested == ["host"] {
        return Ok(hardware::host_capabilities());
    }
    let mut result = Vec::new();
    for name in requested {
        let info = hardware::capability_by_name(name)
            .ok_or_else(|| format!("unknown hardware capability: {name}"))?;
        if info.kind == hardware::CapabilityKind::Inherent {
            return Err(format!(
                "hardware capability '{name}' is inherent and cannot be granted"
            ));
        }
        if !info.available {
            return Err(format!(
                "hardware capability '{name}' is not implemented by windows-userland"
            ));
        }
        let capability = hardware::brokered_by_name(name)
            .ok_or_else(|| format!("hardware capability '{name}' has no backend"))?;
        if !result.contains(&capability) {
            result.push(capability);
        }
    }
    Ok(result)
}

fn inspect_hardware(json: bool) {
    use litebox_runner_linux_on_windows_userland::hardware::{CAPABILITIES, CapabilityKind};

    if json {
        println!("[{}\n]", CAPABILITIES.iter().map(|capability| format!(
            "  {{\"name\":\"{}\",\"kind\":\"{}\",\"backend\":\"{}\",\"available\":{},\"safe\":{},\"description\":\"{}\"}}",
            capability.name,
            match capability.kind { CapabilityKind::Inherent => "inherent", CapabilityKind::Brokered => "brokered" },
            capability.backend, capability.available, capability.safe, capability.description
        )).collect::<Vec<_>>().join(",\n"));
        return;
    }
    println!(
        "{:<12} {:<10} {:<20} {:<11} DESCRIPTION",
        "CAPABILITY", "KIND", "BACKEND", "STATUS"
    );
    for capability in CAPABILITIES {
        println!(
            "{:<12} {:<10} {:<20} {:<11} {}",
            capability.name,
            match capability.kind {
                CapabilityKind::Inherent => "inherent",
                CapabilityKind::Brokered => "brokered",
            },
            capability.backend,
            if capability.available {
                "available"
            } else {
                "unavailable"
            },
            capability.description
        );
    }
}

fn inspect_image(args: ImageInspectArgs) -> Result<(), String> {
    let file = File::open(&args.image).map_err(|error| error.to_string())?;
    let mut archive = tar::Archive::new(BufReader::new(file));
    for entry in archive.entries().map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        println!(
            "{}",
            entry.path().map_err(|error| error.to_string())?.display()
        );
    }
    Ok(())
}

fn build_image(args: ImageBuildArgs) -> Result<(), String> {
    litebox_packager::run(litebox_packager::CliArgs {
        input_files: Vec::new(),
        oci_image: Some(args.oci),
        output: args.output,
        include: Vec::new(),
        no_rewrite: Vec::new(),
        verbose: args.verbose,
    })
    .map_err(|error| format!("image build failed: {error:#}"))
}

fn rewrite(args: RewriteArgs) -> Result<(), String> {
    let input = std::fs::read(&args.input).map_err(|error| error.to_string())?;
    let rewritten = litebox_syscall_rewriter::hook_syscalls_in_elf(&input, args.trampoline_addr)
        .map_err(|error| error.to_string())?;
    let output = args.output.unwrap_or_else(|| {
        let mut name = args.input.as_os_str().to_owned();
        name.push(".hooked");
        PathBuf::from(name)
    });
    std::fs::write(&output, rewritten).map_err(|error| error.to_string())?;
    println!("Rewritten ELF created: {}", output.display());
    Ok(())
}

fn doctor() -> Result<(), String> {
    if !cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        return Err("the Windows-userland runner requires Windows x86-64".into());
    }
    let own_exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let directory = own_exe.parent().ok_or("cannot determine tool directory")?;
    let tools = [
        "litebox-runner.exe",
        "litebox-rewriter.exe",
        "litebox-packager.exe",
    ];
    for tool in tools {
        let path = directory.join(tool);
        if !path.is_file() {
            return Err(format!("missing installed tool: {}", path.display()));
        }
        println!("ok  {}", path.display());
    }
    println!("ok  Windows x86-64");
    Ok(())
}

fn execute(command: Command) -> Result<(), String> {
    match command {
        Command::Run(args) => run(args),
        Command::Image(args) => match args.command {
            ImageCommand::Build(args) => build_image(args),
            ImageCommand::Inspect(args) => inspect_image(args),
            ImageCommand::Encrypt(args) => encrypt_image(args),
        },
        Command::Hardware(args) => {
            let HardwareCommand::Inspect { json } = args.command;
            inspect_hardware(json);
            Ok(())
        }
        Command::Rewrite(args) => rewrite(args),
        Command::Doctor => doctor(),
        Command::Version => {
            println!("litebox {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command()
            .print_help()
            .expect("stdout should be writable");
        println!();
        return ExitCode::SUCCESS;
    };
    match execute(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, decrypt_stream, encrypt_stream, resolve_hardware};
    use age::secrecy::SecretString;
    use clap::Parser;

    #[test]
    fn parses_docker_like_run() {
        let cli = Cli::try_parse_from([
            "litebox",
            "run",
            "-e",
            "HOME=/tmp",
            "rootfs.tar",
            "/bin/sh",
            "-c",
            "echo ok",
        ])
        .unwrap();
        let Some(Command::Run(args)) = cli.command else {
            panic!("expected run")
        };
        assert_eq!(args.image.to_string_lossy(), "rootfs.tar");
        assert_eq!(args.program, "/bin/sh");
        assert_eq!(args.arguments, ["-c", "echo ok"]);
    }

    #[test]
    fn rejects_invalid_environment_name() {
        assert!(
            Cli::try_parse_from(["litebox", "run", "-e", "1BAD=x", "x.tar", "/bin/sh"]).is_err()
        );
    }

    #[test]
    fn resolves_hardware_profiles_and_explicit_capabilities() {
        assert!(resolve_hardware(&["none".into()]).unwrap().is_empty());
        assert_eq!(resolve_hardware(&["safe".into()]).unwrap().len(), 2);
        assert_eq!(resolve_hardware(&["host".into()]).unwrap().len(), 2);
        assert_eq!(
            resolve_hardware(&["hostinfo".into(), "power".into()])
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn rejects_invalid_hardware_requests() {
        assert!(resolve_hardware(&["cpu".into()]).is_err());
        assert!(resolve_hardware(&["gpu".into()]).is_err());
        assert!(resolve_hardware(&["unknown".into()]).is_err());
        assert!(resolve_hardware(&["none".into(), "power".into()]).is_err());
        assert!(resolve_hardware(&["safe".into(), "power".into()]).is_err());
    }

    #[test]
    fn age_round_trip_preserves_bytes() {
        let plaintext = b"ustar test bytes\0\x01\x02";
        let mut encrypted = Vec::new();
        encrypt_stream(
            plaintext.as_slice(),
            &mut encrypted,
            SecretString::from("passphrase".to_owned()),
        )
        .unwrap();
        let mut decrypted = Vec::new();
        decrypt_stream(
            encrypted.as_slice(),
            &mut decrypted,
            SecretString::from("passphrase".to_owned()),
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
