// Dockerfile parser — minimal parser for container build instructions.

use std::path::Path;

use anyhow::{bail, Result};

/// A parsed Dockerfile instruction.
#[derive(Debug, Clone)]
pub enum Instruction {
    From { image: String },
    Run { command: String },
    Copy { sources: Vec<String>, dest: String },
    Add { sources: Vec<String>, dest: String },
    Env { key: String, value: String },
    Workdir { path: String },
    Entrypoint { exec: Vec<String> },
    Cmd { exec: Vec<String> },
}

/// Parse a Dockerfile from a file path.
pub fn parse_file(path: &Path) -> Result<Vec<Instruction>> {
    let content = std::fs::read_to_string(path)?;
    parse(&content)
}

/// Parse Dockerfile content from a string.
pub fn parse(content: &str) -> Result<Vec<Instruction>> {
    let logical_lines = join_continuation_lines(content);
    let mut instructions = Vec::new();

    for line in &logical_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (keyword, rest) = split_first_word(trimmed);
        let rest = rest.trim();

        match keyword.to_ascii_uppercase().as_str() {
            "FROM" => {
                instructions.push(Instruction::From {
                    image: rest.to_string(),
                });
            }
            "RUN" => {
                instructions.push(Instruction::Run {
                    command: rest.to_string(),
                });
            }
            "COPY" => {
                let (sources, dest) = parse_copy_add_args(rest, "COPY")?;
                instructions.push(Instruction::Copy { sources, dest });
            }
            "ADD" => {
                let (sources, dest) = parse_copy_add_args(rest, "ADD")?;
                instructions.push(Instruction::Add { sources, dest });
            }
            "ENV" => {
                let (key, value) = parse_env_args(rest)?;
                instructions.push(Instruction::Env { key, value });
            }
            "WORKDIR" => {
                instructions.push(Instruction::Workdir {
                    path: rest.to_string(),
                });
            }
            "ENTRYPOINT" => {
                let exec = parse_exec_form_or_shell(rest);
                instructions.push(Instruction::Entrypoint { exec });
            }
            "CMD" => {
                let exec = parse_exec_form_or_shell(rest);
                instructions.push(Instruction::Cmd { exec });
            }
            _ => {
                // Unsupported instructions are silently ignored.
            }
        }
    }

    Ok(instructions)
}

/// Join lines ending with `\` with their continuation lines.
fn join_continuation_lines(content: &str) -> Vec<String> {
    let mut logical_lines = Vec::new();
    let mut current = String::new();

    for line in content.lines() {
        if let Some(prefix) = line.strip_suffix('\\') {
            current.push_str(prefix);
            current.push('\n');
        } else {
            current.push_str(line);
            logical_lines.push(std::mem::take(&mut current));
        }
    }

    // If the file ends with a continuation line (no final newline after `\`),
    // flush whatever remains.
    if !current.is_empty() {
        logical_lines.push(current);
    }

    logical_lines
}

/// Split a line into the first whitespace-delimited word and the remainder.
fn split_first_word(s: &str) -> (&str, &str) {
    match s.split_once(char::is_whitespace) {
        Some((word, rest)) => (word, rest),
        None => (s, ""),
    }
}

/// Parse COPY/ADD arguments: split by whitespace, last is dest, rest are sources.
fn parse_copy_add_args(rest: &str, keyword: &str) -> Result<(Vec<String>, String)> {
    let args: Vec<&str> = rest.split_whitespace().collect();
    if args.len() < 2 {
        bail!("{keyword} requires at least a source and a destination");
    }
    let dest = args[args.len() - 1].to_string();
    let sources = args[..args.len() - 1]
        .iter()
        .copied()
        .map(String::from)
        .collect();
    Ok((sources, dest))
}

/// Parse ENV arguments. Supports `KEY=VALUE` and `KEY VALUE` forms.
fn parse_env_args(rest: &str) -> Result<(String, String)> {
    // Try KEY=VALUE form first.
    if let Some((key, value)) = rest.split_once('=') {
        let key = key.trim().to_string();
        let value = value.trim().to_string();
        return Ok((key, value));
    }

    // Fall back to KEY VALUE form (split on first whitespace).
    let (key, value) = split_first_word(rest);
    if value.is_empty() {
        bail!("ENV requires a key and value");
    }
    Ok((key.to_string(), value.trim().to_string()))
}

/// Parse exec form `["arg1", "arg2"]` or shell form `command args...`.
fn parse_exec_form_or_shell(rest: &str) -> Vec<String> {
    let trimmed = rest.trim();
    if trimmed.starts_with('[') {
        // Try JSON array parse.
        if let Ok(arr) = serde_json::from_str::<Vec<String>>(trimmed) {
            return arr;
        }
    }
    // Shell form: wrap in /bin/sh -c.
    vec!["/bin/sh".to_string(), "-c".to_string(), trimmed.to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_dockerfile() {
        let input = r#"
FROM alpine:latest
ENV LANG=C.UTF-8
WORKDIR /app
RUN apk add --no-cache curl
COPY src/ /app/src/
ENTRYPOINT ["python3"]
CMD ["app.py"]
"#;
        let instructions = parse(input).unwrap();
        assert_eq!(instructions.len(), 7);
        assert!(
            matches!(&instructions[0], Instruction::From { image } if image == "alpine:latest")
        );
        assert!(
            matches!(&instructions[1], Instruction::Env { key, value } if key == "LANG" && value == "C.UTF-8")
        );
        assert!(matches!(&instructions[2], Instruction::Workdir { path } if path == "/app"));
        assert!(
            matches!(&instructions[3], Instruction::Run { command } if command == "apk add --no-cache curl")
        );
        assert!(
            matches!(&instructions[4], Instruction::Copy { sources, dest } if sources == &["src/"] && dest == "/app/src/")
        );
        assert!(
            matches!(&instructions[5], Instruction::Entrypoint { exec } if exec == &["python3"])
        );
        assert!(matches!(&instructions[6], Instruction::Cmd { exec } if exec == &["app.py"]));
    }

    #[test]
    fn parse_line_continuation() {
        let input = "RUN apt-get update && \\\n    apt-get install -y curl";
        let instructions = parse(input).unwrap();
        assert_eq!(instructions.len(), 1);
        match &instructions[0] {
            Instruction::Run { command } => {
                assert!(command.contains("apt-get update"));
                assert!(command.contains("apt-get install"));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_comments_and_blanks() {
        let input = "# comment\n\nFROM ubuntu\n# another\nRUN echo hi";
        let instructions = parse(input).unwrap();
        assert_eq!(instructions.len(), 2);
    }

    #[test]
    fn parse_env_space_form() {
        let input = "ENV MY_VAR my_value";
        let instructions = parse(input).unwrap();
        assert!(
            matches!(&instructions[0], Instruction::Env { key, value } if key == "MY_VAR" && value == "my_value")
        );
    }

    #[test]
    fn parse_shell_form_entrypoint() {
        let input = "ENTRYPOINT /bin/myapp --flag";
        let instructions = parse(input).unwrap();
        assert!(
            matches!(&instructions[0], Instruction::Entrypoint { exec } if exec == &["/bin/sh", "-c", "/bin/myapp --flag"])
        );
    }

    #[test]
    fn parse_case_insensitive() {
        let input = "from ubuntu\nrun echo hi\nenv FOO=bar";
        let instructions = parse(input).unwrap();
        assert_eq!(instructions.len(), 3);
    }

    #[test]
    fn parse_copy_multiple_sources() {
        let input = "COPY file1.txt file2.txt /dest/";
        let instructions = parse(input).unwrap();
        assert!(
            matches!(&instructions[0], Instruction::Copy { sources, dest } if sources == &["file1.txt", "file2.txt"] && dest == "/dest/")
        );
    }
}
