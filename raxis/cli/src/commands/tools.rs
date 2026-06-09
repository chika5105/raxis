// raxis-cli::commands::tools — local custom-tool authoring helpers.
//
// These commands never grant authority by themselves. They edit and
// validate plan.toml so the signed plan contains narrow, explicit
// custom-tool capabilities before the kernel admits it.

use std::path::{Path, PathBuf};

use crate::errors::CliError;
use crate::GlobalFlags;
use raxis_tool_authoring::{
    append_custom_tool, attach_profile_to_task, dry_run_tool, find_tool, normalize_tool_schema,
    read_json_arg, validate_plan_tools, CustomToolSpec, DEFAULT_STDERR_MAX_BYTES,
    DEFAULT_STDIN_MAX_BYTES, DEFAULT_STDOUT_MAX_BYTES, DEFAULT_TIMEOUT_SECONDS,
};

pub fn run_add(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_add_help();
        return Ok(());
    }
    let opts = parse_add_args(args)?;
    let plan_text = read_plan(&opts.plan)?;
    let schema_text = match opts.schema {
        None => None,
        Some(SchemaInput::Inline(s)) => Some(s),
        Some(SchemaInput::File(path)) => Some(read_plan(&path)?),
    };
    let schema = normalize_tool_schema(schema_text.as_deref())
        .map_err(|e| CliError::Usage(format!("tools add: {e}")))?;
    let spec = CustomToolSpec {
        profile: opts.profile,
        name: opts.name,
        description: opts.description,
        command: opts.command,
        execution_locality: opts.execution_locality,
        schema,
        timeout_seconds: opts.timeout_seconds,
        stdin_max_bytes: opts.stdin_max_bytes,
        stdout_max_bytes: opts.stdout_max_bytes,
        stderr_max_bytes: opts.stderr_max_bytes,
        expose_stderr: opts.expose_stderr,
    };
    let updated = append_custom_tool(&plan_text, &spec)
        .map_err(|e| CliError::Usage(format!("tools add: {e}")))?;
    write_plan(&opts.plan, &updated)?;
    println!(
        "tools add: added {} to profile {} in {}.",
        spec.name,
        spec.profile,
        opts.plan.display()
    );
    println!(
        "Next: attach it with `raxis tools attach --plan {} --task <task_name> --profile {}`.",
        opts.plan.display(),
        spec.profile
    );
    Ok(())
}

pub fn run_attach(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_attach_help();
        return Ok(());
    }
    let opts = parse_attach_args(args)?;
    let plan_text = read_plan(&opts.plan)?;
    let updated = attach_profile_to_task(&plan_text, &opts.task, &opts.profile)
        .map_err(|e| CliError::Usage(format!("tools attach: {e}")))?;
    write_plan(&opts.plan, &updated)?;
    println!(
        "tools attach: attached profile {} to task {} in {}.",
        opts.profile,
        opts.task,
        opts.plan.display()
    );
    Ok(())
}

pub fn run_validate(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: raxis tools validate <plan.toml>");
        println!("   or: raxis tools validate --plan <plan.toml>");
        return Ok(());
    }
    let plan = parse_plan_path(args, "tools validate")?;
    let plan_text = read_plan(&plan)?;
    let report = validate_plan_tools(&plan_text);
    println!("Tool validation: {}", plan.display());
    println!(
        "  [OK] {} custom tool declaration(s) parsed",
        report.tool_count
    );
    for warning in &report.warnings {
        println!("  [WARN] {warning}");
    }
    for error in &report.errors {
        println!("  [FAIL] {error}");
    }
    if report.is_ok() {
        Ok(())
    } else {
        Err(CliError::Usage(format!(
            "tools validate found {} error(s)",
            report.errors.len()
        )))
    }
}

pub fn run_test(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_test_help();
        return Ok(());
    }
    let opts = parse_test_args(args)?;
    let plan_text = read_plan(&opts.plan)?;
    let input = read_json_arg(&opts.input, Path::new("."))
        .map_err(|e| CliError::Usage(format!("tools test: {e}")))?;
    let spec = find_tool(&plan_text, &opts.profile, &opts.tool)
        .map_err(|e| CliError::Usage(format!("tools test: {e}")))?;
    let output =
        dry_run_tool(&spec, &input).map_err(|e| CliError::Usage(format!("tools test: {e}")))?;
    println!(
        "Tool dry-run: {} / {} ({})",
        spec.profile, spec.name, spec.execution_locality
    );
    if output.timed_out {
        println!("  status: timed out after {}s", spec.timeout_seconds);
    } else {
        println!("  status: exit {:?}", output.status_code);
    }
    println!(
        "  stdout{}:\n{}",
        if output.stdout_truncated {
            " (truncated)"
        } else {
            ""
        },
        output.stdout
    );
    if !output.stderr.is_empty() || output.stderr_truncated {
        println!(
            "  stderr{}:\n{}",
            if output.stderr_truncated {
                " (truncated)"
            } else {
                ""
            },
            output.stderr
        );
    }
    Ok(())
}

#[derive(Debug)]
struct AddOpts {
    plan: PathBuf,
    profile: String,
    name: String,
    description: String,
    command: Vec<String>,
    execution_locality: String,
    schema: Option<SchemaInput>,
    timeout_seconds: u32,
    stdin_max_bytes: u64,
    stdout_max_bytes: u64,
    stderr_max_bytes: u64,
    expose_stderr: bool,
}

#[derive(Debug)]
enum SchemaInput {
    Inline(String),
    File(PathBuf),
}

#[derive(Debug)]
struct AttachOpts {
    plan: PathBuf,
    task: String,
    profile: String,
}

#[derive(Debug)]
struct TestOpts {
    plan: PathBuf,
    profile: String,
    tool: String,
    input: String,
}

fn parse_add_args(args: &[String]) -> Result<AddOpts, CliError> {
    let mut plan = None;
    let mut profile = None;
    let mut name = None;
    let mut description = None;
    let mut command_head = None::<String>;
    let mut command_args = Vec::new();
    let mut command_json = None::<String>;
    let mut execution_locality = "guest_subprocess".to_owned();
    let mut schema = None;
    let mut timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    let mut stdin_max_bytes = DEFAULT_STDIN_MAX_BYTES;
    let mut stdout_max_bytes = DEFAULT_STDOUT_MAX_BYTES;
    let mut stderr_max_bytes = DEFAULT_STDERR_MAX_BYTES;
    let mut expose_stderr = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--plan" => {
                plan = Some(PathBuf::from(require_value(args, &mut i, "--plan")?));
            }
            "--profile" => profile = Some(require_value(args, &mut i, "--profile")?.to_owned()),
            "--name" => name = Some(require_value(args, &mut i, "--name")?.to_owned()),
            "--description" => {
                description = Some(require_value(args, &mut i, "--description")?.to_owned());
            }
            "--command" => {
                command_head = Some(require_value(args, &mut i, "--command")?.to_owned());
            }
            "--command-arg" => {
                command_args.push(require_value(args, &mut i, "--command-arg")?.to_owned());
            }
            "--command-json" => {
                command_json = Some(require_value(args, &mut i, "--command-json")?.to_owned());
            }
            "--locality" | "--execution-locality" => {
                execution_locality = require_value(args, &mut i, "--locality")?.to_owned();
            }
            "--schema" | "--tool-schema" => {
                let raw = require_value(args, &mut i, "--schema")?;
                schema = Some(if let Some(path) = raw.strip_prefix('@') {
                    SchemaInput::File(PathBuf::from(path))
                } else {
                    SchemaInput::Inline(raw.to_owned())
                });
            }
            "--schema-file" | "--tool-schema-file" => {
                schema = Some(SchemaInput::File(PathBuf::from(require_value(
                    args,
                    &mut i,
                    "--schema-file",
                )?)));
            }
            "--timeout" | "--timeout-seconds" => {
                timeout_seconds =
                    parse_u32(require_value(args, &mut i, "--timeout")?, "--timeout")?;
            }
            "--stdin-max-bytes" => {
                stdin_max_bytes = parse_u64(
                    require_value(args, &mut i, "--stdin-max-bytes")?,
                    "--stdin-max-bytes",
                )?;
            }
            "--stdout-max-bytes" => {
                stdout_max_bytes = parse_u64(
                    require_value(args, &mut i, "--stdout-max-bytes")?,
                    "--stdout-max-bytes",
                )?;
            }
            "--stderr-max-bytes" => {
                stderr_max_bytes = parse_u64(
                    require_value(args, &mut i, "--stderr-max-bytes")?,
                    "--stderr-max-bytes",
                )?;
            }
            "--expose-stderr" => expose_stderr = true,
            "--help" | "-h" => {
                unreachable!("handled before parse_add_args")
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{other}`; see `raxis tools add --help`"
                )));
            }
        }
        i += 1;
    }

    let command = match (command_json, command_head) {
        (Some(raw), None) => serde_json::from_str::<Vec<String>>(&raw).map_err(|e| {
            CliError::Usage(format!("--command-json must be a JSON string array: {e}"))
        })?,
        (None, Some(head)) => {
            let mut argv = vec![head];
            argv.extend(command_args);
            argv
        }
        (Some(_), Some(_)) => {
            return Err(CliError::Usage(
                "use either --command/--command-arg or --command-json, not both".to_owned(),
            ));
        }
        (None, None) => {
            return Err(CliError::Usage(
                "tools add requires --command <absolute-path> or --command-json '[...]'".to_owned(),
            ));
        }
    };

    Ok(AddOpts {
        plan: plan.ok_or_else(|| CliError::Usage("tools add requires --plan <path>".to_owned()))?,
        profile: profile
            .ok_or_else(|| CliError::Usage("tools add requires --profile <name>".to_owned()))?,
        name: name.ok_or_else(|| CliError::Usage("tools add requires --name <tool>".to_owned()))?,
        description: description
            .ok_or_else(|| CliError::Usage("tools add requires --description <text>".to_owned()))?,
        command,
        execution_locality,
        schema,
        timeout_seconds,
        stdin_max_bytes,
        stdout_max_bytes,
        stderr_max_bytes,
        expose_stderr,
    })
}

fn parse_attach_args(args: &[String]) -> Result<AttachOpts, CliError> {
    let mut plan = None;
    let mut task = None;
    let mut profile = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--plan" => plan = Some(PathBuf::from(require_value(args, &mut i, "--plan")?)),
            "--task" => task = Some(require_value(args, &mut i, "--task")?.to_owned()),
            "--profile" => profile = Some(require_value(args, &mut i, "--profile")?.to_owned()),
            "--help" | "-h" => {
                unreachable!("handled before parse_attach_args")
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{other}`; see `raxis tools attach --help`"
                )));
            }
        }
        i += 1;
    }
    Ok(AttachOpts {
        plan: plan
            .ok_or_else(|| CliError::Usage("tools attach requires --plan <path>".to_owned()))?,
        task: task
            .ok_or_else(|| CliError::Usage("tools attach requires --task <id>".to_owned()))?,
        profile: profile
            .ok_or_else(|| CliError::Usage("tools attach requires --profile <name>".to_owned()))?,
    })
}

fn parse_test_args(args: &[String]) -> Result<TestOpts, CliError> {
    let mut plan = None;
    let mut profile = None;
    let mut tool = None;
    let mut input = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--plan" => plan = Some(PathBuf::from(require_value(args, &mut i, "--plan")?)),
            "--profile" => profile = Some(require_value(args, &mut i, "--profile")?.to_owned()),
            "--tool" | "--name" => tool = Some(require_value(args, &mut i, "--tool")?.to_owned()),
            "--input" | "--input-json" => {
                input = Some(require_value(args, &mut i, "--input")?.to_owned());
            }
            "--input-file" => {
                input = Some(format!("@{}", require_value(args, &mut i, "--input-file")?));
            }
            "--help" | "-h" => {
                unreachable!("handled before parse_test_args")
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{other}`; see `raxis tools test --help`"
                )));
            }
        }
        i += 1;
    }
    Ok(TestOpts {
        plan: plan
            .ok_or_else(|| CliError::Usage("tools test requires --plan <path>".to_owned()))?,
        profile: profile
            .ok_or_else(|| CliError::Usage("tools test requires --profile <name>".to_owned()))?,
        tool: tool
            .ok_or_else(|| CliError::Usage("tools test requires --tool <name>".to_owned()))?,
        input: input.unwrap_or_else(|| "{}".to_owned()),
    })
}

fn parse_plan_path(args: &[String], command: &str) -> Result<PathBuf, CliError> {
    if args.len() == 2 && args[0] == "--plan" {
        return Ok(PathBuf::from(&args[1]));
    }
    if args.len() == 1 && !args[0].starts_with("--") {
        return Ok(PathBuf::from(&args[0]));
    }
    Err(CliError::Usage(format!(
        "{command} requires <plan.toml> or --plan <plan.toml>"
    )))
}

fn require_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, CliError> {
    *i += 1;
    args.get(*i)
        .map(|s| s.as_str())
        .ok_or_else(|| CliError::Usage(format!("{flag} requires a value")))
}

fn parse_u32(raw: &str, flag: &str) -> Result<u32, CliError> {
    raw.parse::<u32>()
        .map_err(|e| CliError::Usage(format!("{flag} must be an integer: {e}")))
}

fn parse_u64(raw: &str, flag: &str) -> Result<u64, CliError> {
    raw.parse::<u64>()
        .map_err(|e| CliError::Usage(format!("{flag} must be an integer: {e}")))
}

fn read_plan(path: &Path) -> Result<String, CliError> {
    std::fs::read_to_string(path).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

fn write_plan(path: &Path, text: &str) -> Result<(), CliError> {
    std::fs::write(path, text).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

fn print_add_help() {
    println!(
        "Usage: raxis tools add --plan <plan.toml> --profile <name> --name <tool> \\\n+           --description <text> (--command <abs-path> [--command-arg <arg>...] | --command-json '[...]') \\\n+           [--locality guest_subprocess|host_subprocess|host_mcp|remote_mcp] \\\n+           [--tool-schema '<json>' | --tool-schema-file <path>] [--timeout <seconds>]"
    );
}

fn print_attach_help() {
    println!("Usage: raxis tools attach --plan <plan.toml> --task <task_name> --profile <name>");
}

fn print_test_help() {
    println!(
        "Usage: raxis tools test --plan <plan.toml> --profile <name> --tool <tool> [--input-json '<json>' | --input-file <path>]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn parse_add_accepts_command_args_and_schema_alias() {
        let opts = parse_add_args(&s(&[
            "--plan",
            "plan.toml",
            "--profile",
            "repo_tools",
            "--name",
            "repo_search",
            "--description",
            "Search repository files by query string",
            "--command",
            "/usr/bin/rg",
            "--command-arg",
            "--json",
            "--tool-schema",
            r#"{"query":"string"}"#,
        ]))
        .unwrap();
        assert_eq!(opts.command, vec!["/usr/bin/rg", "--json"]);
        assert!(matches!(opts.schema, Some(SchemaInput::Inline(_))));
    }

    #[test]
    fn parse_validate_accepts_positional_path() {
        assert_eq!(
            parse_plan_path(&s(&["plan.toml"]), "tools validate").unwrap(),
            PathBuf::from("plan.toml")
        );
    }
}
