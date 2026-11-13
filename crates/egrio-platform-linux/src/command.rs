use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OsCommand {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<String>,
}
impl OsCommand {
    pub(crate) fn new<I, S>(program: &str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(|s| s.as_ref().into()).collect(),
            stdin: None,
        }
    }
}
pub(crate) fn run(command: &OsCommand) -> Result<String, String> {
    let mut child = Command::new(&command.program)
        .args(&command.args)
        .stdin(if command.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("start {}: {e}", command.program))?;
    if let Some(input) = &command.stdin {
        child
            .stdin
            .take()
            .ok_or("command stdin missing")?
            .write_all(input.as_bytes())
            .map_err(|e| format!("write command input: {e}"))?;
    }
    // Drain concurrently: ip JSON output can exceed a pipe buffer.
    let stdout = child.stdout.take().ok_or("command stdout missing")?;
    let stderr = child.stderr.take().ok_or("command stderr missing")?;
    let out = std::thread::spawn(move || {
        use std::io::Read;
        let mut text = String::new();
        stdout
            .take(4 * 1024 * 1024)
            .read_to_string(&mut text)
            .map(|_| text)
    });
    let err = std::thread::spawn(move || {
        use std::io::Read;
        let mut text = String::new();
        stderr
            .take(64 * 1024)
            .read_to_string(&mut text)
            .map(|_| text)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("command exceeded 5 seconds".to_string());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(error.to_string());
            }
        }
    };
    let output = out
        .join()
        .map_err(|_| "command stdout reader panicked")?
        .map_err(|e| e.to_string())?;
    let error = err
        .join()
        .map_err(|_| "command stderr reader panicked")?
        .map_err(|e| e.to_string())?;
    let status = status.map_err(|e| format!("{} {:?}: {e}", command.program, command.args))?;
    if !status.success() {
        return Err(format!(
            "{} {:?}: {}",
            command.program,
            command.args,
            error.trim()
        ));
    }
    Ok(output)
}
pub(crate) fn program_available(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|path| path.join(program).is_file()))
}
pub(crate) fn json(command: OsCommand) -> Result<Vec<Value>, String> {
    serde_json::from_str::<Vec<Value>>(&run(&command)?)
        .map_err(|e| format!("invalid {} JSON: {e}", command.program))
}
pub(crate) fn number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}
