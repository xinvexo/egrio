//! Egrio's nftables tables. Each carries the session's ownership token as its
//! comment, is never altered under another token, and changes as a whole in
//! one transaction.

use crate::command::{run, OsCommand};
use serde_json::Value;

fn tables() -> Result<Vec<Value>, String> {
    let text = run(&OsCommand::new("nft", ["-j", "list", "tables"]))?;
    let object: Value =
        serde_json::from_str(&text).map_err(|e| format!("invalid nftables JSON: {e}"))?;
    object["nftables"]
        .as_array()
        .cloned()
        .ok_or("nftables response missing objects".into())
}

pub(crate) fn has_table(name: &str) -> Result<bool, String> {
    Ok(tables()?
        .iter()
        .any(|entry| entry["table"]["family"] == "inet" && entry["table"]["name"] == name))
}

/// Whether table `name` exists under `ownership`. A table of that name under
/// another token is an error.
pub(crate) fn owned(name: &str, ownership: &str) -> Result<bool, String> {
    if !has_table(name)? {
        return Ok(false);
    }
    let text = run(&OsCommand::new(
        "nft",
        ["-j", "list", "table", "inet", name],
    ))?;
    let object: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if !object["nftables"].as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry["table"]["comment"] == ownership)
    }) {
        return Err(format!(
            "refusing to alter nftables table inet {name} with a different ownership token"
        ));
    }
    Ok(true)
}

/// Creates table `name` from `script`, or replaces it in place: the old table
/// is deleted and the new one added in one transaction, so there is never a
/// moment without it.
pub(crate) fn replace(name: &str, ownership: &str, script: &str) -> Result<(), String> {
    if has_table(name)? {
        owned(name, ownership)?;
    }
    run(&OsCommand {
        program: "nft".into(),
        args: vec!["-f".into(), "-".into()],
        stdin: Some(format!(
            "add table inet {name}\ndelete table inet {name}\n{script}"
        )),
    })?;
    if !owned(name, ownership)? {
        return Err(format!(
            "nftables table inet {name} observation did not match"
        ));
    }
    Ok(())
}

/// Deletes table `name` if `ownership` holds it, and verifies it is gone.
pub(crate) fn remove(name: &str, ownership: &str) -> Result<(), String> {
    if owned(name, ownership)? {
        run(&OsCommand::new("nft", ["delete", "table", "inet", name]))?;
    }
    if has_table(name)? {
        return Err(format!(
            "nftables table inet {name} cleanup could not be verified"
        ));
    }
    Ok(())
}
