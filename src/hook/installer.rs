use std::fs;
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

pub fn install_hooks(project_dir: &Path, tool_filter: Option<&str>) -> Result<()> {
    let filter: Option<Vec<&str>> = tool_filter.map(|f| f.split(',').collect());
    let mut installed = false;

    println!("\n  Installing secretfence protections...\n");

    // Claude Code
    if filter.as_ref().map_or(true, |f| f.iter().any(|t| t.eq_ignore_ascii_case("claude"))) {
        match install_claude_hook(project_dir) {
            Ok(true) => {
                println!("    {:<15} PreToolUse hook installed", "Claude Code".cyan());
                installed = true;
            }
            Ok(false) => {
                println!("    {:<15} already installed", "Claude Code".cyan());
            }
            Err(e) => {
                eprintln!("    {:<15} {} {}", "Claude Code".cyan(), "error:".red(), e);
            }
        }
    }

    // Cursor has no executable pre-tool hook. Install an advisory project rule
    // rather than representing it as an intercepted tool call.
    if filter.as_ref().map_or(true, |f| f.iter().any(|t| t.eq_ignore_ascii_case("cursor"))) {
        match install_cursor_hook(project_dir) {
            Ok(true) => {
                println!("    {:<15} advisory project rule installed", "Cursor".cyan());
                installed = true;
            }
            Ok(false) => {
                println!("    {:<15} advisory project rule already installed", "Cursor".cyan());
            }
            Err(e) => {
                eprintln!("    {:<15} {} {}", "Cursor".cyan(), "error:".red(), e);
            }
        }
    }

    if !installed {
        println!("    No new hooks installed.");
    }

    println!();
    Ok(())
}

pub fn uninstall_hooks(project_dir: &Path) -> Result<()> {
    println!("\n  Removing secretfence hooks...\n");

    // Claude Code
    let claude_settings = project_dir.join(".claude").join("settings.json");
    if claude_settings.exists() {
        let content = fs::read_to_string(&claude_settings)?;
        if let Ok(mut settings) = serde_json::from_str::<serde_json::Value>(&content) {
            if remove_claude_hooks(&mut settings) {
                let output = serde_json::to_string_pretty(&settings)?;
                fs::write(&claude_settings, output)?;
                println!("    {:<15} hooks removed", "Claude Code".cyan());
            }
        }
    }

    println!();
    Ok(())
}

fn install_claude_hook(project_dir: &Path) -> Result<bool> {
    let claude_dir = project_dir.join(".claude");
    let settings_path = claude_dir.join("settings.json");

    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        fs::create_dir_all(&claude_dir)?;
        serde_json::json!({})
    };

    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert(serde_json::json!({}))
        .as_object_mut()
        .unwrap();

    let pre_tool = hooks
        .entry("PreToolUse")
        .or_insert(serde_json::json!([]))
        .as_array_mut()
        .unwrap();

    // Check if already installed (check both old "hook" format and new "hooks" format)
    let already_installed = pre_tool.iter().any(|entry| {
        // Old format: { "hook": "sf hook check ..." }
        let old = entry.get("hook")
            .and_then(|h| h.as_str())
            .map(|h| h.contains("sf hook check"))
            .unwrap_or(false);
        // New format: { "hooks": [{ "command": "sf hook check ..." }] }
        let new = entry.get("hooks")
            .and_then(|h| h.as_array())
            .map(|arr| arr.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains("sf hook check"))
                    .unwrap_or(false)
            }))
            .unwrap_or(false);
        old || new
    });

    if already_installed {
        return Ok(false);
    }

    pre_tool.push(serde_json::json!({
        "matcher": "Read|Edit|Write|Bash",
        "hooks": [
            {
                "type": "command",
                "command": "sf hook check --format claude"
            }
        ]
    }));

    let output = serde_json::to_string_pretty(&settings)?;
    fs::write(&settings_path, output)?;

    Ok(true)
}

fn install_cursor_hook(project_dir: &Path) -> Result<bool> {
    let cursor_dir = project_dir.join(".cursor");
    if !cursor_dir.exists() {
        return Ok(false);
    }

    let rules_path = cursor_dir.join("rules");
    fs::create_dir_all(&rules_path)?;

    let hook_file = rules_path.join("secretfence.mdc");

    if hook_file.exists() {
        return Ok(false);
    }

    let content = r#"---
description: secretfence secret protection
globs: ["**/.env*", "**/*.pem", "**/*.key"]
---

Before reading any file matching the globs above, run `sf hook check --format cursor` to verify
the file does not contain secrets. If the check fails, do not read the file.
"#;

    fs::write(&hook_file, content)?;
    Ok(true)
}

fn remove_claude_hooks(settings: &mut serde_json::Value) -> bool {
    let hooks = match settings.get_mut("hooks") {
        Some(h) => h,
        None => return false,
    };

    let pre_tool = match hooks.get_mut("PreToolUse") {
        Some(serde_json::Value::Array(arr)) => arr,
        _ => return false,
    };

    let before = pre_tool.len();
    pre_tool.retain(|entry| {
        let old = entry.get("hook")
            .and_then(|h| h.as_str())
            .map(|h| h.contains("sf hook check"))
            .unwrap_or(false);
        let new = entry.get("hooks")
            .and_then(|h| h.as_array())
            .map(|arr| arr.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains("sf hook check"))
                    .unwrap_or(false)
            }))
            .unwrap_or(false);
        !old && !new
    });

    pre_tool.len() != before
}
