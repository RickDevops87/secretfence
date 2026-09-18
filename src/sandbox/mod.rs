mod profiles;

#[cfg(target_os = "macos")]
mod macos;

use std::path::Path;

use anyhow::Result;
use colored::Colorize;

pub use profiles::load_profile;

pub struct SandboxConfig {
    pub deny_paths: Vec<String>,
    pub deny_env: Vec<String>,
    pub command: Vec<String>,
}

pub fn exec_sandboxed(config: &SandboxConfig, project_dir: &Path, dry_run: bool) -> Result<()> {
    if dry_run {
        print_dry_run(config);
        return Ok(());
    }

    println!(
        "\n  {} Starting protected process...\n",
        "secretfence".cyan().bold()
    );

    // Resolve absolute paths for deny list
    let abs_deny: Vec<String> = config
        .deny_paths
        .iter()
        .map(|p| {
            let path = project_dir.join(p);
            path.display().to_string()
        })
        .collect();

    for path in &abs_deny {
        println!("    {} {}", "deny".red(), path);
    }
    for env in &config.deny_env {
        println!("    {} env:{}", "deny".red(), env);
    }
    println!();

    #[cfg(target_os = "macos")]
    {
        macos::exec_sandboxed(&abs_deny, &config.deny_env, &config.command)?;
    }

    #[cfg(target_os = "linux")]
    {
        eprintln!(
            "[secretfence] {} Linux filesystem sandboxing is not implemented; denied paths are not enforced.",
            "WARNING:".yellow()
        );
        eprintln!("[secretfence] Using best-effort environment-variable scrubbing only.\n");
        exec_best_effort(&config.deny_env, &config.command)?;
    }

    #[cfg(target_os = "windows")]
    {
        exec_best_effort(&config.deny_env, &config.command)?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        eprintln!("[secretfence] Unsupported platform — running without sandbox");
        exec_best_effort(&config.deny_env, &config.command)?;
    }

    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "windows",
    not(any(target_os = "macos", target_os = "linux"))
))]
fn exec_best_effort(deny_env: &[String], command: &[String]) -> Result<()> {
    use std::process::Command;

    eprintln!(
        "[secretfence] {} OS-level sandboxing not available on this platform.",
        "WARNING:".yellow()
    );
    eprintln!("[secretfence] Using best-effort env var scrubbing only.\n");

    let (cmd, args) = command.split_first().unwrap();
    let mut child = Command::new(cmd);
    child.args(args);

    // Scrub denied env vars
    for pattern in deny_env {
        for (key, _) in std::env::vars() {
            if matches_env_pattern(&key, pattern) {
                child.env_remove(&key);
            }
        }
    }

    let status = child.status()?;
    std::process::exit(status.code().unwrap_or(1));
}

fn matches_env_pattern(key: &str, pattern: &str) -> bool {
    if pattern.starts_with('*') && pattern.ends_with('*') {
        let inner = &pattern[1..pattern.len() - 1];
        key.contains(inner)
    } else if pattern.starts_with('*') {
        key.ends_with(&pattern[1..])
    } else if pattern.ends_with('*') {
        key.starts_with(&pattern[..pattern.len() - 1])
    } else {
        key == pattern
    }
}

fn print_dry_run(config: &SandboxConfig) {
    println!(
        "\n  {} Dry run — sandbox config:\n",
        "secretfence".cyan().bold()
    );

    println!("  Denied file paths:");
    for path in &config.deny_paths {
        println!("    {}", path.red());
    }

    println!("\n  Denied environment variables:");
    for env in &config.deny_env {
        println!("    {}", env.red());
    }

    println!("\n  Command: {}", config.command.join(" ").cyan());

    let platform = if cfg!(target_os = "macos") {
        "macOS (sandbox-exec / Seatbelt)"
    } else if cfg!(target_os = "linux") {
        "Linux (best-effort environment-variable scrubbing; denied paths are not enforced)"
    } else if cfg!(target_os = "windows") {
        "Windows (best-effort env scrubbing)"
    } else {
        "Unknown (no sandbox available)"
    };

    println!("  Sandbox: {}\n", platform.green());
}

#[cfg(test)]
mod tests {
    use super::matches_env_pattern;

    #[test]
    fn matches_environment_variable_patterns() {
        assert!(matches_env_pattern("DATABASE_URL", "DATABASE_URL"));
        assert!(matches_env_pattern("OPENAI_API_KEY", "*_KEY"));
        assert!(matches_env_pattern("DEPLOYER_SECRET_VALUE", "*SECRET*"));
        assert!(!matches_env_pattern("PATH", "*_KEY"));
    }
}
