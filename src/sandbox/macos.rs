use std::process::Command;

use anyhow::Result;

use super::matches_env_pattern;

pub fn exec_sandboxed(
    deny_paths: &[String],
    deny_env: &[String],
    command: &[String],
) -> Result<()> {
    // Generate Seatbelt profile
    let profile = generate_seatbelt_profile(deny_paths);

    // Write to temp file
    let profile_path = std::env::temp_dir().join("secretfence-sandbox.sb");
    std::fs::write(&profile_path, &profile)?;

    let (cmd, args) = command.split_first().unwrap();

    let mut child = Command::new("sandbox-exec");
    child
        .arg("-f")
        .arg(&profile_path)
        .arg("--")
        .arg(cmd)
        .args(args);

    // Scrub denied env vars
    for pattern in deny_env {
        for (key, _) in std::env::vars() {
            if matches_env_pattern(&key, pattern) {
                child.env_remove(&key);
            }
        }
    }

    let status = child.status()?;

    // Clean up temp profile
    let _ = std::fs::remove_file(&profile_path);

    std::process::exit(status.code().unwrap_or(1));
}

fn generate_seatbelt_profile(deny_paths: &[String]) -> String {
    let mut profile = String::from("(version 1)\n(allow default)\n\n");

    if deny_paths.is_empty() {
        return profile;
    }

    profile.push_str(";; secretfence — deny read access to secret files\n");
    profile.push_str("(deny file-read*\n");

    for path in deny_paths {
        // Use literal match for specific files
        if path.contains('*') {
            // Convert glob to regex for Seatbelt
            let regex = escape_seatbelt_string(path)
                .replace('.', "\\.")
                .replace('*', ".*");
            profile.push_str(&format!("  (regex #\"{}\")\n", regex));
        } else {
            profile.push_str(&format!(
                "  (literal \"{}\")\n",
                escape_seatbelt_string(path)
            ));
        }
    }

    profile.push_str(")\n");
    profile
}

fn escape_seatbelt_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::generate_seatbelt_profile;

    #[test]
    fn escapes_paths_before_inserting_them_in_a_profile() {
        let profile = generate_seatbelt_profile(&["secret\"file\\name".to_owned()]);

        assert!(profile.contains("(literal \"secret\\\"file\\\\name\")"));
    }
}
