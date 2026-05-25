//! Config display command.

use crate::config::CliConfig;
use crate::output::CommandOutput;
use anyhow::Result;

/// Run the config command.
pub async fn run(config: &CliConfig) -> Result<CommandOutput> {
    Ok(CommandOutput::success_with_data(
        "Current configuration",
        serde_json::json!({
            "config_path": CliConfig::config_path().to_string_lossy(),
            "api_key": config.api_key.as_ref().map(|_| "***configured***"),
            "region": config.region,
            "default_algorithm": config.default_algorithm,
            "security_level": config.security_level,
            "key_storage_path": config.key_storage_path.to_string_lossy(),
            "enable_telemetry": config.enable_telemetry,
            "project_id": config.project_id,
        }),
    ))
}
