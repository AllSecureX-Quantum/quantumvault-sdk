//! Output formatting for CLI.

use anyhow::Result;
use serde::Serialize;

/// Command output that can be formatted as text, JSON, or YAML.
#[derive(Debug, Serialize)]
pub struct CommandOutput {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CommandOutput {
    /// Create a success output.
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: None,
        }
    }

    /// Create a success output with data.
    pub fn success_with_data(message: impl Into<String>, data: impl Serialize) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(serde_json::to_value(data).unwrap_or(serde_json::Value::Null)),
        }
    }

    /// Create an error output.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            data: None,
        }
    }
}

/// Print output in the specified format.
pub fn print_output(output: &CommandOutput, format: &str) -> Result<()> {
    match format.to_lowercase().as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(output)?);
        }
        "yaml" => {
            println!("{}", serde_yaml::to_string(output)?);
        }
        _ => {
            // Text format
            use colored::Colorize;

            if output.success {
                println!("{} {}", "✓".green(), output.message);
            } else {
                println!("{} {}", "✗".red(), output.message);
            }

            if let Some(data) = &output.data {
                print_data_as_text(data, 0);
            }
        }
    }

    Ok(())
}

/// Print JSON data as formatted text.
fn print_data_as_text(value: &serde_json::Value, indent: usize) {
    use colored::Colorize;

    let prefix = "  ".repeat(indent);

    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                match val {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        println!("{}{}:", prefix, key.cyan());
                        print_data_as_text(val, indent + 1);
                    }
                    _ => {
                        println!("{}{}: {}", prefix, key.cyan(), format_value(val));
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                println!("{}[{}]", prefix, i);
                print_data_as_text(val, indent + 1);
            }
        }
        _ => {
            println!("{}{}", prefix, format_value(value));
        }
    }
}

/// Format a JSON value as a string.
fn format_value(value: &serde_json::Value) -> String {
    use colored::Colorize;

    match value {
        serde_json::Value::Null => "null".dimmed().to_string(),
        serde_json::Value::Bool(b) => {
            if *b {
                "true".green().to_string()
            } else {
                "false".red().to_string()
            }
        }
        serde_json::Value::Number(n) => n.to_string().yellow().to_string(),
        serde_json::Value::String(s) => s.to_string(),
        _ => value.to_string(),
    }
}
