/// Format DNT / Sec-GPC values as human-readable strings.
pub fn format_dnt(value: Option<String>) -> Option<String> {
    value.map(|v| match v.as_str() {
        "1" => "Enabled".to_string(),
        "0" => "Disabled".to_string(),
        other => other.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_dnt_none() {
        assert_eq!(format_dnt(None), None);
    }

    #[test]
    fn test_format_dnt_enabled() {
        assert_eq!(
            format_dnt(Some("1".to_string())),
            Some("Enabled".to_string())
        );
    }

    #[test]
    fn test_format_dnt_disabled() {
        assert_eq!(
            format_dnt(Some("0".to_string())),
            Some("Disabled".to_string())
        );
    }

    #[test]
    fn test_format_dnt_other_value() {
        assert_eq!(
            format_dnt(Some("unknown".to_string())),
            Some("unknown".to_string())
        );
        assert_eq!(format_dnt(Some("yes".to_string())), Some("yes".to_string()));
    }
}
