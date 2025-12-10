/// Sanitizes a header value for safe HTML output.
/// Escapes HTML special characters to prevent XSS attacks.
pub fn sanitize_header(value: Option<String>) -> String {
    match value {
        Some(v) => {
            let mut out = String::with_capacity((v.len() as f64 * 1.2) as usize + 4);
            for c in v.chars() {
                match c {
                    '<' => out.push_str("&lt;"),
                    '>' => out.push_str("&gt;"),
                    '&' => out.push_str("&amp;"),
                    '"' => out.push_str("&quot;"),
                    '\'' => out.push_str("&#x27;"),
                    '/' => out.push_str("&#x2F;"),
                    ch if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' => {
                        // skip control chars except newline/tab
                    }
                    ch => out.push(ch),
                }
            }
            out
        }
        None => "—".to_string(),
    }
}

/// Sanitizes for JSON output, returning Option<String>
pub fn sanitize_for_json(value: Option<&str>) -> Option<String> {
    value.map(|v| {
        let mut out = String::with_capacity(v.len());
        for c in v.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c.is_control() => {
                    // skip other control characters
                }
                c => out.push(c),
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_header_none() {
        assert_eq!(sanitize_header(None), "—");
    }

    #[test]
    fn test_sanitize_header_safe_string() {
        assert_eq!(sanitize_header(Some("hello".to_string())), "hello");
    }

    #[test]
    fn test_sanitize_header_html_escape() {
        assert_eq!(
            sanitize_header(Some("<script>".to_string())),
            "&lt;script&gt;"
        );
        assert_eq!(sanitize_header(Some("&amp;".to_string())), "&amp;amp;");
        assert_eq!(
            sanitize_header(Some("\"quoted\"".to_string())),
            "&quot;quoted&quot;"
        );
        assert_eq!(
            sanitize_header(Some("'single'".to_string())),
            "&#x27;single&#x27;"
        );
        assert_eq!(
            sanitize_header(Some("path/to/file".to_string())),
            "path&#x2F;to&#x2F;file"
        );
    }

    #[test]
    fn test_sanitize_header_preserves_newlines() {
        assert_eq!(
            sanitize_header(Some("line1\nline2".to_string())),
            "line1\nline2"
        );
        assert_eq!(
            sanitize_header(Some("line1\r\nline2".to_string())),
            "line1\r\nline2"
        );
        assert_eq!(sanitize_header(Some("tab\there".to_string())), "tab\there");
    }

    #[test]
    fn test_sanitize_header_removes_control_chars() {
        let input = format!("hello{}world", { '\x00' });
        let result = sanitize_header(Some(input));
        assert!(!result.contains('\x00'));
        assert_eq!(result, "helloworld");
    }

    #[test]
    fn test_sanitize_for_json_none() {
        assert_eq!(sanitize_for_json(None), None);
    }

    #[test]
    fn test_sanitize_for_json_safe_string() {
        assert_eq!(sanitize_for_json(Some("hello")), Some("hello".to_string()));
    }

    #[test]
    fn test_sanitize_for_json_escape_chars() {
        assert_eq!(sanitize_for_json(Some("\\")), Some("\\\\".to_string()));
        assert_eq!(sanitize_for_json(Some("\"")), Some("\\\"".to_string()));
        assert_eq!(sanitize_for_json(Some("\n")), Some("\\n".to_string()));
        assert_eq!(sanitize_for_json(Some("\r")), Some("\\r".to_string()));
        assert_eq!(sanitize_for_json(Some("\t")), Some("\\t".to_string()));
    }

    #[test]
    fn test_sanitize_for_json_complex() {
        let input = "line1\nline2\t\"quoted\"\\path";
        let expected = "line1\\nline2\\t\\\"quoted\\\"\\\\path";
        assert_eq!(sanitize_for_json(Some(input)), Some(expected.to_string()));
    }

    #[test]
    fn test_sanitize_for_json_removes_control_chars() {
        let input = format!("hello{}world", { '\x00' });
        let result = sanitize_for_json(Some(&input));
        assert_eq!(result, Some("helloworld".to_string()));
    }
}
