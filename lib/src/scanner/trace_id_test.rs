#[cfg(test)]
mod trace_id_tests {
    use crate::compile;
    use crate::Scanner;

    #[test]
    fn test_trace_id_extraction() {
        let rules = compile(r#"
            rule test {
                strings:
                    $a = "traceId:"
                condition:
                    $a
            }
        "#).unwrap();

        let test_data = br#"2024-01-01 INFO Processing request, userId: "user123", traceId: "550e8400-e29b-41d4-a716-446655440000""#;

        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(test_data).unwrap();

        let mut found_trace_id = false;
        for rule in results.matching_rules() {
            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    if let Some(trace_id) = m.trace_id() {
                        assert_eq!(trace_id, "550e8400-e29b-41d4-a716-446655440000");
                        found_trace_id = true;
                    }
                }
            }
        }
        
        assert!(found_trace_id, "Expected to find trace_id in match");
    }

    #[test]
    fn test_trace_id_extraction_multiple_quotes() {
        let rules = compile(r#"
            rule test {
                strings:
                    $a = "Processing"
                condition:
                    $a
            }
        "#).unwrap();

        let test_data = br#"2024-01-01 INFO Processing request, userId: "user123", status: "active", traceId: "last-quoted-string""#;

        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(test_data).unwrap();

        let mut found_trace_id = false;
        for rule in results.matching_rules() {
            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    if let Some(trace_id) = m.trace_id() {
                        // Should extract the last quoted string
                        assert_eq!(trace_id, "last-quoted-string");
                        found_trace_id = true;
                    }
                }
            }
        }
        
        assert!(found_trace_id, "Expected to find trace_id in match");
    }

    #[test]
    fn test_trace_id_no_quotes() {
        let rules = compile(r#"
            rule test {
                strings:
                    $a = "INFO"
                condition:
                    $a
            }
        "#).unwrap();

        let test_data = b"2024-01-01 INFO Processing request without quotes";

        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(test_data).unwrap();

        for rule in results.matching_rules() {
            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    assert!(m.trace_id().is_none(), "Expected no trace_id when no quotes in line");
                }
            }
        }
    }

    #[test]
    fn test_collect_trace_ids_from_rule() {
        let rules = compile(r#"
            rule test {
                strings:
                    $a = "INFO"
                condition:
                    $a
            }
        "#).unwrap();

        let test_data = br#"2024-01-01 INFO Request 1, traceId: "trace-001"
2024-01-01 INFO Request 2, traceId: "trace-002"
2024-01-01 INFO Request 3, traceId: "trace-001"
2024-01-01 INFO Request 4, traceId: "trace-003""#;

        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(test_data).unwrap();

        for rule in results.matching_rules() {
            let trace_ids = rule.trace_ids();
            assert_eq!(trace_ids.len(), 3); // Should have 3 unique trace IDs
            assert!(trace_ids.contains(&"trace-001".to_string()));
            assert!(trace_ids.contains(&"trace-002".to_string()));
            assert!(trace_ids.contains(&"trace-003".to_string()));
        }
    }

    #[test]
    fn test_collect_trace_ids_from_pattern() {
        let rules = compile(r#"
            rule test {
                strings:
                    $info = "INFO"
                    $error = "ERROR"
                condition:
                    $info or $error
            }
        "#).unwrap();

        let test_data = br#"2024-01-01 INFO Request 1, traceId: "trace-001"
2024-01-01 ERROR Request 2, traceId: "trace-002"
2024-01-01 INFO Request 3, traceId: "trace-003""#;

        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(test_data).unwrap();

        for rule in results.matching_rules() {
            for pattern in rule.patterns() {
                let trace_ids = pattern.trace_ids();
                match pattern.identifier() {
                    "$info" => {
                        assert_eq!(trace_ids.len(), 2);
                        assert!(trace_ids.contains(&"trace-001".to_string()));
                        assert!(trace_ids.contains(&"trace-003".to_string()));
                    }
                    "$error" => {
                        assert_eq!(trace_ids.len(), 1);
                        assert!(trace_ids.contains(&"trace-002".to_string()));
                    }
                    _ => panic!("Unexpected pattern"),
                }
            }
        }
    }

    #[test]
    fn test_collect_all_trace_ids_from_scan_results() {
        let rules = compile(r#"
            rule rule1 {
                strings:
                    $a = "INFO"
                condition:
                    $a
            }
            rule rule2 {
                strings:
                    $b = "ERROR"
                condition:
                    $b
            }
        "#).unwrap();

        let test_data = br#"2024-01-01 INFO Request 1, traceId: "trace-001"
2024-01-01 ERROR Request 2, traceId: "trace-002"
2024-01-01 INFO Request 3, traceId: "trace-001"
2024-01-01 ERROR Request 4, traceId: "trace-003""#;

        let mut scanner = Scanner::new(&rules);
        let results = scanner.scan(test_data).unwrap();

        let all_trace_ids = results.trace_ids();
        assert_eq!(all_trace_ids.len(), 3); // Should have 3 unique trace IDs across all rules
        assert!(all_trace_ids.contains(&"trace-001".to_string()));
        assert!(all_trace_ids.contains(&"trace-002".to_string()));
        assert!(all_trace_ids.contains(&"trace-003".to_string()));
    }
}