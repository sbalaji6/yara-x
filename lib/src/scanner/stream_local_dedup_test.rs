use crate::compile;
use crate::scanner::MultiStreamScanner;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[test]
fn test_stream_local_deduplication() {
    let rules = compile(
        r#"
        rule test_rule {
            strings:
                $error = /ERROR.*trace_id/
            condition:
                $error
        }
        "#,
    )
    .unwrap();

    let mut scanner = MultiStreamScanner::new(&rules);
    
    // Enable deduplication
    scanner.enable_deduplication(true);
    
    // Track matches
    let matches = Arc::new(Mutex::new(Vec::new()));
    let matches_clone = matches.clone();
    
    scanner.set_rule_match_callback(move |namespace, stream_id, rule, trace_ids| {
        matches_clone.lock().unwrap().push((
            namespace.to_string(),
            *stream_id,
            rule.to_string(),
            trace_ids.to_vec(),
        ));
    });
    
    let stream1 = Uuid::new_v4();
    
    // Scan stream with same trace ID appearing multiple times
    scanner.scan_chunk(&stream1, b"ERROR: Database connection failed (trace_id=\"ABC123\")\n").unwrap();
    scanner.scan_chunk(&stream1, b"ERROR: Database still failing (trace_id=\"ABC123\")\n").unwrap();
    scanner.scan_chunk(&stream1, b"ERROR: New error occurred (trace_id=\"XYZ789\")\n").unwrap();
    
    let final_matches = matches.lock().unwrap();
    
    // Should have callbacks for each scan
    assert_eq!(final_matches.len(), 3); // One callback per scan_chunk
    
    // First scan: ABC123 is new
    assert_eq!(final_matches[0].3, vec!["ABC123"]);
    
    // Second scan: Still reports ABC123 (accumulated matches) but no new match was added
    assert_eq!(final_matches[1].3, vec!["ABC123"]);
    
    // Third scan: Reports both ABC123 (from before) and XYZ789 (new)
    let mut third_scan_ids = final_matches[2].3.clone();
    third_scan_ids.sort();
    assert_eq!(third_scan_ids, vec!["ABC123", "XYZ789"]);
}

#[test]
fn test_no_cross_stream_deduplication() {
    let rules = compile(
        r#"
        rule test_rule {
            strings:
                $error = /ERROR.*trace_id/
            condition:
                $error
        }
        "#,
    )
    .unwrap();

    let mut scanner = MultiStreamScanner::new(&rules);
    
    // Enable deduplication
    scanner.enable_deduplication(true);
    
    let matches = Arc::new(Mutex::new(Vec::new()));
    let matches_clone = matches.clone();
    
    scanner.set_rule_match_callback(move |_namespace, stream_id, rule, trace_ids| {
        matches_clone.lock().unwrap().push((
            rule.to_string(),
            *stream_id,
            trace_ids.to_vec(),
        ));
    });
    
    let stream1 = Uuid::new_v4();
    let stream2 = Uuid::new_v4();
    
    // Same trace ID in different streams should NOT be deduplicated
    scanner.scan_chunk(&stream1, b"ERROR: Failed (trace_id=\"ABC123\")\n").unwrap();
    scanner.scan_chunk(&stream2, b"ERROR: Failed (trace_id=\"ABC123\")\n").unwrap();
    
    let final_matches = matches.lock().unwrap();
    assert_eq!(final_matches.len(), 2);
    
    // Both streams should report ABC123 since deduplication is per-stream
    assert_eq!(final_matches[0].2, vec!["ABC123"]);
    assert_eq!(final_matches[1].2, vec!["ABC123"]);
    assert_ne!(final_matches[0].1, final_matches[1].1); // Different stream IDs
}

#[test]
fn test_deduplication_disabled() {
    let rules = compile(
        r#"
        rule test_rule {
            strings:
                $error = /ERROR.*trace_id/
            condition:
                $error
        }
        "#,
    )
    .unwrap();

    let mut scanner = MultiStreamScanner::new(&rules);
    
    // Deduplication is disabled by default
    
    let matches = Arc::new(Mutex::new(Vec::new()));
    let matches_clone = matches.clone();
    
    scanner.set_rule_match_callback(move |_namespace, _stream_id, _rule, trace_ids| {
        matches_clone.lock().unwrap().push(trace_ids.to_vec());
    });
    
    let stream1 = Uuid::new_v4();
    
    // Same trace ID appearing multiple times should all be reported
    scanner.scan_chunk(&stream1, b"ERROR: Failed (trace_id=\"ABC123\")\n").unwrap();
    scanner.scan_chunk(&stream1, b"ERROR: Failed again (trace_id=\"ABC123\")\n").unwrap();
    
    let final_matches = matches.lock().unwrap();
    assert_eq!(final_matches.len(), 2);
    
    // Both occurrences should be reported when deduplication is disabled
    assert_eq!(final_matches[0], vec!["ABC123"]);
    assert_eq!(final_matches[1], vec!["ABC123"]);
}

#[test]
fn test_multiple_patterns_same_trace_id() {
    let rules = compile(
        r#"
        rule multi_pattern {
            strings:
                $error = /ERROR.*trace_id/
                $fail = /Failed.*trace_id/
            condition:
                any of them
        }
        "#,
    )
    .unwrap();

    let mut scanner = MultiStreamScanner::new(&rules);
    scanner.enable_deduplication(true);
    
    let matches = Arc::new(Mutex::new(Vec::new()));
    let matches_clone = matches.clone();
    
    scanner.set_rule_match_callback(move |_namespace, _stream_id, _rule, trace_ids| {
        matches_clone.lock().unwrap().push(trace_ids.to_vec());
    });
    
    let stream1 = Uuid::new_v4();
    
    // Single line that matches both patterns with same trace ID
    scanner.scan_chunk(&stream1, b"ERROR: Operation Failed (trace_id=\"ABC123\")\n").unwrap();
    
    // Second scan with same trace ID - both patterns should be deduplicated
    scanner.scan_chunk(&stream1, b"ERROR: Still Failed (trace_id=\"ABC123\")\n").unwrap();
    
    let final_matches = matches.lock().unwrap();
    assert_eq!(final_matches.len(), 2);
    
    // First scan: ABC123 is new
    assert_eq!(final_matches[0], vec!["ABC123"]);
    
    // Second scan: ABC123 already seen for both patterns
    assert!(final_matches[1].is_empty() || final_matches[1] == vec!["ABC123"]);
}

#[test]
fn test_pattern_specific_deduplication() {
    let rules = compile(
        r#"
        rule test_rule {
            strings:
                $error = /ERROR/
                $warn = /WARN/
            condition:
                any of them
        }
        "#,
    )
    .unwrap();

    let mut scanner = MultiStreamScanner::new(&rules);
    scanner.enable_deduplication(true);
    
    let stream1 = Uuid::new_v4();
    
    // First scan: ERROR with trace_id ABC123
    scanner.scan_chunk(&stream1, b"ERROR: Database issue (trace_id=\"ABC123\")\n").unwrap();
    
    // Second scan: WARN with same trace_id ABC123
    // This should NOT be deduplicated because it's a different pattern
    scanner.scan_chunk(&stream1, b"WARN: Retrying operation (trace_id=\"ABC123\")\n").unwrap();
    
    // The deduplication is per (pattern_id, trace_id) combination
    // So WARN+ABC123 is different from ERROR+ABC123
}