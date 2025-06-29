#[cfg(test)]
mod tests {
    use crate::compiler::Compiler;
    use crate::scanner::MultiStreamScanner;
    use uuid::Uuid;
    use std::time::Duration;
    
    #[test]
    fn test_multi_stream_debug() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(r#"
                rule test {
                    strings:
                        $a = "AAA"
                        $b = "BBB"
                    condition:
                        $a or $b
                }
            "#)
            .unwrap();
        let rules = compiler.build();

        let mut scanner = MultiStreamScanner::new(&rules);
        let stream1 = Uuid::new_v4();

        // First scan: should match with AAA
        scanner.scan_line(&stream1, b"AAA").unwrap();
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 1, "Should match with AAA");
        
        // Second scan: should still match (accumulated)
        scanner.scan_line(&stream1, b"CCC").unwrap();
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 1, "Should still match");
    }

    #[test]
    fn test_multi_stream_basic() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(r#"
                rule test {
                    strings:
                        $a = "pattern1"
                        $b = "pattern2"
                    condition:
                        $a and $b
                }
            "#)
            .unwrap();
        let rules = compiler.build();

        let mut scanner = MultiStreamScanner::new(&rules);

        // Create two stream IDs
        let stream1 = Uuid::new_v4();
        let stream2 = Uuid::new_v4();

        // Stream 1: Add pattern1
        scanner.scan_line(&stream1, b"first line with pattern1").unwrap();
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 0, "Stream 1: Rule shouldn't match yet");

        // Stream 2: Add both patterns in one line
        scanner.scan_line(&stream2, b"line with pattern1 and pattern2").unwrap();
        let results = scanner.get_matches(&stream2).unwrap();
        assert_eq!(results.matching_rules().count(), 1, "Stream 2: Rule should match");

        // Back to Stream 1: Add pattern2
        scanner.scan_line(&stream1, b"second line with pattern2").unwrap();
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 1, "Stream 1: Rule should now match");
    }

    #[test]
    fn test_multi_stream_context_isolation() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(r#"
                rule count_foo {
                    strings:
                        $a = "foo"
                    condition:
                        #a == 3
                }
            "#)
            .unwrap();
        let rules = compiler.build();

        let mut scanner = MultiStreamScanner::new(&rules);

        let stream1 = Uuid::new_v4();
        let stream2 = Uuid::new_v4();

        // Stream 1: Add 2 "foo"
        scanner.scan_line(&stream1, b"foo foo").unwrap();
        
        // Stream 2: Add 3 "foo"
        scanner.scan_line(&stream2, b"foo foo foo").unwrap();
        
        // Check Stream 2 matches
        let results = scanner.get_matches(&stream2).unwrap();
        assert_eq!(results.matching_rules().count(), 1, "Stream 2 should match with 3 foo");
        
        // Check Stream 1 doesn't match
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 0, "Stream 1 should not match with only 2 foo");
        
        // Add one more foo to Stream 1
        scanner.scan_line(&stream1, b"foo").unwrap();
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 1, "Stream 1 should now match with 3 foo");
    }

    #[test]
    fn test_multi_stream_chunk_scanning() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(r#"
                rule test_multiline {
                    strings:
                        $a = "start"
                        $b = "middle"
                        $c = "end"
                    condition:
                        $a and $b and $c
                }
            "#)
            .unwrap();
        let rules = compiler.build();

        let mut scanner = MultiStreamScanner::new(&rules);

        let stream1 = Uuid::new_v4();
        let stream2 = Uuid::new_v4();

        // Stream 1: Use chunk scanning
        scanner.scan_chunk(&stream1, b"line with start\nline with middle\nline with end\n").unwrap();
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 1, "Stream 1: Chunk scan should find all patterns");

        // Stream 2: Use line-by-line scanning
        scanner.scan_line(&stream2, b"line with start").unwrap();
        scanner.scan_line(&stream2, b"line with middle").unwrap();
        let results = scanner.get_matches(&stream2).unwrap();
        assert_eq!(results.matching_rules().count(), 0, "Stream 2: Should not match yet");
        
        scanner.scan_line(&stream2, b"line with end").unwrap();
        let results = scanner.get_matches(&stream2).unwrap();
        assert_eq!(results.matching_rules().count(), 1, "Stream 2: Should match after all patterns");
    }

    #[test]
    fn test_multi_stream_counters() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(r#"
                rule dummy {
                    condition:
                        true
                }
            "#)
            .unwrap();
        let rules = compiler.build();

        let mut scanner = MultiStreamScanner::new(&rules);

        let stream1 = Uuid::new_v4();
        let stream2 = Uuid::new_v4();

        // Stream 1: Process 20 bytes
        scanner.scan_line(&stream1, b"12345678901234567890").unwrap();
        assert_eq!(scanner.bytes_processed(&stream1), Some(20));
        assert_eq!(scanner.lines_processed(&stream1), Some(1));

        // Stream 2: Process different amount
        scanner.scan_chunk(&stream2, b"line1\nline2\nline3\n").unwrap();
        assert_eq!(scanner.bytes_processed(&stream2), Some(18));
        assert_eq!(scanner.lines_processed(&stream2), Some(3));

        // Stream 1: Add more data
        scanner.scan_chunk(&stream1, b"more\ndata\n").unwrap();
        assert_eq!(scanner.bytes_processed(&stream1), Some(30));
        assert_eq!(scanner.lines_processed(&stream1), Some(3)); // 1 + 2 from chunk
    }

    #[test]
    fn test_multi_stream_reset() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(r#"
                rule test {
                    strings:
                        $a = "pattern"
                    condition:
                        $a
                }
            "#)
            .unwrap();
        let rules = compiler.build();

        let mut scanner = MultiStreamScanner::new(&rules);
        let stream1 = Uuid::new_v4();

        // Add pattern and verify match
        scanner.scan_line(&stream1, b"line with pattern").unwrap();
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 1);

        // Reset the stream
        scanner.reset_stream(&stream1).unwrap();

        // Verify stream was reset
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 0);
        assert_eq!(scanner.bytes_processed(&stream1), Some(0));
        assert_eq!(scanner.lines_processed(&stream1), Some(0));
    }

    #[test]
    fn test_multi_stream_close() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(r#"
                rule test {
                    strings:
                        $a = "pattern"
                    condition:
                        $a
                }
            "#)
            .unwrap();
        let rules = compiler.build();

        let mut scanner = MultiStreamScanner::new(&rules);
        let stream1 = Uuid::new_v4();

        // Add pattern
        scanner.scan_line(&stream1, b"line with pattern").unwrap();

        // Close the stream
        let final_results = scanner.close_stream(&stream1).unwrap();
        assert_eq!(final_results.non_private_matching_rules.len(), 1);
        assert_eq!(final_results.bytes_processed, 17);
        assert_eq!(final_results.lines_processed, 1);

        // Verify stream is gone
        assert!(scanner.get_matches(&stream1).is_none());
        assert!(scanner.bytes_processed(&stream1).is_none());
    }

    #[test]
    fn test_multi_stream_active_streams() {
        let rules = crate::compile("rule dummy { condition: true }").unwrap();
        let mut scanner = MultiStreamScanner::new(&rules);

        let stream1 = Uuid::new_v4();
        let stream2 = Uuid::new_v4();
        let stream3 = Uuid::new_v4();

        // Initially no streams
        assert_eq!(scanner.active_streams().len(), 0);

        // Add streams
        scanner.scan_line(&stream1, b"data").unwrap();
        assert_eq!(scanner.active_streams().len(), 1);

        scanner.scan_line(&stream2, b"data").unwrap();
        scanner.scan_line(&stream3, b"data").unwrap();
        
        let active = scanner.active_streams();
        assert_eq!(active.len(), 3);
        assert!(active.contains(&stream1));
        assert!(active.contains(&stream2));
        assert!(active.contains(&stream3));

        // Close one stream
        scanner.close_stream(&stream2);
        let active = scanner.active_streams();
        assert_eq!(active.len(), 2);
        assert!(!active.contains(&stream2));
    }

    #[test]
    fn test_multi_stream_global_offsets() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(r#"
                rule test_offset {
                    strings:
                        $a = "marker"
                    condition:
                        $a and @a[1] == 30
                }
            "#)
            .unwrap();
        let rules = compiler.build();

        let mut scanner = MultiStreamScanner::new(&rules);

        let stream1 = Uuid::new_v4();
        let stream2 = Uuid::new_v4();

        // Stream 1: marker at position 30
        scanner.scan_chunk(&stream1, b"123456789012345678901234567890marker").unwrap();
        let results = scanner.get_matches(&stream1).unwrap();
        assert_eq!(results.matching_rules().count(), 1, "Stream 1 should match with marker at 30");

        // Stream 2: marker at wrong position
        scanner.scan_chunk(&stream2, b"marker at wrong position").unwrap();
        let results = scanner.get_matches(&stream2).unwrap();
        assert_eq!(results.matching_rules().count(), 0, "Stream 2 should not match");

        // Stream 2: Add more data, but first marker is still at offset 0
        scanner.scan_chunk(&stream2, b"123456marker").unwrap(); // marker at 30 globally, but @a[1] is still 0
        let results = scanner.get_matches(&stream2).unwrap();
        assert_eq!(results.matching_rules().count(), 0, "Stream 2 should still not match - first marker at 0");
    }

    #[test]
    fn test_multi_stream_timeout() {
        let mut compiler = Compiler::new();
        compiler
            .add_source(r#"
                rule complex_regex {
                    strings:
                        $a = /a.*b.*c.*d.*e.*f.*g/
                    condition:
                        $a
                }
            "#)
            .unwrap();
        let rules = compiler.build();

        let mut scanner = MultiStreamScanner::new(&rules);
        scanner.set_timeout(Duration::from_millis(1));

        let stream1 = Uuid::new_v4();

        // This might timeout with complex pattern
        let result = scanner.scan_line(&stream1, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        
        // We accept either timeout or completion for this simple test
        match result {
            Err(crate::scanner::ScanError::Timeout) => {
                // Test passes - timeout occurred
            }
            Ok(_) => {
                // Also acceptable - scan completed quickly
            }
            Err(other) => {
                panic!("Unexpected error: {:?}", other);
            }
        }
    }

    #[test]
    fn test_multi_stream_many_streams() {
        let rules = crate::compile(r#"
            rule count_test {
                strings:
                    $a = "test"
                condition:
                    #a == 1
            }
        "#).unwrap();

        let mut scanner = MultiStreamScanner::new(&rules);
        let mut streams = Vec::new();

        // Create 100 streams
        for _ in 0..100 {
            let stream_id = Uuid::new_v4();
            streams.push(stream_id);
            scanner.scan_line(&stream_id, b"this is a test").unwrap();
        }

        // Verify all streams have matches
        for stream_id in &streams {
            let results = scanner.get_matches(stream_id).unwrap();
            assert_eq!(results.matching_rules().count(), 1);
        }

        // Verify we have 100 active streams
        assert_eq!(scanner.active_streams().len(), 100);
    }
}