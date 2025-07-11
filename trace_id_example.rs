use yara_x;

fn main() {
    // Create YARA rules that look for different log levels
    let rules = yara_x::compile(r#"
        rule info_logs {
            strings:
                $info = "INFO"
            condition:
                $info
        }
        
        rule error_logs {
            strings:
                $error = "ERROR"
            condition:
                $error
        }
    "#).unwrap();

    // Sample log data with traceIds
    let log_data = br#"
2024-01-01 10:00:00 INFO Starting request processing, userId: "user123", traceId: "550e8400-e29b-41d4-a716-446655440000"
2024-01-01 10:00:01 INFO Database query executed, duration: "45ms", traceId: "550e8400-e29b-41d4-a716-446655440000"
2024-01-01 10:00:02 ERROR Failed to connect to service, error: "timeout", traceId: "550e8400-e29b-41d4-a716-446655440001"
2024-01-01 10:00:03 INFO Request completed successfully, status: "200", traceId: "550e8400-e29b-41d4-a716-446655440000"
2024-01-01 10:00:04 ERROR Database connection lost, retrying: "true", traceId: "550e8400-e29b-41d4-a716-446655440002"
    "#;

    // Create scanner and scan the data
    let mut scanner = yara_x::Scanner::new(&rules);
    let scan_results = scanner.scan(log_data).unwrap();

    println!("=== YARA Scan Results with TraceId Extraction ===\n");

    // Method 1: Get all unique traceIds across all matching rules
    println!("All unique traceIds from scan:");
    let all_trace_ids = scan_results.trace_ids();
    for trace_id in &all_trace_ids {
        println!("  - {}", trace_id);
    }
    println!("\nTotal unique traceIds: {}\n", all_trace_ids.len());

    // Method 2: Get traceIds per rule
    for rule in scan_results.matching_rules() {
        println!("Rule '{}' matched", rule.identifier());
        let rule_trace_ids = rule.trace_ids();
        println!("  Unique traceIds for this rule:");
        for trace_id in &rule_trace_ids {
            println!("    - {}", trace_id);
        }
        println!("  Total: {} unique traceIds\n", rule_trace_ids.len());
    }

    // Method 3: Get traceIds per pattern with match details
    println!("Detailed matches with traceIds:");
    for rule in scan_results.matching_rules() {
        for pattern in rule.patterns() {
            println!("  Pattern '{}' in rule '{}':", pattern.identifier(), rule.identifier());
            
            // Get unique traceIds for this pattern
            let pattern_trace_ids = pattern.trace_ids();
            println!("    Unique traceIds: {:?}", pattern_trace_ids);
            
            // Show individual matches
            for (i, mat) in pattern.matches().enumerate() {
                let matched_text = std::str::from_utf8(mat.data()).unwrap_or("<invalid utf8>");
                println!("    Match #{}: '{}' at offset {}", 
                    i + 1, 
                    matched_text.trim(), 
                    mat.range().start
                );
                if let Some(trace_id) = mat.trace_id() {
                    println!("      TraceId: {}", trace_id);
                }
            }
        }
    }
}