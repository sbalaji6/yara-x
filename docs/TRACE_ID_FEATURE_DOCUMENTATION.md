# TraceId Feature Documentation

## Overview

The TraceId feature in YARA-X allows you to extract trace identifiers from matched content, enabling you to correlate YARA matches with specific log entries or transactions. When a YARA pattern matches, the system automatically extracts the last quoted string from the matched line as the traceId.

## How TraceId Extraction Works

### Extraction Logic
- **What is extracted**: The last string enclosed in double quotes on the line containing the match
- **When extraction occurs**: During pattern matching, for each individual match
- **Storage**: Each match stores its own traceId independently

### Example
Given this log line:
```
2024-01-01 ERROR occurred, userId: "user123", traceId: "550e8400-e29b-41d4-a716"
```

If a YARA pattern matches "ERROR", the extracted traceId would be: `"550e8400-e29b-41d4-a716"`

## Implementation Details

### Data Structure
Each match in YARA-X contains:
```rust
pub struct Match {
    pub range: Range<usize>,      // Match position in the data
    pub xor_key: Option<u8>,      // XOR key if applicable
    pub trace_id: Option<String>, // Extracted traceId
}
```

### Extraction Process
1. When a pattern matches, the system identifies the line containing the match
2. It scans the line from start to end, finding all quoted strings
3. The last quoted string is stored as the traceId
4. Escaped quotes (\\") are handled correctly

## API Methods

### 1. Match Level - Individual Match TraceId
```rust
match.trace_id() -> Option<&str>
```
Returns the traceId for a specific match instance.

**Example:**
```rust
for m in pattern.matches() {
    if let Some(trace_id) = m.trace_id() {
        println!("Match at offset {:#x} has traceId: {}", m.range().start, trace_id);
    }
}
```

### 2. Pattern Level - All TraceIds for a Pattern
```rust
pattern.trace_ids() -> Vec<String>
```
Returns all unique traceIds from all matches of a specific pattern.

**Example:**
```rust
for pattern in rule.patterns() {
    let trace_ids = pattern.trace_ids();
    println!("Pattern '{}' has {} unique traceIds", 
             pattern.identifier(), 
             trace_ids.len());
}
```

### 3. Rule Level - All Contributing TraceIds
```rust
rule.trace_ids() -> Vec<String>
```
Returns all unique traceIds from all pattern matches that contributed to the rule matching.

**Example:**
```rust
for rule in scan_results.matching_rules() {
    let trace_ids = rule.trace_ids();
    println!("Rule '{}' matched due to {} unique traceIds", 
             rule.identifier(), 
             trace_ids.len());
}
```

### 4. Scan Results Level - All TraceIds
```rust
scan_results.trace_ids() -> Vec<String>
```
Returns all unique traceIds from all matches across all matching rules.

**Example:**
```rust
let all_trace_ids = scan_results.trace_ids();
println!("Total unique traceIds in scan: {}", all_trace_ids.len());
```

## Use Cases

### 1. Security Incident Investigation
Track which specific transactions or requests triggered security rules:
```rust
let rules = compile(r#"
    rule sql_injection {
        strings:
            $sqli = /(\bUNION\b.*\bSELECT\b|\bOR\b.*=.*)/i
        condition:
            $sqli
    }
"#)?;

// After scanning logs...
for rule in results.matching_rules() {
    if rule.identifier() == "sql_injection" {
        println!("SQL injection attempts in requests:");
        for trace_id in rule.trace_ids() {
            println!("  - Investigate request: {}", trace_id);
        }
    }
}
```

### 2. Compliance Auditing
Identify specific transactions that match compliance patterns:
```rust
let rules = compile(r#"
    rule pii_exposure {
        strings:
            $ssn = /\b\d{3}-\d{2}-\d{4}\b/
            $ccn = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/
        condition:
            any of them
    }
"#)?;

// After scanning...
let affected_transactions = results.trace_ids();
println!("Transactions with potential PII exposure: {:?}", affected_transactions);
```

### 3. Multi-Pattern Correlation
Understanding which log entries satisfy complex rule conditions:
```rust
let rules = compile(r#"
    rule suspicious_activity {
        strings:
            $login_fail = "authentication failed"
            $privilege_escalation = "sudo"
            $data_export = "export" nocase
        condition:
            $login_fail and ($privilege_escalation or $data_export)
    }
"#)?;

// Analyze which traceIds contributed to each pattern
for rule in results.matching_rules() {
    for pattern in rule.patterns() {
        let trace_ids = pattern.trace_ids();
        if !trace_ids.is_empty() {
            println!("Pattern '{}' matched in transactions:", pattern.identifier());
            for id in trace_ids {
                println!("  - {}", id);
            }
        }
    }
}
```

## Limitations

### 1. Streaming Mode
- **Issue**: In streaming/multi-stream scanning modes, traceId extraction is disabled
- **Reason**: The `scanned_data` pointer is null to conserve memory
- **Workaround**: Use normal (non-streaming) scan mode when traceId extraction is required

### 2. Line-Based Extraction
- **Issue**: TraceId must be on the same line as the match
- **Reason**: The extraction only examines the line containing the match
- **Workaround**: Ensure log formats place traceIds on the same line as relevant content

### 3. Quote Format Requirement
- **Issue**: TraceIds must be enclosed in double quotes
- **Reason**: The extractor specifically looks for quoted strings
- **Workaround**: Ensure your logging format uses quotes around traceIds

## Performance Considerations

1. **Memory Usage**: Each match stores its traceId, increasing memory usage proportionally to the number of matches
2. **Extraction Overhead**: Minimal - only processes the matched line, not the entire file
3. **Deduplication**: The `trace_ids()` methods return deduplicated results using HashSet internally

## Best Practices

### 1. Log Format Design
Structure logs to ensure traceIds are on the same line as important events:
```
// Good - traceId on same line as ERROR
2024-01-01 ERROR Database connection failed, traceId: "abc-123"

// Bad - traceId on different line
2024-01-01 ERROR Database connection failed
TraceId: "abc-123"
```

### 2. Consistent Quoting
Always quote traceIds in logs:
```
// Good
traceId: "550e8400-e29b-41d4-a716"

// Bad - won't be extracted
traceId: 550e8400-e29b-41d4-a716
```

### 3. Unique TraceIds
Ensure traceIds are unique per transaction/request for accurate correlation.

### 4. Memory-Conscious Usage
For large-scale scanning, consider:
- Processing files in batches
- Using streaming mode without traceId extraction for initial filtering
- Re-scanning matches with normal mode for traceId extraction

## Complete Example

```rust
use yara_x::{compile, Scanner};
use std::collections::HashMap;

fn analyze_security_incidents(log_file: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Compile security rules
    let rules = compile(r#"
        rule authentication_attack {
            strings:
                $failed_login = "authentication failed"
                $brute_force = /failed login.*\d{3,}/
            condition:
                any of them
        }
        
        rule data_exfiltration {
            strings:
                $large_download = /download.*[0-9]+GB/
                $suspicious_export = "unauthorized export"
            condition:
                any of them
        }
    "#)?;
    
    // Scan the logs
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(log_file)?;
    
    // Create incident report grouped by traceId
    let mut incidents: HashMap<String, Vec<String>> = HashMap::new();
    
    for rule in results.matching_rules() {
        for trace_id in rule.trace_ids() {
            incidents
                .entry(trace_id.clone())
                .or_insert_with(Vec::new)
                .push(rule.identifier().to_string());
        }
    }
    
    // Generate report
    println!("Security Incident Report");
    println!("========================\n");
    
    for (trace_id, rules) in incidents {
        println!("Transaction: {}", trace_id);
        println!("Triggered rules:");
        for rule in rules {
            println!("  - {}", rule);
        }
        println!();
    }
    
    // Summary statistics
    println!("Summary:");
    println!("  Total suspicious transactions: {}", incidents.len());
    println!("  Total rule matches: {}", 
             results.matching_rules().count());
    
    Ok(())
}
```

## Troubleshooting

### TraceIds Not Being Extracted
1. **Check scanning mode**: Ensure you're not using streaming mode
2. **Verify format**: Confirm traceIds are in double quotes
3. **Check line boundaries**: Ensure pattern and traceId are on same line

### Empty TraceId Lists
1. **Verify matches exist**: Check that patterns are actually matching
2. **Inspect match data**: Use `match.data()` to see the matched content
3. **Debug extraction**: Manually check if the matched line contains quoted strings

### Performance Issues
1. **Large number of matches**: Consider filtering rules or data
2. **Memory constraints**: Use streaming mode for initial filtering
3. **Duplicate processing**: Use the deduplicated `trace_ids()` methods

## Future Enhancements

Potential improvements to the traceId feature:
1. Support for custom extraction patterns (regex-based)
2. Multi-line traceId extraction
3. TraceId extraction in streaming mode (with memory trade-offs)
4. Configuration options for extraction behavior
5. Support for different quote types (single quotes, backticks)