# TraceId Extraction Feature Documentation

## Overview

This feature adds the ability to automatically extract traceId values from matched lines when using YARA-X. When a YARA rule matches any part of a log line, the system will extract the last double-quoted string from that line (typically the traceId UUID) and store it with the match information.

## Implementation Details

### 1. Modified Files

#### **lib/src/scanner/matches.rs**
- **Purpose**: Core match data structure
- **Changes**:
  ```rust
  // Added new field to Match struct
  pub struct Match {
      pub range: Range<usize>,
      pub xor_key: Option<u8>,
      pub trace_id: Option<String>,  // NEW: Stores extracted traceId
  }
  ```
- **Impact**: All Match objects now carry an optional traceId

#### **lib/src/scanner/context.rs**
- **Purpose**: Scanner context and match processing logic
- **Key Changes**:
  1. Added `extract_trace_id()` function:
     ```rust
     fn extract_trace_id(scanned_data: &[u8], match_range: &Range<usize>) -> Option<String>
     ```
     - Finds the complete line containing the match
     - Scans for all double-quoted strings in the line
     - Returns the last quoted string found

  2. Modified `handle_sub_pattern_match()`:
     ```rust
     // Automatically extracts trace_id for every match
     if match_.trace_id.is_none() {
         match_.trace_id = extract_trace_id(self.scanned_data(), &match_.range);
     }
     ```

  3. Updated all Match creations to include `trace_id: None` field

#### **lib/src/models.rs**
- **Purpose**: Public API for accessing match data
- **New Methods**:
  ```rust
  // On Match struct
  pub fn trace_id(&self) -> Option<&str>
  
  // On Pattern struct  
  pub fn trace_ids(&self) -> Vec<String>
  
  // On Rule struct
  pub fn trace_ids(&self) -> Vec<String>
  ```

#### **lib/src/scanner/mod.rs**
- **Purpose**: Scanner module and results API
- **New Method**:
  ```rust
  // On ScanResults struct
  pub fn trace_ids(&self) -> Vec<String>
  ```
- **Additional**: Added test module declaration

### 2. New Test File

#### **lib/src/scanner/trace_id_test.rs**
Comprehensive test suite covering:
- Basic traceId extraction
- Multiple quoted strings (verifies last one is extracted)
- Lines without quotes
- Collection methods for Rule, Pattern, and ScanResults

## Usage Examples

### Basic Usage
```rust
use yara_x;

let rules = yara_x::compile(r#"
    rule detect_errors {
        strings:
            $error = "ERROR"
        condition:
            $error
    }
"#).unwrap();

let log_data = br#"
2024-01-01 ERROR Failed to process, userId: "123", traceId: "550e8400-e29b-41d4-a716-446655440000"
"#;

let mut scanner = yara_x::Scanner::new(&rules);
let results = scanner.scan(log_data).unwrap();

// Get traceId from individual matches
for rule in results.matching_rules() {
    for pattern in rule.patterns() {
        for match_ in pattern.matches() {
            if let Some(trace_id) = match_.trace_id() {
                println!("Match has traceId: {}", trace_id);
            }
        }
    }
}
```

### Collecting All TraceIds
```rust
// Method 1: Get all unique traceIds from entire scan
let all_trace_ids = results.trace_ids();

// Method 2: Get unique traceIds per rule
for rule in results.matching_rules() {
    let rule_trace_ids = rule.trace_ids();
    println!("Rule {} has {} unique traceIds", 
             rule.identifier(), 
             rule_trace_ids.len());
}

// Method 3: Get unique traceIds per pattern
for pattern in rule.patterns() {
    let pattern_trace_ids = pattern.trace_ids();
}
```

## Testing

### Running Unit Tests
```bash
# Run all trace_id tests
cargo test trace_id_test --lib

# Run specific test
cargo test test_trace_id_extraction --lib
```

### Manual Testing
1. Create a test YARA rule:
```yara
rule test_trace {
    strings:
        $a = "INFO"
        $b = "ERROR"
    condition:
        $a or $b
}
```

2. Create test data with traceIds:
```
2024-01-01 INFO Request start, traceId: "trace-001"
2024-01-01 ERROR Request failed, traceId: "trace-002"
2024-01-01 INFO Request retry, traceId: "trace-001"
```

3. Run scan and verify traceIds are extracted

### Test Coverage
The test suite covers:
- ✅ Single match with traceId extraction
- ✅ Multiple matches with same traceId (deduplication)
- ✅ Multiple quoted strings in line (last one extracted)
- ✅ Lines without quotes (None returned)
- ✅ Collection methods at Rule level
- ✅ Collection methods at Pattern level
- ✅ Collection methods at ScanResults level

## How It Works

1. **Match Detection**: When YARA finds a pattern match in the data
2. **Line Extraction**: The system finds the complete line containing the match
3. **Quote Scanning**: Scans the line for all double-quoted strings
4. **TraceId Storage**: Stores the last quoted string as the traceId
5. **Access Methods**: Provides multiple ways to access collected traceIds

## Use Cases

1. **Security Monitoring**: Track which requests triggered security rules
2. **Log Analysis**: Correlate YARA matches with specific transactions
3. **Incident Response**: Quickly identify affected requests/sessions
4. **Compliance**: Maintain audit trail of matched patterns with request context

## Performance Considerations

- TraceId extraction happens during match processing (minimal overhead)
- Extraction only scans the matched line, not the entire file
- Collection methods use HashSet for deduplication (O(1) insertion)
- No significant memory overhead for typical log files

## Future Enhancements

Potential improvements could include:
- Configurable extraction patterns (not just last quoted string)
- Support for different traceId formats
- Option to disable extraction for performance-critical scans
- Streaming support for very large files