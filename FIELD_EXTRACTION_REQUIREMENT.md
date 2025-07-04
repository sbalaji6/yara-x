# YARA Field Extraction Requirement

## Date: 2025-07-04

## User Requirement

When YARA rules match against input data:
1. Each regex pattern in the rule matches specific lines
2. From these matched lines, extract specific fields
3. Pass these extracted fields to downstream services for further processing

### Example Use Case
```
Input data:
ERROR: [2025-01-04 10:23:45] User authentication failed for user_id=12345
INFO: [2025-01-04 10:23:46] System healthy
ERROR: [2025-01-04 10:23:47] Database connection timeout for db_name=prod_db

YARA rule with regex:
rule error_logs {
    strings:
        $error_pattern = /ERROR:.*user_id=(\d+)/
    condition:
        $error_pattern
}

Desired outcome:
- Match lines containing ERROR with user_id
- Extract the user_id value (e.g., "12345")
- Pass extracted user_id to downstream service
```

## Current Implementation Analysis

### Match Structure (lib/src/scanner/matches.rs:10)
```rust
pub(crate) struct Match {
    pub range: Range<usize>,      // Byte range of match
    pub xor_key: Option<u8>,      // XOR key for xor patterns
}
```

**Limitation**: Only stores byte range, not the actual content or line information.

### Pattern Matching Flow
1. Regex patterns are compiled into VM instructions
2. Scanner finds matches and stores byte ranges
3. No mechanism to preserve matched content or extract fields

## Proposed Solution

### 1. Extend Match Structure
```rust
pub(crate) struct Match {
    pub range: Range<usize>,
    pub xor_key: Option<u8>,
    // New fields for field extraction
    pub matched_content: Option<String>,     // Actual matched text
    pub line_number: Option<usize>,          // Line where match occurred
    pub extracted_fields: Option<HashMap<String, String>>, // Named captures
}
```

### 2. Add Capture Group Support
- Leverage regex capture groups to define extractable fields
- Named capture groups preferred: `(?P<field_name>pattern)`
- Store captured values in `extracted_fields` map

### 3. Implementation Strategy

#### Phase 1: Infrastructure
- Extend Match struct with new fields
- Modify pattern compilation to preserve capture group information
- Update scanner to populate matched_content during scanning

#### Phase 2: Line-Aware Matching
- Add line tracking to scanner
- Store line number with each match
- Option to match against lines vs entire content

#### Phase 3: Field Extraction
- Extract capture groups during match confirmation
- Populate extracted_fields HashMap
- Add API to access extracted fields from matches

#### Phase 4: Integration
- Expose extracted fields through Scanner API
- Add serialization support for downstream consumption
- Consider performance implications and optimization

### 4. API Design Considerations
```rust
// Example usage after implementation
let scanner = Scanner::new(rules)?;
let scan_results = scanner.scan(data)?;

for matching_rule in scan_results.matching_rules() {
    for pattern_match in matching_rule.matches() {
        // Access extracted fields
        if let Some(fields) = pattern_match.extracted_fields() {
            if let Some(user_id) = fields.get("user_id") {
                // Send to downstream service
                downstream_service.process(user_id);
            }
        }
    }
}
```

## Implementation Notes

1. **Performance Considerations**:
   - Storing matched content increases memory usage
   - Field extraction adds processing overhead
   - Consider making it opt-in via scanner configuration

2. **Backward Compatibility**:
   - New fields should be Optional to maintain compatibility
   - Existing behavior unchanged when field extraction not enabled

3. **Testing Requirements**:
   - Unit tests for field extraction
   - Performance benchmarks
   - Edge cases: multi-line matches, large captures

## Next Steps

1. Review and refine the Match struct extension
2. Implement basic field extraction for single-line matches
3. Add capture group support to regex compilation
4. Integrate with scanner and test with real YARA rules
5. Optimize for performance and memory usage

## Questions to Address

1. Should field extraction be enabled by default or opt-in?
2. How to handle multi-line matches?
3. Maximum size limits for extracted fields?
4. Format for passing to downstream services (JSON, protobuf, etc.)?