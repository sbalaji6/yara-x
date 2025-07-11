# TraceId Callback Implementation for Multi-Stream Scanner

This document describes the implementation of a callback mechanism for the multi-stream scanner that reports YARA rule matches along with their associated trace IDs.

## Overview

The multi-stream scanner (`MultiStreamScanner`) has been enhanced with a callback mechanism that fires after each scan operation, reporting all currently matching rules along with their extracted trace IDs. This allows real-time monitoring of YARA rule matches across multiple streams.

## Key Features

1. **Callback fires for ALL matches** - The callback is invoked for all currently matching rules after each scan, not just newly detected matches
2. **TraceId extraction** - Extracts trace IDs from matched patterns (last quoted string in the matched line)
3. **Memory tracking** - Memory usage calculations now include trace ID storage

## Implementation Details

### Callback Type Definition

```rust
/// Callback invoked when a rule matches with its trace IDs.
/// Parameters: (rule_namespace, stream_id, rule_identifier, trace_ids)
pub type RuleMatchCallback = Box<dyn FnMut(&str, &Uuid, &str, &[String])>;
```

### Callback Invocation

The callback is invoked in the `_scan_data` method after WASM execution completes and matching rules have been identified. For each non-private matching rule:

1. Collects all unique trace IDs from the rule's pattern matches
2. Retrieves the rule's namespace and identifier from the identifier pool
3. Invokes the callback with the collected information

### Usage Example

```rust
let mut scanner = MultiStreamScanner::new(&rules);

// Set up callback to print rule matches with trace IDs
scanner.set_rule_match_callback(|namespace, stream_id, rule_name, trace_ids| {
    println!("\n    *** YARA RULE MATCH DETECTED ***");
    println!("    Rule: {}:{}", namespace, rule_name);
    println!("    Stream: {}", stream_id);
    if !trace_ids.is_empty() {
        println!("    Trace IDs found: {}", trace_ids.len());
        for (i, trace_id) in trace_ids.iter().enumerate() {
            println!("      [{}] {}", i + 1, trace_id);
        }
    }
});
```

## Modified Files and Changes

### 1. `/Users/balaji/gemini_workspace/yara-x/lib/src/scanner/multi_stream.rs`

**Major changes:**
- **Added callback type and field** (lines 29-31, 182):
  ```rust
  pub type RuleMatchCallback = Box<dyn FnMut(&str, &Uuid, &str, &[String])>;
  ```
  Added `rule_match_callback: Option<RuleMatchCallback>` field to `MultiStreamScanner`

- **Added callback setter method** (lines 316-323):
  ```rust
  pub fn set_rule_match_callback<F>(&mut self, callback: F) -> &mut Self
  where
      F: FnMut(&str, &Uuid, &str, &[String]) + 'static,
  ```

- **Implemented callback invocation** (lines 477-516):
  After WASM execution, the callback is invoked for all non-private matching rules, collecting trace IDs from their pattern matches

- **Enhanced memory calculation** (lines 785-807):
  Updated `contexts_memory_usage()` to include trace ID memory:
  - Calculates size of `Match` structs containing trace IDs
  - Adds actual string capacity for each trace ID

### 2. `/Users/balaji/gemini_workspace/yara-x/cli/src/multi_input_stream_perf.rs`

**Major changes:**
- **Added callback setup** (lines 97-112):
  ```rust
  scanner.set_rule_match_callback(|namespace, stream_id, rule_name, trace_ids| {
      println!("\n    *** YARA RULE MATCH DETECTED ***");
      println!("    Rule: {}:{}", namespace, rule_name);
      println!("    Stream: {}", stream_id);
      if !trace_ids.is_empty() {
          println!("    Trace IDs found: {}", trace_ids.len());
          for (i, trace_id) in trace_ids.iter().enumerate() {
              println!("      [{}] {}", i + 1, trace_id);
          }
      } else {
          println!("    Trace IDs: (none extracted - check if log lines contain quoted strings)");
      }
      println!("    ***************************\n");
  });
  ```

### 3. `/Users/balaji/gemini_workspace/yara-x/lib/src/scanner/matches.rs`

**Minor changes:**
- **Added iterator method** (lines 219-222):
  ```rust
  /// Returns an iterator over all pattern matches.
  pub fn iter(&self) -> impl Iterator<Item = (&PatternId, &MatchList)> {
      self.matches.iter()
  }
  ```

## Memory Usage Tracking

The memory calculation now includes:

1. **Base structures**: HashMap overhead, StreamContext struct
2. **Rule matching data**: Vectors of RuleIds, bitmaps
3. **Pattern matches with trace IDs**:
   - FxHashMap overhead for pattern matches
   - Match struct size (including Option<String> for trace_id)
   - Actual string data for each trace ID

Example memory usage:
- With 4 trace IDs: ~1,460 bytes
- With 20 trace IDs: ~2,806 bytes

## Testing

The implementation was tested using the `multi-input-stream-perf` command with log files containing ERROR patterns and trace IDs:

```bash
cargo run --bin multi-input-stream-perf -- -r test_data/error_rule.yar -i test_data/logs2.txt test_data/logs3.txt -c 500
```

Output example:
```
*** YARA RULE MATCH DETECTED ***
Rule: default:detect_errors_simple
Stream: ddee38e4-7719-4c22-858e-70bf699c8c9b
Trace IDs found: 2
  [1] trace-004
  [2] trace-005
***************************
```

## Benefits

1. **Real-time monitoring**: Users can monitor YARA rule matches as they occur during scanning
2. **TraceId visibility**: Full visibility into which trace IDs contributed to each rule match
3. **Stream identification**: Clear identification of which stream produced each match
4. **Memory awareness**: Accurate memory usage tracking including trace ID storage

## Future Enhancements

Potential improvements could include:
1. Filtering callbacks by rule or namespace
2. Batch callback mode for performance optimization
3. Callback for pattern-level matches (not just rule-level)
4. Configurable trace ID extraction patterns