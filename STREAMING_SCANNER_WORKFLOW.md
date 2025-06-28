# YARA-X Streaming Scanner: Line-by-Line Workflow

## Overview

This document provides a detailed step-by-step workflow of what happens when the streaming scanner processes each line of data, from initialization through multiple line scans.

## Initial Scanner Creation

```rust
let mut scanner = StreamingScanner::new(&rules);
```

### What happens during `new()`:
1. **WASM Store Initialization**: Creates a pinned WASM store with `ScanContext`
2. **Context Setup**: Initializes scan context with:
   - `global_scan_offset: 0`
   - Empty pattern matches
   - Empty rule vectors
   - Fresh module output maps
3. **WASM Instance Creation**: Sets up WASM instance with:
   - Global variables (filesize, pattern_search_done)
   - Memory layout for rule/pattern bitmaps
   - Linker configuration
4. **Function Binding**: Gets typed function handle to WASM main function
5. **Counter Initialization**: Sets `total_bytes_processed: 0`, `line_count: 0`

## First Line Scan

```rust
scanner.scan_line(b"first line content\n").unwrap();
```

### Step-by-Step Process:

#### 1. Timeout Setup
```rust
// In scan_line() method
let timeout_secs = if let Some(timeout) = self.timeout {
    std::cmp::min(timeout.as_secs_f32().ceil() as u64, 315_360_000)
} else { 315_360_000 };
```
- Calculates timeout in seconds (handles sub-second timeouts correctly)
- Sets up WASM epoch deadline and callback

#### 2. Heartbeat Thread Initialization
```rust
if self.timeout.is_some() {
    INIT_HEARTBEAT.call_once(|| {
        thread::spawn(|| loop {
            thread::sleep(Duration::from_secs(1));
            crate::wasm::ENGINE.increment_epoch();
            HEARTBEAT_COUNTER.fetch_update(/* ... */).unwrap();
        });
    });
}
```
- **First line only**: Spawns background heartbeat thread for timeout handling
- Thread increments WASM epoch every second
- Subsequent lines skip this (already initialized)

#### 3. Context Data Setup
```rust
let ctx = self.wasm_store.data_mut();
ctx.scanned_data = line.as_ptr();           // Points to current line
ctx.scanned_data_len = line.len();          // Length of current line
ctx.global_scan_offset = self.total_bytes_processed; // 0 for first line
```
- Updates scan context to point to current line data
- Sets global offset (0 for first line)
- Line becomes the "scanned data" that YARA sees

#### 4. Module Initialization (First Line Only)
```rust
if ctx.module_outputs.is_empty() {
    // Process imported modules
    for module_name in ctx.compiled_rules.imports() {
        let module = modules::BUILTIN_MODULES.get(module_name).unwrap();
        // Initialize module with empty data for streaming
        let module_output = if let Some(main_fn) = module.main_fn {
            Some(main_fn(&[], None)?) // Empty data for streaming
        } else { None };
        
        // Create module struct and add to root struct
        let module_struct = Struct::from_proto_descriptor_and_msg(/* ... */);
        ctx.root_struct.add_field(module_name, TypeValue::Struct(module_struct));
    }
}
```
- **First line only**: Initializes all YARA modules
- Modules get empty data since this is streaming
- Creates module structures and adds to global namespace
- Subsequent lines skip this (already initialized)

#### 5. Pattern Search Reset
```rust
self.pattern_search_done.set(self.wasm_store.as_context_mut(), Val::I32(0))?;
self.filesize.set(self.wasm_store.as_context_mut(), Val::I64(line.len() as i64))?;
```
- **Every line**: Resets pattern search flag to force new search
- Sets filesize to current line length
- This makes YARA treat each line as a fresh scan

#### 6. WASM Execution
```rust
let main_fn_result = self.wasm_main_func.call(self.wasm_store.as_context_mut(), ());
```
- Calls YARA's main WASM function
- WASM code performs pattern matching on current line
- Rule conditions evaluated with current + accumulated state

#### 7. Pattern Matching Process (Inside WASM)
1. **Aho-Corasick Search**: Finds pattern atoms in current line
2. **Pattern Verification**: Confirms full patterns match
3. **Match Recording**: Records matches with local offsets (0-based for current line)
4. **Offset Adjustment**: Our `handle_sub_pattern_match` function adjusts offsets:
   ```rust
   if self.global_scan_offset > 0 { // 0 for first line, skipped
       match_.range.start += self.global_scan_offset as usize;
       match_.range.end += self.global_scan_offset as usize;
   }
   ```
5. **Rule Evaluation**: WASM evaluates rule conditions with all available matches

#### 8. Rule Accumulation
```rust
// Move newly matched rules to persistent storage
for rules_vec in ctx.matching_rules.values_mut() {
    for rule_id in rules_vec.drain(0..) {
        if ctx.compiled_rules.get(rule_id).is_private {
            if !ctx.private_matching_rules.contains(&rule_id) {
                ctx.private_matching_rules.push(rule_id);
            }
        } else {
            if !ctx.non_private_matching_rules.contains(&rule_id) {
                ctx.non_private_matching_rules.push(rule_id);
            }
        }
    }
}
```
- Moves newly matched rules from temporary map to persistent vectors
- Avoids duplicate rules (checks if already present)
- Separates private and non-private rules

#### 9. Counter Updates
```rust
self.total_bytes_processed += line.len() as u64;  // Now = line.len()
self.line_count += 1;                             // Now = 1
```

### State After First Line:
- `total_bytes_processed`: Length of first line
- `line_count`: 1
- `global_scan_offset`: Will be `total_bytes_processed` for next line
- Pattern matches: Stored with original offsets (0-based for first line)
- Matching rules: Any rules that matched are in persistent vectors
- Modules: Fully initialized and ready for subsequent lines

## Second Line Scan

```rust
scanner.scan_line(b"second line content\n").unwrap();
```

### Key Differences from First Line:

#### 1. Timeout Setup
- Same process, but heartbeat thread already running (skipped)

#### 2. Context Data Setup
```rust
ctx.scanned_data = line.as_ptr();           // Points to second line
ctx.scanned_data_len = line.len();          // Length of second line  
ctx.global_scan_offset = self.total_bytes_processed; // Length of first line
```
- **Key difference**: `global_scan_offset` now equals first line's length
- YARA sees only the second line data, but we track global position

#### 3. Module Initialization
- **Skipped**: `ctx.module_outputs.is_empty()` is false, so no re-initialization

#### 4. Pattern Search Reset
- Same as first line: resets search flags, sets filesize to current line length

#### 5. WASM Execution
- Same process, but now operating on second line data

#### 6. Pattern Matching with Global Offset Adjustment
When patterns are found in second line:
```rust
// Example: "pattern" found at local offset 0 in second line
// handle_sub_pattern_match is called:
if self.global_scan_offset > 0 { // Now true! 
    match_.range.start += self.global_scan_offset as usize; // 0 + first_line_length
    match_.range.end += self.global_scan_offset as usize;   // 7 + first_line_length
}
```
- Pattern found at local offset 0 becomes global offset = first_line_length
- This maintains correct stream-relative positions

#### 7. Rule Evaluation
- WASM evaluates rules with:
  - All pattern matches from first line (with original offsets)
  - New pattern matches from second line (with adjusted global offsets)
  - Accumulated rule state from previous lines

#### 8. Rule Accumulation
- Same process: new matches added to persistent vectors
- Existing rules not duplicated

#### 9. Counter Updates
```rust
self.total_bytes_processed += line.len() as u64;  // first_line_len + second_line_len
self.line_count += 1;                             // 2
```

### State After Second Line:
- `total_bytes_processed`: Combined length of both lines
- `line_count`: 2
- Pattern matches: Mix of first line (original offsets) and second line (adjusted offsets)
- Matching rules: Accumulated from both lines

## Subsequent Lines (3rd, 4th, etc.)

Follow the same pattern as the second line:

### For each line:
1. **Timeout setup** (heartbeat already running)
2. **Context update** with current line data and accumulated global offset
3. **Skip module initialization** (already done)
4. **Reset pattern search** for current line
5. **WASM execution** on current line
6. **Pattern matching** with global offset = sum of all previous lines
7. **Rule evaluation** with all accumulated state
8. **Rule accumulation** (new matches only)
9. **Counter updates**

### Example for 3rd line:
```rust
// Before 3rd line scan:
global_scan_offset = len(line1) + len(line2)

// Pattern found at local offset 5 in 3rd line becomes:
global_offset = 5 + len(line1) + len(line2)
```

## Rule Matching Behavior

### Scenario: Rule requires patterns from multiple lines
```rust
rule test {
    strings:
        $a = "pattern1"  // Found in line 1
        $b = "pattern2"  // Found in line 3
    condition:
        $a and $b
}
```

#### After line 1:
- `$a` found, stored in pattern matches
- Rule condition: `$a and $b` = `true and false` = **not matched**

#### After line 2:
- No new patterns for this rule
- Rule condition: `$a and $b` = `true and false` = **not matched**

#### After line 3:
- `$b` found, stored in pattern matches  
- Rule condition: `$a and $b` = `true and true` = **MATCHED**
- Rule added to `non_private_matching_rules` vector

## Memory and State Management

### What persists between lines:
- Pattern matches (`PatternMatches`)
- Matching rule vectors (`non_private_matching_rules`, `private_matching_rules`)
- Module outputs and structures
- Global offset counter
- WASM instance and store

### What resets between lines:
- `scanned_data` pointer (points to current line)
- `scanned_data_len` (current line length)
- `pattern_search_done` flag (forces new search)
- `filesize` global (set to current line length)
- Temporary rule matching map (`matching_rules`)

## Reset Operation

```rust
scanner.reset();
```

### What gets cleared:
1. **Pattern matches**: `ctx.pattern_matches.clear()`
2. **Rule vectors**: `ctx.non_private_matching_rules.clear()`, `ctx.private_matching_rules.clear()`
3. **Temporary state**: `ctx.matching_rules.clear()`, `ctx.unconfirmed_matches.clear()`
4. **Counters**: `total_bytes_processed = 0`, `line_count = 0`, `global_scan_offset = 0`
5. **WASM memory**: Clears rule and pattern bitmaps in WASM memory

### What persists after reset:
- Module initialization (reused for next stream)
- WASM instance and compiled rules
- Scanner configuration (timeout, etc.)

## Performance Characteristics

### Per-line overhead:
- **Minimal**: Context pointer updates, counter increments
- **One-time**: Module initialization only on first line
- **Efficient**: Pattern search works on single line (smaller search space)
- **Optimized**: Rule evaluation leverages WASM performance

### Memory usage:
- **Bounded**: Pattern matches limited by max_matches_per_pattern
- **Efficient**: Reuses WASM memory layout
- **Predictable**: Linear growth with stream length

This workflow shows how the streaming scanner maintains the illusion of scanning a continuous stream while actually processing discrete lines, with careful state management to ensure correct rule evaluation and global offset tracking.