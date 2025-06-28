# YARA-X Streaming Scanner: Efficiency and Processing Model Explained

## Question: How does the streaming scanner handle the 5000th line?

**User Question**: "So say 5000th line is sent for scanning, the engine searches for pattern only on this line and then updates in the bitmap and in the pattern matches structure right. After that only the conditional evaluation happens and which uses the matches of all the 5000 lines in pattern matches structure and bitmap right?"

**Answer**: Yes, exactly! This question demonstrates the key insight into how the streaming scanner achieves efficiency while maintaining correctness.

## The Two-Phase Processing Model

The streaming scanner uses a **two-phase approach** that separates pattern detection from rule evaluation:

### Phase 1: Incremental Pattern Detection (Limited Scope)
- **Scope**: Only the current line (e.g., line 5000)
- **Purpose**: Find new patterns in the current data chunk
- **Efficiency**: O(current_line_length) complexity

### Phase 2: Cumulative Rule Evaluation (Full Scope)  
- **Scope**: All accumulated data from lines 1-5000
- **Purpose**: Evaluate rule conditions with complete context
- **Correctness**: Maintains global stream semantics

## Detailed Breakdown: Processing Line 5000

### 1. Pattern Search - LIMITED TO LINE 5000 ONLY

```rust
// Context points ONLY to line 5000
ctx.scanned_data = line_5000.as_ptr();           // Only line 5000 data
ctx.scanned_data_len = line_5000.len();          // Only line 5000 length
ctx.global_scan_offset = sum_of_lines_1_to_4999; // Tracks global position
```

**What happens during pattern search:**
```rust
// Aho-Corasick automaton searches ONLY line 5000
let scanned_data = self.scanned_data();  // Points to line 5000 only
for ac_match in ac.find_overlapping_iter(scanned_data) {
    // This loop only processes patterns found in line 5000
    // Previous 4999 lines are NOT re-searched
}
```

**Key Point**: The pattern search engine never looks at lines 1-4999 again. They've already been processed and their results are stored.

### 2. Data Structure Updates - NEW PATTERNS ONLY

#### Pattern Matches Structure Update:
```rust
// When pattern found at local offset 10 in line 5000:
// Global offset adjustment happens:
match_.range.start = 10 + sum_of_lines_1_to_4999;  // Convert to global offset
match_.range.end = 17 + sum_of_lines_1_to_4999;    // Convert to global offset

// PatternMatches structure now contains:
// ├── Patterns from line 1 (stored previously)
// ├── Patterns from line 2 (stored previously)  
// ├── ...
// ├── Patterns from line 4999 (stored previously)
// └── Patterns from line 5000 (just added with global offsets)
```

#### WASM Bitmap Updates:
```rust
// Pattern bitmap gets updated with NEW findings only:
// Bit positions for patterns found in line 5000 are set to 1
// Previously set bits (from lines 1-4999) remain unchanged
// Result: Bitmap reflects patterns found across ALL 5000 lines
```

### 3. Rule Evaluation - USES ALL ACCUMULATED DATA

**Complete Context Available:**
```rust
// Rule evaluation has access to:
// 1. PatternMatches: All patterns from lines 1-5000
// 2. Pattern Bitmap: All pattern states from lines 1-5000
// 3. Rule Bitmap: All rule states from lines 1-5000
```

**Example Rule Evaluation:**
```rust
rule comprehensive_test {
    strings:
        $early = "login"       // Found in line 50
        $middle = "password"   // Found in line 2500
        $recent = "success"    // Found in line 5000 (just now!)
    condition:
        $early and $middle and $recent  // NOW evaluates to TRUE!
}
```

**What the WASM evaluator sees:**
- All pattern matches with correct global offsets
- Complete pattern occurrence counts (`#pattern`)
- Accurate pattern positions (`@pattern[n]`) 
- Full rule evaluation context spanning the entire stream

## The Efficiency Model

### Why This Design is Efficient

#### 1. **Search Complexity**: O(line_length) not O(stream_length)
```
Traditional approach: Re-scan entire stream each time
├── Line 1: Search 1 line
├── Line 2: Search 2 lines  
├── Line 3: Search 3 lines
└── Line 5000: Search 5000 lines (EXPENSIVE!)

Streaming approach: Search only current line
├── Line 1: Search 1 line
├── Line 2: Search 1 line
├── Line 3: Search 1 line  
└── Line 5000: Search 1 line (EFFICIENT!)
```

#### 2. **Memory Usage**: Bounded and Predictable
```rust
// Memory grows with number of matches, not stream size
PatternMatches {
    max_matches_per_pattern: 1_000_000,  // Configurable limit
    // Total memory ≈ num_patterns × matches_per_pattern × match_size
    // Independent of total stream length
}
```

#### 3. **Processing Time**: Constant per Line
```
Time per line ≈ constant (assuming similar line lengths)
Total time for N lines ≈ O(N) 
// vs traditional O(N²) for naive re-scanning approach
```

### What Makes This Possible

#### 1. **State Separation**
- **Transient State**: Current line data, search flags
- **Persistent State**: Pattern matches, rule results, counters

#### 2. **Incremental Updates**
- Only new findings are added to existing state
- No modification of previously processed data

#### 3. **Global Offset Tracking**
```rust
// Each line knows its position in the global stream:
global_offset_for_line_N = sum(lengths of lines 1 to N-1)

// Pattern offsets are adjusted to maintain global semantics:
global_pattern_offset = local_offset + global_offset_for_current_line
```

## Correctness Guarantees

### Global Stream Semantics Maintained
1. **Pattern Positions**: All offsets are stream-relative, not line-relative
2. **Rule Evaluation**: Always considers complete accumulated context
3. **Pattern Counts**: Accurate across the entire stream
4. **Condition Logic**: Operates on global state, not local state

### Example Demonstrating Correctness
```rust
// Stream: "aaabbbccc|dddeeefff|ggghhhiii" (| represents line boundaries)
// Rule: condition: #a == 3 and @b[2] > 5

// After line 1 ("aaabbbccc"):
// - Patterns: a@0, a@1, a@2, b@3, b@4, b@5, c@6, c@7, c@8
// - Rule evaluation: #a == 3 ✓, @b[2] == 5 ✗ (not > 5)

// After line 2 ("dddeeefff"):  
// - New patterns: d@9, d@10, d@11, e@12, e@13, e@14, f@15, f@16, f@17
// - Rule evaluation: #a == 3 ✓, @b[2] == 5 ✗ (still not > 5)
// - Note: @b[2] correctly refers to global offset 5, not line-local offset

// The rule correctly evaluates using global stream context!
```

## Performance Comparison

### Naive Re-scanning Approach
```
Line 1:    Search 10 bytes    = 10 operations
Line 2:    Search 20 bytes    = 20 operations  
Line 3:    Search 30 bytes    = 30 operations
...
Line 5000: Search 50,000 bytes = 50,000 operations
Total:     ~125,000,000 operations (O(N²))
```

### Streaming Scanner Approach
```
Line 1:    Search 10 bytes = 10 operations + store results
Line 2:    Search 10 bytes = 10 operations + update results
Line 3:    Search 10 bytes = 10 operations + update results  
...
Line 5000: Search 10 bytes = 10 operations + update results
Total:     50,000 operations (O(N))
```

**Efficiency Gain**: ~2500x improvement for 5000 lines!

## Key Insights

### 1. **Separation of Concerns**
- **Pattern Detection**: Incremental, line-by-line
- **Rule Evaluation**: Cumulative, stream-wide

### 2. **Smart State Management**  
- **Persistent**: What needs to accumulate across lines
- **Transient**: What changes with each line

### 3. **Global Semantics with Local Processing**
- Process locally (current line only)
- Maintain globally (stream-wide context)

### 4. **Scalability**
- Performance doesn't degrade with stream length
- Memory usage remains bounded
- Processing time stays predictable

## Conclusion

The user's question perfectly captures the elegance of the streaming scanner design:

✅ **"Engine searches for pattern only on this line"** - Efficient incremental detection  
✅ **"Updates bitmap and pattern matches structure"** - Minimal state updates  
✅ **"Conditional evaluation uses matches of all 5000 lines"** - Complete context for correctness

This design achieves the best of both worlds: **linear-time efficiency** with **complete semantic correctness**. The streaming scanner proves that you don't need to re-process the entire stream to maintain accurate rule evaluation - you just need smart separation between pattern detection and rule evaluation phases.

## Practical Implications

For real-world usage:
- **Large log files**: Can process gigabytes without performance degradation
- **Real-time streams**: Constant per-line processing time
- **Memory efficiency**: Bounded memory usage regardless of stream size  
- **Rule accuracy**: Full YARA rule semantics preserved across stream boundaries

This makes the streaming scanner ideal for scenarios like log analysis, network monitoring, and real-time security scanning where both efficiency and correctness are critical.