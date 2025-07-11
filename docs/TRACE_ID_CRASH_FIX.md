# TraceId Extraction Crash Fix Documentation

## Date: 2025-07-11

## Issue Summary
The code was crashing when trying to extract traceId in streaming/multi-stream scanning modes due to a null pointer dereference.

## Root Causes

1. **Null Pointer Dereference**: In streaming mode, `scanned_data` pointer is null, but the code was trying to dereference it via `self.scanned_data()` method without checking.

2. **Offset Mismatch**: The traceId extraction was happening after adjusting match offsets for global stream position, causing incorrect range access on chunk-local data.

## Files Modified

### 1. `lib/src/scanner/context.rs`
   - **Location 1**: Lines 753-756 (in `handle_sub_pattern_match` function)
   - **Location 2**: Line 891 (in chain pattern matching logic)

### 2. `lib/src/scanner/mod.rs`
   - Added test module import for new streaming tests

### 3. `lib/src/scanner/streaming_trace_id_test.rs` (New file)
   - Created comprehensive tests for the fix

## Detailed Changes

### Change 1: Fix in `handle_sub_pattern_match` (context.rs:747-756)

**Before:**
```rust
// Adjust match offset for streaming scanner
if self.global_scan_offset > 0 {
    match_.range.start += self.global_scan_offset as usize;
    match_.range.end += self.global_scan_offset as usize;
}

// Extract trace_id from the matched line if not already set
if match_.trace_id.is_none() {
    match_.trace_id = extract_trace_id(self.scanned_data(), &match_.range);
}
```

**After:**
```rust
// Extract trace_id from the matched line if not already set
// Must be done BEFORE adjusting offsets, as the match range is relative to current chunk
// Only attempt if scanned_data is available (not null in streaming mode)
if match_.trace_id.is_none() && !self.scanned_data.is_null() && self.scanned_data_len > 0 {
    match_.trace_id = extract_trace_id(self.scanned_data(), &match_.range);
}

// Adjust match offset for streaming scanner
if self.global_scan_offset > 0 {
    match_.range.start += self.global_scan_offset as usize;
    match_.range.end += self.global_scan_offset as usize;
}
```

**Key changes:**
1. Added null pointer check: `!self.scanned_data.is_null() && self.scanned_data_len > 0`
2. Moved extraction BEFORE offset adjustment to use correct chunk-relative ranges
3. Added detailed comments explaining the order dependency

### Change 2: Fix in chain pattern matching (context.rs:891)

**Before:**
```rust
let full_range = match_range.start..tail_match_range.end;
let trace_id = extract_trace_id(self.scanned_data(), &full_range);
```

**After:**
```rust
let full_range = match_range.start..tail_match_range.end;
// Extract trace_id only if scanned_data is available
let trace_id = if !self.scanned_data.is_null() && self.scanned_data_len > 0 {
    extract_trace_id(self.scanned_data(), &full_range)
} else {
    None
};
```

**Key changes:**
1. Added conditional extraction based on null pointer check
2. Returns `None` when in streaming mode instead of attempting extraction

### Change 3: Test Module Addition (mod.rs:63-64)

**Added:**
```rust
#[cfg(test)]
mod streaming_trace_id_test;
```

### Change 4: New Test File (streaming_trace_id_test.rs)

Created comprehensive tests including:
1. `test_trace_id_extraction_in_streaming_mode` - Verifies no crash in streaming mode
2. `test_trace_id_extraction_normal_scan` - Verifies traceId extraction works in normal mode

## Test Results

- **Streaming mode**: No crash occurs, traceId extraction returns 0 results (expected)
- **Normal scan mode**: TraceId extraction works correctly, finding 2+ traceIds
- All tests pass without crashes

## Impact

1. **Fixes crash**: Prevents null pointer dereference in streaming/multi-stream modes
2. **Maintains functionality**: Normal scan mode continues to extract traceIds correctly
3. **Correct offset handling**: TraceId extraction now uses proper chunk-relative offsets

## Future Considerations

To enable traceId extraction in streaming mode, would need to:
1. Keep chunk data in memory during processing
2. Or implement a different extraction mechanism that works with streaming data
3. Consider memory implications of retaining chunk data