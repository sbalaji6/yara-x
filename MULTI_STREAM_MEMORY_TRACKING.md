# Multi-Stream Scanner Memory Tracking Implementation

## Date: 2025-07-04

## Overview
Added memory usage tracking capabilities to the `MultiStreamScanner` to monitor the memory consumption of cached stream contexts during scanning operations.

## Changes Made

### 1. MultiStreamScanner Memory Methods (`lib/src/scanner/multi_stream.rs`)

#### Added `contexts_memory_usage()` method (lines 694-733)
```rust
/// Estimates the memory usage of all cached stream contexts in bytes.
pub fn contexts_memory_usage(&self) -> usize
```

This method calculates:
- Base HashMap overhead
- Per-stream memory including:
  - UUID size
  - StreamContext struct size
  - Dynamic allocations (vectors, bitmaps, hashmaps)
  - Rule and pattern bitmap capacities

**Note**: This is an estimate because it doesn't include:
- Full size of `PatternMatches` (complex nested structure)
- Module outputs (protobuf messages)
- Heap fragmentation or allocator overhead

#### Added `memory_stats()` method (lines 735-752)
```rust
/// Returns detailed memory statistics for debugging.
pub fn memory_stats(&self) -> String
```

Provides a formatted string with:
- Total streams cached
- Total estimated memory usage
- Per-stream details:
  - Stream UUID
  - Bytes processed
  - Lines processed
  - Number of matched rules (private and non-private)
  - Bitmap sizes

### 2. Performance Tool Updates (`cli/src/multi_input_stream_perf.rs`)

#### Per-chunk memory reporting (lines 94-97)
```rust
// Print memory usage after each chunk
println!("        Cache memory usage: {} KB ({} active streams)", 
    scanner.contexts_memory_usage() / 1024, 
    scanner.active_streams().len());
```

Shows memory usage in KB and number of active streams after processing each chunk.

#### Final memory statistics (lines 120-122)
```rust
// Print detailed memory statistics
println!("\nFinal memory statistics:");
println!("{}", scanner.memory_stats());
```

Displays comprehensive memory breakdown at the end of the scan.

## Usage Example

### Command
```bash
./target/debug/multi-input-stream-perf -r test_multi_stream.yar -i test_input1.log test_input2.log -c 3
```

### Sample Output
```
Round 1 - File 0: 149 bytes in 329.292µs, 2 new matches (total: 2)
        Currently matching rules:
          - test_pattern1
          - test_pattern2
        Cache memory usage: 0 KB (1 active streams)

...

Final memory statistics:
Total streams cached: 2
Total contexts memory (estimate): 948 bytes

Stream 0: cce48898-4ce2-419d-9a9b-14fcb2daf29b
  - Bytes processed: 498
  - Lines processed: 10
  - Non-private rules matched: 3
  - Private rules matched: 0
  - Rule bitmap size: 1 bytes
  - Pattern bitmap size: 1 bytes
```

## Memory Efficiency Observations

1. **Minimal overhead**: Each stream context uses less than 500 bytes for basic state
2. **Bitmap efficiency**: Rule and pattern bitmaps scale with the number of rules/patterns (1 bit per rule/pattern)
3. **No data storage**: The scanner doesn't cache the actual scanned data, only metadata and match information
4. **Linear scaling**: Memory usage scales linearly with the number of active streams

## Future Improvements

1. **More accurate memory calculation**:
   - Add size calculation for `PatternMatches`
   - Include module outputs size
   - Account for heap fragmentation

2. **Memory limits**:
   - Add configurable memory limits per stream or total
   - Implement automatic stream eviction when limits are reached

3. **Memory profiling**:
   - Add memory usage metrics to performance benchmarks
   - Track memory growth over time

## Testing

Test files are provided:
- `test_multi_stream.yar` - Sample YARA rules
- `test_input1.log`, `test_input2.log` - Sample log files
- `run_multi_stream_test.sh` - Complete test script

Run the test script to see memory tracking in action:
```bash
./run_multi_stream_test.sh
```