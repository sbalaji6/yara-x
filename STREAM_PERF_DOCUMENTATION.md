# Stream Performance Testing Documentation

This document describes the streaming performance testing tools for YARA-X and the recent enhancements made to compare `scan_line` vs `scan_chunk` methods.

## Overview

Two performance testing tools are now available:
- `stream-perf`: Uses `scan_line()` method for line-by-line processing
- `stream-perf-chunk`: Uses `scan_chunk()` method for chunk-based processing

## Recent Changes

### 1. Enhanced `stream-perf` (scan_line version)

**File**: `cli/src/stream_perf.rs`

#### Changes in Test 1 (Cumulative Testing):
- Added total time tracking across all iterations
- New summary output shows cumulative time for all test iterations
- Helps understand the overhead of creating new scanners vs processing more data

#### Changes in Test 2 (Streaming Testing):
- Added match reporting after each chunk is processed
- Shows which rules matched at each stage of streaming
- Provides better visibility into when matches occur during streaming

### 2. New `stream-perf-chunk` Tool

**File**: `cli/src/stream_perf_chunk.rs`

A new performance testing tool that uses `scan_chunk()` instead of `scan_line()` for comparison purposes.

#### Key Features:
- Processes multiple lines as a single byte chunk
- Preserves newlines within chunks
- Tracks both line count and byte count
- Allows patterns to match across line boundaries

## Usage

Both tools share the same command-line interface:

```bash
# Using scan_line (line-by-line processing)
./target/debug/stream-perf -r rule1.yar rule2.yar -i input.txt -c 1000

# Using scan_chunk (chunk-based processing)
./target/debug/stream-perf-chunk -r rule1.yar rule2.yar -i input.txt -c 1000
```

### Parameters:
- `-r, --rules`: YARA rule files to load (can specify multiple)
- `-i, --input`: Input file to scan
- `-c, --chunk-size`: Number of lines to process per chunk

## Key Differences: scan_line vs scan_chunk

### scan_line Method (`stream-perf`)
- **Processing**: One line at a time
- **Pattern Matching**: Patterns cannot span across line boundaries
- **Line Counting**: Increments by 1 for each call
- **Use Cases**: 
  - Log file analysis
  - Line-oriented data processing
  - When patterns are contained within single lines

### scan_chunk Method (`stream-perf-chunk`)
- **Processing**: Multiple lines as a single chunk
- **Pattern Matching**: Patterns can match across lines within the chunk
- **Line Counting**: Counts actual newlines in the chunk
- **Use Cases**:
  - Multi-line pattern matching
  - Binary data processing
  - Better performance for large data blocks

## Example Patterns

### Pattern that works differently with each method:

```yara
rule MultiLinePattern {
    strings:
        $a = "error\nfatal"  // This pattern spans two lines
    condition:
        $a
}
```

- With `scan_line`: This pattern will NOT match (pattern spans line boundary)
- With `scan_chunk`: This pattern WILL match if both lines are in the same chunk

### Pattern that works the same with both methods:

```yara
rule SingleLinePattern {
    strings:
        $a = "error"
        $b = "warning"
    condition:
        $a or $b
}
```

## Performance Considerations

1. **Memory Usage**:
   - `scan_line`: Lower memory footprint (processes one line at a time)
   - `scan_chunk`: Higher memory usage (holds entire chunk in memory)

2. **Processing Speed**:
   - `scan_line`: May be slower due to more function calls
   - `scan_chunk`: Generally faster for large files due to fewer function calls

3. **Pattern Matching**:
   - `scan_line`: More restrictive but predictable
   - `scan_chunk`: More flexible but depends on chunk boundaries

## Test Output Examples

### Test 1: Cumulative Input Testing

**Summary**: Test 1 simulates scenarios where increasingly larger portions of data need to be scanned, such as when analyzing growing log files or streaming data that requires re-evaluation of the entire dataset.

**How it works**:
- Creates a new `StreamingScanner` instance for each iteration
- Processes cumulative data in growing chunks:
  - Iteration 1: Scans lines 1 to chunk_size
  - Iteration 2: Scans lines 1 to (2 × chunk_size)
  - Iteration 3: Scans lines 1 to (3 × chunk_size)
  - And so on...
- Measures the time taken for each scan operation
- Tracks total matches found at each iteration
- Calculates total time across all iterations to understand cumulative overhead

**Purpose**: 
- Measures how performance scales with increasing input size
- Demonstrates the overhead of creating new scanner instances
- Shows the cost of rescanning previously processed data
- Useful for understanding performance characteristics when full dataset re-evaluation is required

### Test 1 Output (Cumulative):
```
=== Test 1: Cumulative Input Testing ===
Processing input cumulatively with chunk size: 1000
Iteration 1: Processed 1000 lines in 15.234ms, 3 matches found
  - Matched rule: ErrorDetector
Iteration 2: Processed 2000 lines in 28.456ms, 5 matches found
  - Matched rule: ErrorDetector
  - Matched rule: WarningPattern

Test 1 Summary:
Total time taken by all iterations: 156.789ms
```

### Test 2 Output (Streaming):
```
=== Test 2: True Streaming Processing ===
Processing input in 1000 line chunks
Chunk 1: Processed 1000 lines (total: 1000) in 12.345ms, total time: 12.345ms, 2 matches so far
  Matches after chunk 1:
    - ErrorDetector
Chunk 2: Processed 1000 lines (total: 2000) in 11.234ms, total time: 23.579ms, 5 matches so far
  Matches after chunk 2:
    - ErrorDetector
    - WarningPattern
```

## Building the Tools

```bash
# Build both tools
cargo build --bin stream-perf --bin stream-perf-chunk

# Or build individually
cargo build --bin stream-perf
cargo build --bin stream-perf-chunk
```

## Recommendations

1. **For Log Files**: Use `stream-perf` (scan_line) as logs are naturally line-oriented
2. **For Binary Data**: Use `stream-perf-chunk` (scan_chunk) for better performance
3. **For Multi-line Patterns**: Must use `stream-perf-chunk` (scan_chunk)
4. **For Performance Testing**: Run both tools to compare results

## Future Enhancements

Potential improvements to consider:
1. Add memory usage tracking
2. Support for custom chunk sizes in bytes (not just lines)
3. Parallel processing options
4. CSV/JSON output formats for easier analysis
5. Automated comparison between scan_line and scan_chunk results