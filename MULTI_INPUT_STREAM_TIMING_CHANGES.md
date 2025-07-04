# Multi-Input Stream Performance Tool - Timing Feature Implementation

## Overview
This document describes the changes made to add per-file timing information to the `multi-input-stream-perf` tool in the YARA-X project.

## Changes Made

### 1. Modified `StreamInfo` Struct
Added timing-related fields to track processing time for each stream:

```rust
struct StreamInfo {
    // ... existing fields ...
    start_time: Option<Instant>,        // When processing started for this stream
    total_time: std::time::Duration,    // Total time spent processing this stream
    processed_in_main_loop: bool,       // Helper flag to track stream processing
}
```

### 2. Updated `StreamInfo::new()` Constructor
Initialize the new timing fields:

```rust
fn new(path: PathBuf, uuid: Uuid) -> Result<Self> {
    // ... existing code ...
    Ok(StreamInfo {
        // ... existing fields ...
        start_time: None,
        total_time: std::time::Duration::new(0, 0),
        processed_in_main_loop: false,
    })
}
```

### 3. Modified Chunk Processing Logic
In `test1_round_robin_processing`, added timing capture for each chunk:

```rust
// Start timing for this stream if not already started
if stream.start_time.is_none() {
    stream.start_time = Some(Instant::now());
}

let chunk_start = Instant::now();
scanner.scan_chunk(&stream.uuid, &chunk)?;
let chunk_elapsed = chunk_start.elapsed();

// Add to total time for this stream
stream.total_time += chunk_elapsed;
```

### 4. Enhanced Final Results Output
Updated the results section to display timing information:

```rust
println!("  Total time: {:?}", stream.total_time);
if stream.total_time.as_secs_f64() > 0.0 {
    println!("  Processing speed: {:.2} MB/s", 
        stream.bytes_read as f64 / (1024.0 * 1024.0) / stream.total_time.as_secs_f64());
}
```

### 5. Fixed Infinite Loop Bug
Fixed an issue where the program would enter an infinite loop when streams were exhausted:
- Properly track when streams become exhausted
- Only decrement `active_streams` when a stream transitions from active to exhausted
- Added `processed_in_main_loop` flag to prevent double-processing

## Building the Tool

### Prerequisites
- Rust toolchain installed
- Clone of the yara-x repository

### Build Command
```bash
cd /Users/balaji/gemini_workspace/yara-x
cargo build --bin multi-input-stream-perf
```

The binary will be created at: `./target/debug/multi-input-stream-perf`

## Test Files Used

### 1. YARA Rule File: `simple_test.yar`
```yara
rule simple_test {
    strings:
        $test = "test"
    condition:
        $test
}
```

### 2. Test Input File 1: `test_input1.txt`
```
File1: This is the first test file
File1: It contains test patterns
File1: Multiple lines with test content
File1: Another test pattern here
File1: Some more content to scan
```

### 3. Test Input File 2: `test_input2.txt`
```
File2: This is the second test file
File2: It also has test patterns
File2: Different content from file1
File2: More test data here
File2: Additional lines for testing
File2: Final line of file2
```

### 4. Test Input File 3: `test_input3.txt`
```
File3: Third test file
File3: Shorter than others
File3: Contains test pattern
```

## Test Commands and Expected Output

### Test 1: Multiple Files with Default Chunk Size
```bash
./target/debug/multi-input-stream-perf -r simple_test.yar -i test_input1.txt -i test_input2.txt -i test_input3.txt -c 10
```

**Expected Output Structure:**
```
Loading YARA rules from: simple_test.yar
Successfully loaded 1 YARA file(s)

Input files:
  test_input1.txt -> [UUID]
  test_input2.txt -> [UUID]
  test_input3.txt -> [UUID]

=== Test 1: Round-Robin Multi-File Stream Processing ===
Processing 3 files concurrently with chunk size: 10
[Processing output...]

--- Final Results ---

Stream [UUID] (test_input1.txt)
  Lines processed: 5
  Bytes processed: 173
  Total time: 247.916µs
  Processing speed: 0.67 MB/s
  Matches: 1
  - Matched rule: simple_test

Stream [UUID] (test_input2.txt)
  Lines processed: 6
  Bytes processed: 167
  Total time: 53.875µs
  Processing speed: 2.96 MB/s
  Matches: 1
  - Matched rule: simple_test

[Similar output for test_input3.txt]
```

### Test 2: Smaller Chunk Size
```bash
./target/debug/multi-input-stream-perf -r simple_test.yar -i test_input1.txt -i test_input2.txt -c 5
```

This will process files in smaller chunks, potentially showing multiple rounds of processing.

### Test 3: Single File Processing
```bash
./target/debug/multi-input-stream-perf -r simple_test.yar -i test_input1.txt -c 100
```

This processes a single file with a large chunk size (all at once).

### Test 4: With Custom UUIDs
```bash
./target/debug/multi-input-stream-perf -r simple_test.yar -i test_input1.txt:550e8400-e29b-41d4-a716-446655440000 -i test_input2.txt -c 10
```

## Key Features of the Implementation

1. **Per-Stream Timing**: Each input file/stream has its own timing information tracked independently

2. **Accurate Processing Speed**: Calculates MB/s based on actual bytes processed and time taken

3. **Round-Robin Support**: Timing works correctly even when files are processed in alternating chunks

4. **Multiple Test Modes**: Supports both round-robin and weighted processing modes

5. **Safe Division**: Handles edge cases where processing time might be zero

## Performance Metrics Displayed

For each input file, the tool now displays:
- **Lines processed**: Total number of lines read from the file
- **Bytes processed**: Total bytes scanned
- **Total time**: Cumulative time spent processing this specific file
- **Processing speed**: Throughput in MB/s
- **Matches**: Number of YARA rule matches

## Troubleshooting

If the program appears to hang:
1. Check that input files exist and are readable
2. Verify YARA rules compile correctly
3. Use smaller chunk sizes for testing
4. Check for very large input files that might take time to process

## Notes

- The timing excludes file I/O time for reading chunks; it only measures the actual scanning time
- Processing speed may vary based on rule complexity and input data patterns
- The tool uses high-resolution timers (`std::time::Instant`) for accuracy