# Multi-Stream Scanner Implementation Guide

## Overview

This document details the implementation of multi-stream scanning capabilities in YARA-X, including the creation of two performance testing tools that demonstrate concurrent stream processing.

## Implementation Summary

### 1. Multi-Stream Scanner Analysis

First, we analyzed the existing multi-stream scanner implementation in `/lib/src/scanner/multi_stream.rs` and identified:
- UUID-based stream identification
- Independent context management per stream
- Support for both `scan_line` and `scan_chunk` methods
- Stream lifecycle operations (reset, close)
- Built-in performance metrics (bytes/lines processed)

### 2. Created Two Performance Testing Tools

#### A. `multi-stream-perf` - Single File, Multiple Streams
- **Purpose**: Demonstrates splitting a single input file between multiple streams
- **Location**: `/cli/src/multi_stream_perf.rs`
- **Features**:
  - Test 1: Alternates chunks between two streams
  - Test 2: Splits even/odd lines into separate streams
  - Stream lifecycle testing (reset/close operations)

#### B. `multi-input-stream-perf` - Multiple Files, Multiple Streams
- **Purpose**: Demonstrates true multi-stream processing with multiple input files
- **Location**: `/cli/src/multi_input_stream_perf.rs`
- **Features**:
  - Each input file gets its own stream
  - Support for user-specified or auto-generated UUIDs
  - Round-robin processing across all files
  - Weighted processing (priority-based)

## Detailed Changes

### 1. Added UUID Dependency

**File**: `/cli/Cargo.toml`
```toml
uuid = { version = "1.10", features = ["v4"] }
```

### 2. Created `multi_stream_perf.rs`

**Key components**:
- Command-line argument parsing with clap
- Two test scenarios for demonstrating stream splitting
- Performance metrics collection and reporting
- Stream lifecycle operations demonstration

### 3. Created `multi_input_stream_perf.rs`

**Key components**:
- Custom argument parser for `file:uuid` format
- `StreamInfo` struct to manage per-file state
- Round-robin chunk processing across files
- Graceful EOF handling for files of different sizes

### 4. Updated Cargo.toml for New Binaries

**File**: `/cli/Cargo.toml`
```toml
[[bin]]
name = "multi-stream-perf"
path = "src/multi_stream_perf.rs"
test = false

[[bin]]
name = "multi-input-stream-perf"
path = "src/multi_input_stream_perf.rs"
test = false
```

## Build Commands

### Build All Binaries
```bash
cargo build --release
```

### Build Specific Binaries
```bash
# Build multi-stream-perf
cargo build --bin multi-stream-perf

# Build multi-input-stream-perf
cargo build --bin multi-input-stream-perf
```

### Build with Debug Information
```bash
cargo build --bin multi-stream-perf
cargo build --bin multi-input-stream-perf
```

## Test Files Created

### 1. YARA Rules

**test_relaxed_regex.yar**:
```yara
rule test_relaxed_regex {
    strings:
        $a = /test\Rpattern/
    condition:
        $a
}
```

**simple_test.yar**:
```yara
rule simple_test {
    strings:
        $a = "test"
    condition:
        $a
}
```

### 2. Input Files

**test_stream_input.txt**:
```
This is a test file for streaming scanner
It contains multiple lines with test pattern
Some lines have pattern and some don't
This line has test in it
Another line without the pattern
test pattern appears here
More content for testing
Streaming test example
Pattern test line
Final line with test
```

**test_input1.txt**:
```
File1: This is the first test file
File1: It contains test patterns
File1: Multiple lines with test content
File1: Another test pattern here
File1: Some more content to scan
```

**test_input2.txt**:
```
File2: Second input file
File2: Also has test patterns
File2: Different content here
File2: More test data
File2: Pattern matching content
File2: Additional test lines
```

**test_input3.txt**:
```
File3: Third file for testing
File3: Contains test pattern
File3: Short file with less content
```

## Testing Commands Used

### 1. Testing `multi-stream-perf`

#### Basic Test
```bash
./target/debug/multi-stream-perf -r test_relaxed_regex.yar -i test_stream_input.txt -c 100 --relaxed-re-syntax
```

#### With Different Chunk Sizes
```bash
# Small chunks (3 lines per chunk)
./target/debug/multi-stream-perf -r test_relaxed_regex.yar -i test_stream_input.txt -c 3 --relaxed-re-syntax

# Large chunks (100 lines per chunk)
./target/debug/multi-stream-perf -r test_relaxed_regex.yar -i test_stream_input.txt -c 100 --relaxed-re-syntax
```

#### With Simple Rule
```bash
./target/debug/multi-stream-perf -r simple_test.yar -i test_stream_input.txt -c 5
```

### 2. Testing `multi-input-stream-perf`

#### Basic Multi-File Test
```bash
./target/debug/multi-input-stream-perf -r simple_test.yar -i test_input1.txt -i test_input2.txt -i test_input3.txt -c 2
```

#### With Explicit UUIDs
```bash
./target/debug/multi-input-stream-perf \
  -r simple_test.yar \
  -i test_input1.txt:550e8400-e29b-41d4-a716-446655440000 \
  -i test_input2.txt:6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
  -c 2
```

#### With Relaxed Regex
```bash
./target/debug/multi-input-stream-perf \
  -r test_relaxed_regex.yar \
  -i test_input1.txt \
  -i test_input2.txt \
  -i test_input3.txt \
  -c 2 \
  --relaxed-re-syntax
```

## Test Results

### Multi-Stream-Perf Output Example
```
=== Test 1: Alternating Between Two Streams ===
Processing input alternating between two streams with chunk size: 3
Stream 1 ID: cd6d13e8-231a-46b6-bda1-4a9d785a910b
Stream 2 ID: ba3a5f41-b93e-4800-9a26-b36954aa2a69
Chunk 1 (Stream 1): Processed 3 lines (109 bytes) in 192.5µs, 1 matches
  - Stream 1: test_relaxed_regex
Chunk 2 (Stream 2): Processed 3 lines (61 bytes) in 36.5µs, 1 matches
  - Stream 2: test_relaxed_regex
...

=== Test 2: Concurrent Stream Processing ===
Processing even/odd lines in separate streams
Stream 1 (even lines) ID: af66b521-24e9-442f-bbda-e6b909201295
Stream 2 (odd lines) ID: 470d6850-4a8d-4ddc-b14d-9580503a1480
...
```

### Multi-Input-Stream-Perf Output Example
```
=== Test 1: Round-Robin Multi-File Stream Processing ===
Processing 3 files concurrently with chunk size: 2
Stream 3074de57-50c4-4aef-9de9-450f7c582a57 -> test_input1.txt
Stream bbcf4645-a902-4fef-a6fe-2cbec3fde1d3 -> test_input2.txt
Stream 49248c43-23ff-49fc-a31e-82fe24dfa5e4 -> test_input3.txt
  Round 1 - test_input1.txt: 2 lines (67 bytes) in 194.041µs, 1 matches
  Round 1 - test_input2.txt: 2 lines (54 bytes) in 40.25µs, 1 matches
  Round 1 - test_input3.txt: 2 lines (58 bytes) in 17.125µs, 0 matches
Round 1 completed in 571.917µs
...
```

## Verification Commands

### Check if binaries were built
```bash
ls -la target/debug/multi-stream-perf
ls -la target/debug/multi-input-stream-perf
```

### Run help commands
```bash
./target/debug/multi-stream-perf --help
./target/debug/multi-input-stream-perf --help
```

### Run all multi-stream tests
```bash
cargo test multi_stream --lib
```

### Check for compilation warnings
```bash
cargo check --bin multi-stream-perf
cargo check --bin multi-input-stream-perf
```

## Troubleshooting

### If UUID dependency is missing
```bash
cargo add uuid --features v4
```

### If binaries don't build
1. Ensure you're in the project root directory
2. Run `cargo clean` and rebuild
3. Check that the source files exist in `/cli/src/`

### Performance considerations
- Use smaller chunk sizes for more frequent updates
- Use larger chunk sizes for better performance
- Files are read using buffered I/O for efficiency

## Future Enhancements

1. **Directory Support**: Process all files in a directory
2. **Live Streaming**: Support for tailing files in real-time
3. **Custom Scheduling**: Beyond round-robin (e.g., priority queues)
4. **Stream Persistence**: Save/restore stream states
5. **Parallel Processing**: True parallel scanning using threads

## Summary

The implementation successfully demonstrates YARA-X's multi-stream capabilities through two complementary tools:
- `multi-stream-perf`: Shows how a single data source can be split across streams
- `multi-input-stream-perf`: Shows true multi-source concurrent processing

Both tools provide valuable performance insights and serve as reference implementations for real-world multi-stream scanning applications.