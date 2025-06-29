# Stream Performance Test Implementation

## Overview

A new binary `stream-perf` has been added to the yara-x CLI tools to measure and compare the performance of YARA-X's streaming scanner under different usage patterns.

## Changes Made

### 1. Modified Files

#### `/cli/Cargo.toml`
- Added new binary entry for `stream-perf` pointing to `src/stream_perf.rs`
- Configured with `test = false` to exclude from default test runs

### 2. New Files

#### `/cli/src/stream_perf.rs`
A complete streaming performance test implementation featuring:

- **Command-line argument parsing** using clap
- **Multi-file YARA rule loading** support
- **Two distinct test methodologies** for performance comparison
- **Detailed timing and match reporting**

## Features

### Command Line Interface

```bash
stream-perf -r <YARA_FILES>... -i <INPUT_FILE> -c <CHUNK_SIZE>
```

**Arguments:**
- `-r, --rules`: One or more YARA rule files to load
- `-i, --input`: Input file to scan
- `-c, --chunk-size`: Number of lines to process per chunk

### Test 1: Cumulative Input Testing

This test simulates a use case where increasingly larger portions of data are scanned:

1. Creates a new `StreamingScanner` for each iteration
2. Processes cumulative data:
   - Iteration 1: Lines 1-2 (chunk_size = 2)
   - Iteration 2: Lines 1-4 (previous + chunk_size)
   - Iteration 3: Lines 1-6, and so on...
3. Measures time for each individual scan operation
4. Reports matches found at each iteration

**Purpose**: Measures how performance scales with increasing input size and demonstrates the overhead of rescanning data.

### Test 2: True Streaming Processing

This test simulates real-world streaming scenarios:

1. Creates a single `StreamingScanner` instance
2. Processes input in fixed-size chunks sequentially
3. Maintains cumulative timing from test start
4. Handles partial last chunk (if total lines % chunk_size != 0)

**Purpose**: Demonstrates the efficiency of incremental scanning and state persistence across chunks.

## Implementation Details

### Key Components

1. **Rule Loading** (`load_rules` function):
   - Loads multiple YARA files sequentially
   - Compiles all rules into a single `Rules` object
   - Provides detailed error messages for compilation failures

2. **File Reading** (`read_file_lines` function):
   - Reads entire input file into memory as lines
   - Uses `BufReader` for efficient I/O

3. **Performance Measurement**:
   - Uses `std::time::Instant` for high-precision timing
   - Reports timing in human-readable format (µs, ms, etc.)
   - Tracks both individual operation and cumulative times

### Error Handling

- Comprehensive error handling using `anyhow::Result`
- Descriptive error messages for:
  - File not found
  - YARA compilation errors
  - I/O errors

## Usage Examples

### Basic Usage
```bash
# Single rule file, 2-line chunks
./target/debug/stream-perf -r rule.yar -i input.txt -c 2
```

### Multiple Rule Files
```bash
# Multiple rule files, 5-line chunks
./target/debug/stream-perf -r rules1.yar -r rules2.yar -r rules3.yar -i data.log -c 5
```

### Example Output

```
Loading YARA rules from: test_rule.yar
Successfully loaded 1 YARA file(s)
Input file contains 9 lines

=== Test 1: Cumulative Input Testing ===
Processing input cumulatively with chunk size: 2
Iteration 1: Processed 2 lines in 95.166µs, 0 matches found
Iteration 2: Processed 4 lines in 119.917µs, 1 matches found
  - Matched rule: test_pattern
...

=== Test 2: True Streaming Processing ===
Processing input in 2 line chunks
Chunk 1: Processed 2 lines (total: 2) in 31.625µs, total time: 32.166µs, 0 matches so far
Chunk 2: Processed 2 lines (total: 4) in 32.666µs, total time: 68.916µs, 1 matches so far
...
```

## Performance Insights

The implementation reveals several key performance characteristics:

1. **Streaming Efficiency**: Test 2 consistently shows better performance for processing the same amount of data due to:
   - Single scanner instance reuse
   - No redundant processing of already-scanned data
   - Efficient state management

2. **Memory Usage**: Streaming scanner maintains minimal state, making it suitable for processing large files

3. **Match Accumulation**: Both tests demonstrate how matches accumulate as more data is processed

## Building and Running

```bash
# Build the binary
cargo build --bin stream-perf

# Run with sample files
./target/debug/stream-perf -r test_rule.yar -i test_input.txt -c 3
```

## Test Files Included

1. **test_rule.yar**: Sample YARA rules demonstrating pattern matching
2. **test_rule2.yar**: Additional rules showing count-based conditions
3. **test_input.txt**: Sample input file with various matching patterns

## Future Enhancements

Potential improvements could include:
- CSV/JSON output for automated performance analysis
- Memory usage tracking
- Support for binary file scanning
- Configurable pattern matching modes (line vs chunk)
- Parallel processing options