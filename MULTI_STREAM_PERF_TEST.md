# Multi-Stream Performance Test

## Overview

The `multi-stream-perf` binary is a performance testing tool for YARA-X's multi-stream scanner capabilities. It demonstrates how to use the `MultiStreamScanner` to process multiple independent data streams concurrently.

## Building

```bash
cargo build --bin multi-stream-perf
```

## Usage

```bash
./target/debug/multi-stream-perf -r <rule_file> -i <input_file> -c <chunk_size> [--relaxed-re-syntax]
```

### Options

- `-r, --rules <YARA_FILES>...`: YARA rule files to load (required)
- `-i, --input <INPUT_FILE>`: Input file to scan (required)
- `-c, --chunk-size <CHUNK_SIZE>`: Number of lines to process per chunk (required)
- `--relaxed-re-syntax`: Use relaxed syntax check for regular expressions

## Test Scenarios

### Test 1: Alternating Between Two Streams

This test simulates processing data that arrives from two different sources alternately:
- Creates two stream IDs using UUIDs
- Processes chunks of the input file alternating between stream 1 and stream 2
- Each stream maintains its own pattern matching context
- Shows how matches accumulate independently in each stream

### Test 2: Concurrent Stream Processing

This test simulates processing even and odd lines in separate streams:
- Stream 1 processes even-numbered lines (0, 2, 4, ...)
- Stream 2 processes odd-numbered lines (1, 3, 5, ...)
- Demonstrates buffering and chunk-based processing for each stream
- Shows stream lifecycle operations (reset and close)

## Example Output

```
=== Test 1: Alternating Between Two Streams ===
Stream 1 ID: cd6d13e8-231a-46b6-bda1-4a9d785a910b
Stream 2 ID: ba3a5f41-b93e-4800-9a26-b36954aa2a69
Chunk 1 (Stream 1): Processed 3 lines (109 bytes) in 192.5µs, 1 matches
  - Stream 1: test_relaxed_regex
...

=== Test 2: Concurrent Stream Processing ===
Stream 1 (even lines) Summary:
  Lines processed: 5
  Bytes processed: 91
  Total matches: 1
  - Matched rule: test_relaxed_regex
...
```

## Key Features Demonstrated

1. **Independent Stream Contexts**: Each stream maintains its own scanning state
2. **Pattern Matching Across Chunks**: Patterns can match across chunk boundaries within a stream
3. **Stream Lifecycle Management**: Reset and close operations
4. **Performance Metrics**: Tracks lines processed, bytes processed, and execution time
5. **UUID-based Stream Identification**: Uses UUIDs to uniquely identify each stream

## Use Cases

This tool is useful for:
- Testing multi-stream scanner performance
- Validating pattern matching across multiple concurrent data sources
- Benchmarking stream processing capabilities
- Understanding how YARA-X handles independent scanning contexts