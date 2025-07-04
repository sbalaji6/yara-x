# Multi-Input Stream Performance Test

## Overview

The `multi-input-stream-perf` binary is a performance testing tool for YARA-X's multi-stream scanner that processes multiple input files concurrently as separate streams. Each file maintains its own independent scanning context.

## Building

```bash
cargo build --bin multi-input-stream-perf
```

## Usage

```bash
./target/debug/multi-input-stream-perf -r <rule_files>... -i <input_files>... -c <chunk_size> [--relaxed-re-syntax]
```

### Options

- `-r, --rules <YARA_FILES>...`: YARA rule files to load (required)
- `-i, --input <INPUT_FILES>...`: Input files with optional UUID (required)
  - Format: `file.txt` (auto-generates UUID) or `file.txt:uuid`
- `-c, --chunk-size <CHUNK_SIZE>`: Number of lines to process per chunk (required)
- `--relaxed-re-syntax`: Use relaxed syntax check for regular expressions

### Examples

#### Basic usage with auto-generated UUIDs:
```bash
./target/debug/multi-input-stream-perf \
  -r rules.yar \
  -i server1.log \
  -i server2.log \
  -i server3.log \
  -c 100
```

#### With explicit UUIDs (useful for resuming processing):
```bash
./target/debug/multi-input-stream-perf \
  -r rules.yar \
  -i server1.log:550e8400-e29b-41d4-a716-446655440000 \
  -i server2.log:6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
  -i server3.log:6ba7b814-9dad-11d1-80b4-00c04fd430c8 \
  -c 100
```

## Test Scenarios

### Test 1: Round-Robin Multi-File Stream Processing

This test simulates processing multiple files concurrently:
- Each input file is assigned to a separate stream with its own UUID
- Processes chunks from each file in round-robin fashion
- Continues until all files are exhausted
- Shows real-time progress and match counts per stream

Example output:
```
=== Test 1: Round-Robin Multi-File Stream Processing ===
Processing 3 files concurrently with chunk size: 100
Stream 550e8400-e29b-41d4-a716-446655440000 -> server1.log
Stream 6ba7b810-9dad-11d1-80b4-00c04fd430c8 -> server2.log
Stream 6ba7b814-9dad-11d1-80b4-00c04fd430c8 -> server3.log
  Round 1 - server1.log: 100 lines (2048 bytes) in 1.2ms, 5 matches
  Round 1 - server2.log: 100 lines (1890 bytes) in 0.9ms, 3 matches
  Round 1 - server3.log: 100 lines (2105 bytes) in 1.1ms, 7 matches
Round 1 completed in 3.5ms
...
```

### Test 2: Weighted Stream Processing (Currently Disabled)

This test would demonstrate priority-based processing:
- Assigns weights to streams (first file gets highest priority)
- Processes more chunks from higher-priority streams
- Useful for scenarios where some data sources are more critical

## Key Features Demonstrated

1. **Multi-File Processing**: Each file is processed as an independent stream
2. **UUID Management**: Support for both auto-generated and user-specified UUIDs
3. **Concurrent Scanning**: All streams remain active and are processed in rounds
4. **Independent Contexts**: Each stream maintains its own pattern matching state
5. **Flexible File Sizes**: Handles files of different sizes gracefully
6. **Real-time Progress**: Shows processing progress for each stream

## Use Cases

This tool is ideal for:
- **Log Aggregation**: Processing logs from multiple servers simultaneously
- **Multi-Source Monitoring**: Scanning data from different sources in parallel
- **Distributed Systems**: Analyzing outputs from multiple nodes
- **Performance Testing**: Benchmarking multi-stream capabilities
- **Forensic Analysis**: Scanning multiple evidence files concurrently

## Performance Considerations

- Files are processed in chunks to maintain memory efficiency
- Round-robin processing ensures fair resource distribution
- Each stream's state is preserved throughout the scan
- Pattern matches can span across chunks within a stream
- Streams are automatically closed when their files are exhausted

## Implementation Details

The tool uses:
- `BufReader` for efficient file reading
- UUID v4 for stream identification
- Round-robin scheduling for fair processing
- Separate buffers per stream to handle line boundaries
- Graceful handling of EOF conditions