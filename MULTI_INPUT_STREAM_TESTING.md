# Multi-Input Stream Scanner Testing Documentation

## Overview

The `multi-input-stream-perf` tool demonstrates YARA-X's capability to scan multiple files concurrently using the `MultiStreamScanner`, processing them in a round-robin fashion while maintaining separate scanning contexts for each stream.

## Key Features

1. **Round-Robin Processing**: Alternates between multiple input files, processing chunks from each in turn
2. **State Preservation**: Maintains scanning state across chunks for each stream independently
3. **Cross-Chunk Pattern Matching**: Can detect patterns that span multiple chunks within each stream
4. **Performance Metrics**: Reports timing and match information for each chunk processed

## Implementation Details

### Core Components

- **MultiStreamScanner**: Manages multiple concurrent scanning contexts
- **Stream Identification**: Each file is assigned a UUID for tracking
- **Chunk-based Processing**: Reads and processes data in configurable chunks (by line count)

### Match Tracking

The scanner tracks two types of match information:
- **New Matches**: Rules that started matching in the current round
- **Total Matches**: Cumulative count of all rules matching so far

```rust
// Tracking logic
let current_matches = results.matching_rules().count();
let new_matches = current_matches - prev_matches[i];
prev_matches[i] = current_matches;
```

## Building the Tool

```bash
# Build the binary
cargo build --bin multi-input-stream-perf

# Location of the built binary
./target/debug/multi-input-stream-perf
```

## Test Files Setup

### 1. Create YARA Rules

**Simple rule (test_simple_chunk.yar):**
```yara
rule simple_test {
    strings:
        $a = "START_MARKER"
        $b = "END_MARKER"
    condition:
        $a and $b
}
```

**Complex rule (test_cross_chunk.yar):**
```yara
rule cross_chunk_pattern {
    meta:
        description = "Test pattern spanning across chunks"
    strings:
        $pattern1 = "START_MARKER"
        $pattern2 = "END_MARKER"
        $combined = "HELLO_WORLD_PATTERN"
        $regex = /DATA_\d+_VALUE/
    condition:
        all of them
}
```

### 2. Create Test Data Files

**test_chunk_data1.txt:**
```
This file contains START_MARKER at the beginning
Some random data here
END_MARKER at the end
More data to fill the chunk
HELLO_WORLD_PATTERN in this file
DATA_123_VALUE matches regex
Additional content here
END_MARKER at the end
```

**test_chunk_data2.txt:**
```
Second file with START_MARKER
Different content here  
HELLO_WORLD_PATTERN in one line
Some filler text
DATA_456_VALUE for regex match
More content to process
Finally END_MARKER completes
```

**Simple test files (test_input1.txt, test_input2.txt):**
```bash
# Create smaller test files
echo -e "This is line 1\nContains foo pattern\nMore content\nEnd of file" > test_input1.txt
echo -e "Another file\nWith bar pattern\nAdditional lines\nMore data\nFinal line" > test_input2.txt
```

## Running Tests

### Basic Usage

```bash
./target/debug/multi-input-stream-perf -r <rule_file> -i <input_files...> -c <chunk_size>
```

Parameters:
- `-r, --rules`: YARA rule file(s) to load
- `-i, --input`: Input files to scan (can specify multiple)
- `-c, --chunk-size`: Number of lines to process per chunk
- `--relaxed-re-syntax`: Optional flag for relaxed regex syntax

### Test Scenarios

#### 1. Small Chunks (Forces Pattern Splits)
```bash
./target/debug/multi-input-stream-perf -r test_simple_chunk.yar -i test_chunk_data1.txt test_chunk_data2.txt -c 2
```

Expected output:
- File 0 matches in Round 2 (when END_MARKER is found)
- File 1 matches in Round 4 (when END_MARKER is found)
- Both files show "0 new matches" in subsequent rounds but maintain total match count

#### 2. Medium Chunks
```bash
./target/debug/multi-input-stream-perf -r test_simple_chunk.yar -i test_chunk_data1.txt test_chunk_data2.txt -c 5
```

#### 3. Large Chunks (Entire File)
```bash
./target/debug/multi-input-stream-perf -r test_simple_chunk.yar -i test_chunk_data1.txt test_chunk_data2.txt -c 100
```

#### 4. Complex Rule Testing
```bash
./target/debug/multi-input-stream-perf -r test_cross_chunk.yar -i test_chunk_data1.txt test_chunk_data2.txt -c 3
```

### Understanding the Output

Sample output:
```
Processing 2 files with chunk size 2
Round 1 - File 0: 71 bytes in 197.292µs, 0 new matches (total: 0)
Round 1 - File 1: 55 bytes in 33.083µs, 0 new matches (total: 0)
Round 2 - File 0: 50 bytes in 75.125µs, 1 new matches (total: 1)
        Currently matching rules:
          - simple_test
Round 2 - File 1: 49 bytes in 23.875µs, 0 new matches (total: 0)
```

Key metrics:
- **Round**: Current iteration of round-robin processing
- **File**: Index of the file being processed
- **Bytes**: Size of the chunk being scanned
- **Time**: Duration of the scan operation
- **New matches**: Rules that started matching in this round
- **Total**: Cumulative matches for this stream
- **Currently matching rules**: List of all rules currently matching

## Verifying Cross-Chunk Pattern Matching

To verify that patterns spanning chunks are properly detected:

1. **Check file contents:**
```bash
# See what patterns are where
grep -n "START_MARKER\|END_MARKER" test_chunk_data1.txt
```

2. **Run with small chunks:**
```bash
# Use chunk size 2 to ensure patterns are split
./target/debug/multi-input-stream-perf -r test_simple_chunk.yar -i test_chunk_data1.txt -c 2
```

3. **Verify behavior:**
- The rule should only match after both required patterns have been seen
- Once matched, the rule continues to show as matching in subsequent rounds
- Each stream maintains its own independent matching state

## Advanced Testing

### Testing with UUID Specification
```bash
# Files can optionally specify their UUID
./target/debug/multi-input-stream-perf -r test_simple_chunk.yar \
  -i test_chunk_data1.txt:550e8400-e29b-41d4-a716-446655440000 \
     test_chunk_data2.txt:6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
  -c 3
```

### Comparing with Other Scanners

To compare behavior with single-stream scanner:
```bash
# Build and run the chunk boundary test
cargo build --bin test-chunk-boundary
./target/debug/test-chunk-boundary
```

This test compares:
- StreamingScanner (single stream) behavior
- MultiStreamScanner (multiple streams) behavior
- Both should show equivalent pattern matching capabilities

## Key Findings

1. **State Preservation**: MultiStreamScanner correctly maintains scanning context for each stream across chunks
2. **Pattern Matching**: Patterns that span chunk boundaries are properly detected
3. **Rule Persistence**: Once a rule's conditions are satisfied, it remains in the matching state for subsequent chunks
4. **Performance**: Round-robin processing allows efficient concurrent scanning of multiple files

## Troubleshooting

If matches aren't appearing as expected:
1. Verify the YARA rule syntax
2. Check that patterns exist in the test files
3. Ensure chunk size isn't too large (missing the split)
4. Use smaller chunk sizes to force patterns to span boundaries
5. Add debug output to show chunk contents

## Performance Considerations

- Smaller chunk sizes increase overhead but demonstrate cross-chunk matching
- Larger chunk sizes are more efficient but may process entire files at once
- The scanner maintains separate contexts, using more memory than single-stream scanning
- Context switching between streams has minimal overhead due to efficient state management