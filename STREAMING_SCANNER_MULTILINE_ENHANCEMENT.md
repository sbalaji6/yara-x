# YARA-X Streaming Scanner Multi-Line Enhancement

## Overview

This document describes the enhancement made to the YARA-X streaming scanner to support scanning multiple lines in a single operation, in addition to the existing line-by-line scanning capability.

## Problem Statement

The original streaming scanner implementation only supported line-by-line scanning through the `scan_line()` method. This meant:
- Patterns could not span across line boundaries
- Each line had to be processed individually
- For use cases where data arrives in chunks (not necessarily aligned with line boundaries), this was inefficient

## Solution

We've enhanced the streaming scanner with a new `scan_chunk()` method that can process multiple lines in a single operation while maintaining the same state persistence and global offset tracking capabilities.

## Implementation Details

### 1. New Public API Method

```rust
pub fn scan_chunk(&mut self, chunk: &[u8]) -> Result<(), ScanError>
```

This method:
- Accepts a chunk of data that may contain multiple lines
- Allows patterns to span across lines within the chunk
- Automatically counts lines within the chunk for statistics
- Maintains global offset tracking across chunks

### 2. Refactored Internal Implementation

The core scanning logic was refactored into a shared internal method:

```rust
fn _scan_data(&mut self, data: &[u8], count_lines: bool) -> Result<(), ScanError>
```

This method:
- Handles both line-by-line and chunk scanning
- Takes a `count_lines` parameter to determine whether to count newlines
- Properly handles chunks that don't end with a newline

### 3. Line Counting Logic

Enhanced line counting to handle various cases:
- Counts newline characters in chunks
- Handles chunks without trailing newlines correctly
- Maintains backward compatibility with `scan_line()` (always increments by 1)

## Usage Examples

### Line-by-Line Scanning (Original Behavior)
```rust
let mut scanner = StreamingScanner::new(&rules);

// Process line by line - patterns cannot span lines
scanner.scan_line(b"first line with pattern1").unwrap();
scanner.scan_line(b"second line with pattern2").unwrap();

let results = scanner.get_matches();
```

### Multi-Line Chunk Scanning (New Feature)
```rust
let mut scanner = StreamingScanner::new(&rules);

// Process entire chunk - patterns can span lines within the chunk
let chunk = b"first line with pattern1\nsecond line with pattern2\n";
scanner.scan_chunk(chunk).unwrap();

let results = scanner.get_matches();
```

### Mixed Usage
```rust
let mut scanner = StreamingScanner::new(&rules);

// Can mix both approaches
scanner.scan_chunk(b"chunk with\nmultiple lines\n").unwrap();
scanner.scan_line(b"single line").unwrap();
scanner.scan_chunk(b"another\nchunk\n").unwrap();
```

## Key Benefits

1. **Flexibility**: Users can choose between line-by-line or chunk processing based on their needs
2. **Efficiency**: Process multiple lines in a single call when data arrives in chunks
3. **Pattern Spanning**: Within a chunk, patterns can span across line boundaries
4. **Backward Compatibility**: Existing `scan_line()` usage remains unchanged
5. **Accurate Statistics**: Line counting works correctly for both methods

## Test Coverage

Added comprehensive tests to validate the new functionality:

1. **test_streaming_scanner_chunk_multiline**: Tests basic multi-line chunk scanning
2. **test_streaming_scanner_chunk_pattern_across_lines**: Validates patterns spanning lines within chunks
3. **test_streaming_scanner_chunk_line_counting**: Ensures accurate line counting with various chunk formats
4. **test_streaming_scanner_chunk_offsets**: Verifies global offset calculation across chunks

All existing tests continue to pass, ensuring backward compatibility.

## Technical Considerations

1. **Memory Usage**: Chunk size is controlled by the caller - larger chunks use more memory but are more efficient
2. **Pattern Boundaries**: Patterns still cannot span across chunk boundaries (only within chunks)
3. **Global Offsets**: All pattern matches maintain correct global stream positions regardless of scanning method

## Future Enhancements

Potential future improvements could include:
1. Automatic chunk buffering with configurable size limits
2. Pattern continuation across chunk boundaries with a sliding window approach
3. Async/streaming APIs for processing data as it arrives