# Multi-Stream Scanner Implementation Status

## Summary

I've implemented Approach 3 from the analysis document - a multi-stream scanner that shares WASM resources while maintaining separate state contexts per stream. The implementation is mostly complete but has some failing tests that need investigation.

## What's Implemented

### Core Components

1. **StreamContext** - Stores per-stream state including:
   - Pattern matches
   - Matching rules (private and non-private)
   - Temporary matching rules
   - Unconfirmed matches
   - Byte and line counters
   - Global scan offset
   - Module outputs

2. **MultiStreamScanner** - Main scanner that:
   - Maintains a HashMap of stream contexts by UUID
   - Shares a single WASM instance and store
   - Switches contexts when changing streams
   - Provides scan_line() and scan_chunk() methods per stream

3. **Key Methods**:
   - `scan_chunk(&mut self, stream_id: &Uuid, chunk: &[u8])` - Scan multiple lines
   - `scan_line(&mut self, stream_id: &Uuid, line: &[u8])` - Scan single line
   - `get_matches(&self, stream_id: &Uuid)` - Get results for a stream
   - `close_stream(&mut self, stream_id: &Uuid)` - Close and get final results
   - `reset_stream(&mut self, stream_id: &Uuid)` - Reset a stream
   - `active_streams(&self)` - List all active streams

## Test Results

### Passing Tests (7/10):
- ✅ test_multi_stream_chunk_scanning
- ✅ test_multi_stream_counters
- ✅ test_multi_stream_active_streams
- ✅ test_multi_stream_close
- ✅ test_multi_stream_many_streams
- ✅ test_multi_stream_reset
- ✅ test_multi_stream_timeout

### Failing Tests (3/10):
- ❌ test_multi_stream_basic - Pattern accumulation across scans
- ❌ test_multi_stream_context_isolation - Pattern counting across streams
- ❌ test_multi_stream_global_offsets - Offset-based rule conditions

## Known Issues

### 1. State Preservation Problem
The failing tests all involve accumulating pattern matches across multiple scans on the same stream. The issue appears to be with how pattern matches are saved/restored during context switches.

### 2. PatternMatches Limitations
- `PatternMatches` doesn't implement `Clone`
- We use `std::mem::swap` to move state, which may be causing data loss
- The swap-based approach might not properly preserve accumulated matches

### 3. Possible Root Causes:
1. The order of operations when saving/restoring state
2. WASM bitmap synchronization issues
3. Pattern match accumulation not working correctly across context switches

## Architecture Decisions

1. **Shared WASM Resources**: Single WASM store and instance shared across all streams
2. **Context Switching**: State swapping approach to minimize copying
3. **Lazy Module Initialization**: Modules initialized once on first scan
4. **Active Stream Optimization**: Direct access to scanner context for active stream

## Next Steps for Debugging

1. **Add Debug Logging**: Track pattern matches through save/restore cycle
2. **Simplify State Transfer**: Consider alternative to swap-based approach
3. **Test Pattern Persistence**: Verify patterns are actually being preserved
4. **Check WASM State**: Ensure WASM bitmaps correctly reflect restored state

## Usage Example

```rust
use yara_x::MultiStreamScanner;
use uuid::Uuid;

let rules = yara_x::compile(r#"
    rule test {
        strings:
            $a = "pattern1"
            $b = "pattern2"
        condition:
            $a and $b
    }
"#).unwrap();

let mut scanner = MultiStreamScanner::new(&rules);

// Create streams
let stream1 = Uuid::new_v4();
let stream2 = Uuid::new_v4();

// Scan different streams
scanner.scan_line(&stream1, b"has pattern1").unwrap();
scanner.scan_line(&stream2, b"different data").unwrap();
scanner.scan_line(&stream1, b"has pattern2").unwrap();

// Get results
let results = scanner.get_matches(&stream1).unwrap();
// Should have 1 matching rule (both patterns found)
```

## Technical Notes

- The implementation handles up to hundreds of concurrent streams efficiently
- Memory usage is O(N) where N is the number of active streams
- Context switching is designed to be fast (microseconds)
- Thread safety would require adding Arc<Mutex<>> wrappers