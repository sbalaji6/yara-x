# Offset Matching Fix for Streaming Scanners

## Overview

This document describes a critical fix implemented to prevent panics when using YARA rules with offset matching conditions (e.g., `$pattern at 100`) in streaming scanners (`StreamingScanner` and `MultiStreamScanner`).

## The Problem

### Background
YARA-X provides streaming scanners that process data in chunks to handle large files efficiently without loading the entire content into memory. These scanners maintain a `global_scan_offset` that tracks the total bytes processed across all chunks.

### The Issue
When using offset matching conditions in YARA rules with streaming scanners, the following panic could occur:

```
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: TryFromIntError(())'
```

This panic occurred in the WASM module at `/lib/src/wasm/mod.rs` in the `is_pat_match_at` function:

```rust
// Original problematic code
matches.search(offset.try_into().unwrap()).is_ok()
```

### Root Cause
1. **Type Conversion Failure**: The function receives an `i64` offset and attempts to convert it to `usize` using `try_into().unwrap()`
2. **Platform Limitations**: On 32-bit platforms, `usize::MAX` is 4,294,967,295, but `i64` can represent values up to 9,223,372,036,854,775,807
3. **Streaming Offset Accumulation**: As the scanner processes more data, `global_scan_offset` increases. When checking offset conditions, these large values can exceed platform limits
4. **Unsafe Unwrap**: The `.unwrap()` call causes a panic when the conversion fails

## The Solution

### Approach
Instead of panicking on conversion failures, we gracefully handle these cases by returning sensible defaults:
- For boolean checks (pattern matches): return `false`
- For counts: return `0`
- For sizes/offsets: return `i64::MAX` (saturation)

### Implementation Details

#### 1. `is_pat_match_at` Function
**Before:**
```rust
if let Some(matches) = caller.data().pattern_matches.get(pattern_id) {
    matches.search(offset.try_into().unwrap()).is_ok()
} else {
    false
}
```

**After:**
```rust
if let Some(matches) = caller.data().pattern_matches.get(pattern_id) {
    // Try to convert offset from i64 to usize, return false if it fails
    if let Ok(offset_usize) = offset.try_into() {
        matches.search(offset_usize).is_ok()
    } else {
        // Offset is too large to be represented as usize, no match possible
        false
    }
} else {
    false
}
```

#### 2. `is_pat_match_in` Function
**Before:**
```rust
matches.matches_in_range(lower_bound as isize..=upper_bound as isize).is_positive()
```

**After:**
```rust
// Try to convert bounds from i64 to isize, return false if conversion fails
if let (Ok(lower), Ok(upper)) = (lower_bound.try_into(), upper_bound.try_into()) {
    matches.matches_in_range(lower..=upper).is_positive()
} else {
    // Bounds are too large to be represented as isize, no match possible
    false
}
```

#### 3. `pat_matches` Function
**Before:**
```rust
matches.len().try_into().unwrap()
```

**After:**
```rust
// Convert usize to i64, saturating at i64::MAX if too large
matches.len().try_into().unwrap_or(i64::MAX)
```

#### 4. Similar fixes applied to:
- `pat_matches_in`: Safe bounds conversion
- `pat_length`: Safe length conversion with saturation
- `pat_offset`: Safe offset conversion with saturation

## Why This Matters

### Streaming Scanner Use Cases
1. **Large File Analysis**: Scanning multi-gigabyte files for malware patterns
2. **Network Stream Analysis**: Continuous scanning of network traffic
3. **Log File Monitoring**: Real-time analysis of growing log files
4. **Memory-Constrained Environments**: Systems with limited RAM

### Impact Without Fix
- **Production Crashes**: Applications using streaming scanners with offset-based rules would crash unexpectedly
- **Security Implications**: Malicious files could exploit this to cause denial of service
- **Limited Rule Compatibility**: Users couldn't use offset-based rules with streaming scanners

## Testing Considerations

### Test Scenarios
1. **Small Offsets**: Verify normal operation with offsets within platform limits
2. **Large Offsets**: Test with offsets exceeding `usize::MAX` on 32-bit platforms
3. **Boundary Cases**: Test offsets near platform limits
4. **Mixed Rules**: Combine offset matching with other conditions

### Example Test Rule
```yara
rule test_offset_matching {
    strings:
        $a = "pattern"
    condition:
        $a at 4294967296  // Just beyond 32-bit usize::MAX
}
```

## Performance Impact

The fix adds minimal overhead:
- One additional conditional check per offset operation
- No memory allocation
- No change to the happy path performance

## Compatibility

- **Backward Compatible**: Existing rules continue to work
- **Forward Compatible**: Enables offset matching in streaming scenarios
- **Platform Independent**: Works correctly on both 32-bit and 64-bit systems

## Future Considerations

1. **Documentation**: Update user documentation to explain offset matching behavior in streaming mode
2. **Warnings**: Consider logging warnings when offset conversions fail (currently silent)
3. **Alternative Approaches**: Future versions might cache file segments for offset verification

## Conclusion

This fix ensures YARA-X streaming scanners can safely handle offset matching conditions without panicking, making them more robust and suitable for production use with arbitrary rule sets and file sizes.