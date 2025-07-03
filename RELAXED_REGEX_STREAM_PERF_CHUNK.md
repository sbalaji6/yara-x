# Relaxed Regex Support for stream-perf-chunk

## Overview
This document describes the changes made to add relaxed regex support to the `stream-perf-chunk` binary, matching the functionality already present in `stream-perf`.

## Changes Made

### 1. Added `relaxed_re_syntax` field to Args struct (cli/src/stream_perf_chunk.rs:41-46)
```rust
#[arg(
    long = "relaxed-re-syntax",
    help = "Use a more relaxed syntax check while parsing regular expressions",
    default_value = "false"
)]
relaxed_re_syntax: bool,
```

### 2. Updated `load_rules` function signature (cli/src/stream_perf_chunk.rs:49)
```rust
fn load_rules(yara_files: &[PathBuf], relaxed_re_syntax: bool) -> Result<Rules> {
```

### 3. Added relaxed regex support in `load_rules` (cli/src/stream_perf_chunk.rs:52-54)
```rust
if relaxed_re_syntax {
    compiler.relaxed_re_syntax(true);
}
```

### 4. Updated `load_rules` call in main (cli/src/stream_perf_chunk.rs:210)
```rust
let rules = load_rules(&args.yara_files, args.relaxed_re_syntax)?;
```

## Testing

### Test Files Used

1. **test_relaxed_regex.yar** - Contains regex patterns that require relaxed syntax:
```yara
rule test_relaxed_regex {
    strings:
        // These patterns use relaxed regex syntax that YARA accepts but YARA-X doesn't by default
        
        // Invalid escape sequence - \R is treated as literal 'R' in YARA
        $a = /test\Rpattern/
        
        // Unescaped braces in non-repetition context
        $b = /foo{}bar/
        
        // Another invalid escape sequence
        $c = /data\Xfile/
        
    condition:
        any of them
}
```

2. **test_stream_input.txt** - Test input file containing matching patterns:
```
This is a test file
It contains testRpattern which should match with relaxed syntax
Also has foo{}bar pattern
And dataXfile content
Multiple lines to test streaming
Line 6
Line 7
Line 8
Line 9
Line 10
```

### Command Lines Used for Testing

1. **Build the stream-perf-chunk binary:**
```bash
cargo build --bin stream-perf-chunk
```

2. **Verify the new option is available:**
```bash
./target/debug/stream-perf-chunk --help
```

3. **Test WITHOUT relaxed regex (should fail):**
```bash
./target/debug/stream-perf-chunk -r test_relaxed_regex.yar -i test_stream_input.txt -c 3
```
Result: Error - "unrecognized escape sequence" for `\R` in the regex pattern

4. **Test WITH relaxed regex (should succeed):**
```bash
./target/debug/stream-perf-chunk -r test_relaxed_regex.yar -i test_stream_input.txt -c 3 --relaxed-re-syntax
```
Result: Success - Rule compiled and matches found

5. **Compare with stream-perf behavior:**
```bash
./target/debug/stream-perf -r test_relaxed_regex.yar -i test_stream_input.txt -c 3 --relaxed-re-syntax | grep -E "(Matched rule:|Total matches:)"
```
Result: Same matching behavior as stream-perf-chunk

## Validation Results

The implementation was validated by:
1. Confirming that without `--relaxed-re-syntax`, invalid regex patterns cause compilation errors
2. Confirming that with `--relaxed-re-syntax`, the same patterns compile successfully
3. Verifying that matches are found in the test input when using relaxed regex
4. Comparing output with `stream-perf` to ensure consistent behavior

Both `stream-perf` and `stream-perf-chunk` now support the `--relaxed-re-syntax` flag with identical functionality.