# Relaxed Regex Implementation for stream-perf

## Overview
Added support for relaxed regular expression syntax in the `stream-perf` command, allowing it to handle YARA rules that use legacy regex patterns. This brings stream-perf in line with the main `scan` command's capabilities.

## Changes Made

### 1. Modified `/Users/balaji/gemini_workspace/yara-x/cli/src/stream_perf.rs`

#### Added CLI flag to Args struct (lines 41-46):
```rust
#[arg(
    long = "relaxed-re-syntax",
    help = "Use a more relaxed syntax check while parsing regular expressions",
    default_value = "false"
)]
relaxed_re_syntax: bool,
```

#### Modified load_rules function signature (line 49):
```rust
fn load_rules(yara_files: &[PathBuf], relaxed_re_syntax: bool) -> Result<Rules> {
```

#### Added relaxed syntax configuration (lines 52-54):
```rust
if relaxed_re_syntax {
    compiler.relaxed_re_syntax(true);
}
```

#### Updated function call in main (line 194):
```rust
let rules = load_rules(&args.yara_files, args.relaxed_re_syntax)?;
```

## Test Files Created

### 1. test_relaxed_regex.yar
YARA rule file that uses relaxed regex syntax features:
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

### 2. test_standard_regex.yar
YARA rule file with standard regex patterns (works without relaxed mode):
```yara
rule test_standard_regex {
    strings:
        // Standard regex patterns that work without relaxed mode
        $a = /test.*pattern/
        $b = /foo\{2\}bar/
        $c = /data.+file/
        
    condition:
        any of them
}
```

### 3. test_stream_input.txt
Test input file containing lines that match the patterns:
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

## Test Results

### Test 1: Without --relaxed-re-syntax flag (Expected to fail)
```bash
./target/debug/stream-perf -r test_relaxed_regex.yar -i test_stream_input.txt -c 2
```
**Result**: Compilation error as expected
```
Error: Failed to compile test_relaxed_regex.yar: error[E014]: invalid regular expression
 --> line:6:19
  |
6 |         $a = /test\Rpattern/
  |                   ^^ unrecognized escape sequence
  |
  = note: did you mean `\\R` instead of `\R`?
```

### Test 2: With --relaxed-re-syntax flag (Expected to succeed)
```bash
./target/debug/stream-perf -r test_relaxed_regex.yar -i test_stream_input.txt -c 2 --relaxed-re-syntax
```
**Result**: Successfully compiled and matched the patterns
- Rule compiled without errors
- Detected matches in the input file
- Both cumulative and streaming tests completed successfully

### Test 3: Standard regex without flag (Expected to work)
```bash
./target/debug/stream-perf -r test_standard_regex.yar -i test_stream_input.txt -c 3
```
**Result**: Works correctly without needing the relaxed flag
- Standard regex patterns compile and match as expected

## Usage

To use the new feature:
```bash
stream-perf -r <rules.yar> -i <input_file> -c <chunk_size> --relaxed-re-syntax
```

The `--relaxed-re-syntax` flag enables:
- Invalid escape sequences (e.g., `\R` treated as literal 'R')
- Unescaped special characters in certain contexts (e.g., `{}` as literals when not forming a repetition operator)
- Other YARA-compatible but technically invalid regex constructs

## Benefits

1. **Compatibility**: Allows testing of legacy YARA rules without modification
2. **Performance Testing**: Enables accurate performance measurement of rules that require relaxed syntax
3. **Consistency**: Aligns stream-perf with the main scan command's capabilities
4. **Opt-in**: The feature is disabled by default, maintaining strict syntax checking unless explicitly requested

## Notes

- The relaxed syntax option must be set before any rules are compiled
- This only affects regex pattern compilation, not the streaming scanner performance
- The flag is compatible with all other stream-perf options