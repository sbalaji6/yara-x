# Commit Comparison Analysis

## Overview
This document provides a detailed comparison between commits:
- **f44562ba**: Refactored CLI options for recursive directory walking (by Victor M. Alvarez)
- **228c20d9**: Fixed file length handling in multi-input stream processing (by Balaji S)

These commits are completely unrelated and work on different parts of the YARA-X codebase.

## Commit f44562ba - CLI Refactoring
**Date**: June 25, 2025  
**Author**: Victor M. Alvarez <vmalvarez@virustotal.com>  
**Purpose**: Refactor CLI to improve consistency in recursive directory walking options

### Changes Made:
1. **Command Line Interface Refactoring**
   - Changed `-d/--max-depth` argument to `-r/--recursive` 
   - Affects `check` and `fix` commands
   - Improves clarity and consistency across the CLI
   - Related to issue #386

2. **Files Modified**:
   - `cli/src/commands/check.rs` (16 lines changed)
   - `cli/src/commands/fix.rs` (14 lines changed)
   - `cli/src/commands/scan.rs` (2 lines changed)
   - `cli/src/help.rs` (110 lines changed)

3. **Intent**:
   - Make the CLI more intuitive by using `--recursive` flag instead of `--max-depth`
   - Standardize options across different commands
   - Better align with common CLI conventions where `-r` typically means recursive

## Commit 228c20d9 - Multi-Input Stream Fix
**Date**: July 8, 2025  
**Author**: Balaji S <balajii.subramanian@gmail.com>  
**Purpose**: Fix file length handling in multi-input stream performance tool

### Changes Made:
1. **File Management Improvements**
   - Added `active_files` vector to track which files are still being processed
   - Changed from tracking count of active files to maintaining list of active file indices
   - Prevents attempting to read from already exhausted files

2. **Code Changes in `cli/src/multi_input_stream_perf.rs`**:
   ```rust
   // Before: Simple counter
   let mut active = args.input_files.len();
   while active > 0 {
       // Process all files
   }
   
   // After: Track active file indices
   let mut active_files = Vec::new();
   for (i, path) in args.input_files.iter().enumerate() {
       active_files.push(i);
   }
   while !active_files.is_empty() {
       // Process only active files
   }
   ```

3. **Exhausted File Handling**:
   - Added `exhausted_indices` to collect files that have no more data
   - Removes exhausted files from active list in reverse order to maintain correct indices
   - Added logging when files are exhausted

4. **Enhanced Output**:
   - File output now includes filename in addition to index
   - Better visibility into which files are being processed and when they're exhausted

### Intent:
- Fix potential infinite loop when some files are shorter than others
- Properly handle files of different lengths in round-robin processing
- Improve debugging and monitoring by showing filenames
- Ensure the tool terminates correctly when all files are processed

## Key Differences

1. **Scope**:
   - f44562ba: General CLI refactoring affecting multiple commands
   - 228c20d9: Specific bug fix for multi-input stream processing tool

2. **Type of Change**:
   - f44562ba: API/interface change (breaking change for users using --max-depth)
   - 228c20d9: Bug fix (non-breaking, improves reliability)

3. **Files Affected**:
   - f44562ba: Core CLI command files and help system
   - 228c20d9: Single specialized tool file

4. **Impact**:
   - f44562ba: Affects all users of check/fix commands
   - 228c20d9: Affects users of the multi-input-stream-perf testing tool

## Additional Context

Between these commits, the repository shows several other changes related to:
- Build and test documentation (BUILD_AND_TEST_COMMANDS.md)
- Field extraction requirements (FIELD_EXTRACTION_REQUIREMENT.md)
- Multi-input stream testing documentation
- Memory usage tracking
- Relaxed regex support
- UUID dependency addition (shown in Cargo.lock)

These indicate active development on the multi-input streaming feature, with commit 228c20d9 being a bug fix discovered during this development work.