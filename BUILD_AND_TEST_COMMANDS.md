# YARA-X Build and Test Commands

This document provides a comprehensive list of commands for building, testing, and developing YARA-X with the streaming scanner enhancements.

## Building the Project

### Basic Build Commands
```bash
# Build the entire project (debug mode)
cargo build

# Build in release mode (optimized for performance)
cargo build --release

# Build only the yara-x library
cargo build -p yara-x

# Build with all features enabled
cargo build --all-features

# Build without default features
cargo build --no-default-features
```

### Checking Code Without Building
```bash
# Check for compilation errors without producing binaries
cargo check

# Check a specific package
cargo check -p yara-x

# Check with all features
cargo check --all-features
```

## Running Tests

### All Tests
```bash
# Run all tests in the workspace
cargo test

# Run tests in release mode (faster execution)
cargo test --release

# Run tests with output displayed (even for passing tests)
cargo test -- --nocapture

# Run tests with single thread (useful for debugging)
cargo test -- --test-threads=1
```

### Streaming Scanner Tests
```bash
# Run all streaming scanner tests
cargo test streaming_scanner

# Run only the library tests for streaming scanner
cargo test --lib streaming_scanner

# Run streaming scanner tests with output
cargo test streaming_scanner -- --nocapture
```

### Multi-line Chunk Scanning Tests
```bash
# Run only the new chunk scanning tests
cargo test streaming_scanner_chunk

# Run specific chunk tests
cargo test test_streaming_scanner_chunk_multiline
cargo test test_streaming_scanner_chunk_pattern_across_lines
cargo test test_streaming_scanner_chunk_line_counting
cargo test test_streaming_scanner_chunk_offsets

# Run chunk tests with detailed output
cargo test streaming_scanner_chunk -- --nocapture --test-threads=1
```

### Debugging Failed Tests
```bash
# Run with backtrace on failure
RUST_BACKTRACE=1 cargo test streaming_scanner

# Run with full backtrace
RUST_BACKTRACE=full cargo test streaming_scanner

# Run a single test with debugging output
cargo test test_streaming_scanner_chunk_multiline -- --exact --nocapture
```

## Code Quality and Formatting

### Linting
```bash
# Run clippy (Rust linter)
cargo clippy

# Run clippy with all features
cargo clippy --all-features

# Run clippy and fail on warnings
cargo clippy -- -D warnings

# Run clippy with pedantic lints
cargo clippy -- -W clippy::pedantic
```

### Formatting
```bash
# Format all code in the project
cargo fmt

# Check formatting without applying changes
cargo fmt -- --check

# Format a specific package
cargo fmt -p yara-x
```

## Documentation

```bash
# Generate and open documentation in browser
cargo doc --open

# Generate docs for all dependencies
cargo doc --open --all

# Generate docs without dependencies
cargo doc --no-deps

# Generate docs for a specific package
cargo doc -p yara-x --open
```

## Benchmarking and Performance

```bash
# Run benchmarks (if available)
cargo bench

# Run specific benchmark
cargo bench streaming

# Run benchmarks and save baseline
cargo bench -- --save-baseline my_baseline

# Compare against baseline
cargo bench -- --baseline my_baseline
```

## Maintenance Commands

### Cleaning and Updating
```bash
# Remove all build artifacts
cargo clean

# Update dependencies to latest compatible versions
cargo update

# Check for outdated dependencies
cargo outdated

# Audit dependencies for security vulnerabilities
cargo audit
```

### Dependency Tree
```bash
# Show dependency tree
cargo tree

# Show dependency tree for a specific package
cargo tree -p yara-x

# Show only duplicate dependencies
cargo tree --duplicates
```

## Development Workflow Commands

### Quick Development Cycle
```bash
# 1. Make changes to the code

# 2. Check compilation
cargo check

# 3. Run relevant tests
cargo test streaming_scanner_chunk

# 4. Format code
cargo fmt

# 5. Run linter
cargo clippy

# 6. Run all tests
cargo test
```

### Before Committing
```bash
# Run this sequence before committing changes
cargo fmt && cargo clippy && cargo test

# Or as separate commands with error checking
cargo fmt
cargo clippy -- -D warnings
cargo test
```

## Platform-Specific Builds

```bash
# Build for specific target
cargo build --target x86_64-unknown-linux-gnu

# List available targets
rustup target list

# Add a new target
rustup target add wasm32-unknown-unknown

# Build for WebAssembly
cargo build --target wasm32-unknown-unknown
```

## Environment Variables

```bash
# Increase logging verbosity
RUST_LOG=debug cargo test

# Set specific log level for yara_x
RUST_LOG=yara_x=debug cargo test

# Disable colored output
NO_COLOR=1 cargo test

# Set backtrace level
RUST_BACKTRACE=1 cargo test  # Short backtrace
RUST_BACKTRACE=full cargo test  # Full backtrace
```

## Useful Aliases

Add these to your shell configuration file (`.bashrc`, `.zshrc`, etc.):

```bash
# Quick test command
alias ct='cargo test'

# Test with output
alias ctn='cargo test -- --nocapture'

# Quick check
alias cc='cargo check'

# Format and clippy
alias cf='cargo fmt && cargo clippy'

# Test streaming scanner
alias cts='cargo test streaming_scanner -- --nocapture'
```

## Troubleshooting

### If tests fail unexpectedly:
```bash
# Clean and rebuild
cargo clean && cargo build

# Update dependencies
cargo update

# Run with verbose output
RUST_LOG=trace cargo test streaming_scanner_chunk -- --nocapture
```

### If build fails:
```bash
# Check Rust version
rustc --version

# Update Rust
rustup update

# Check for missing dependencies
cargo tree -i <package_name>
```

### Common Issues

1. **Doc test failures for StreamingScanner**:
   - Ensure `StreamingScanner` is exported in `lib/src/lib.rs`
   - Add `pub use scanner::StreamingScanner;` to the public exports

2. **Unused import warnings**:
   - These are expected if the module is only used in tests
   - Can be suppressed with `#[allow(unused_imports)]` if needed

## CI/CD Commands

For continuous integration, use these commands:

```bash
# Full CI check
cargo fmt -- --check && \
cargo clippy -- -D warnings && \
cargo test --all-features && \
cargo doc --no-deps
```

Remember to run `cargo test` before pushing changes to ensure all tests pass!