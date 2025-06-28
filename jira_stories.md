### Epic: Implement Streaming YARA Scanner

**Description:** This epic covers the implementation of a new `StreamingScanner` in YARA-X, enabling efficient line-by-line processing of input data where patterns are guaranteed not to span across lines. This will allow for incremental scanning and accumulation of match results.

---

#### **Dev Story 1: Implement `StreamingScanner` Core Structure**

*   **Title:** Implement `StreamingScanner` struct and its initialization.
*   **Description:** Create a new `StreamingScanner` struct, likely in `lib/src/scanner/mod.rs` or a new dedicated file. This struct will encapsulate the persistent state required for incremental scanning, including the `ScanContext`, WASM store, WASM main function reference, WASM `filesize` global, and a `total_offset` counter. The `ScanContext` within this scanner must be initialized once and persist across all subsequent line scans.
*   **Acceptance Criteria:**
    *   A `StreamingScanner` struct is defined with fields: `rules`, `wasm_store: Pin<Box<Store<ScanContext<'static>>>>`, `wasm_main_func: TypedFunc<(), i32>`, `filesize: Global`, and `total_offset: u64`.
    *   A `StreamingScanner::new()` constructor is implemented that correctly initializes these fields, ensuring the `ScanContext` is created once and is not reset during the scanner's lifecycle.

#### **Test Story 1: Verify `StreamingScanner` Initialization**

*   **Title:** Verify `StreamingScanner` struct initialization and state persistence.
*   **Description:** Write unit tests to confirm that the `StreamingScanner` is correctly initialized and that its internal `ScanContext` and other state variables are designed to be persistent across multiple processing calls.
*   **Test Cases:**
    *   Verify that `StreamingScanner::new()` successfully creates an instance without errors.
    *   Confirm that the `ScanContext` instance within the `wasm_store` is a single, persistent object throughout the `StreamingScanner`'s lifetime.
    *   (Once `scan_line` is implemented) Verify that the `total_offset` field correctly accumulates the length of processed lines.

---

#### **Dev Story 2: Implement `scan_line` Method and WASM Interaction**

*   **Title:** Implement `scan_line` method for incremental processing and WASM interaction.
*   **Description:** Add a `scan_line(line: &[u8])` method to the `StreamingScanner` struct. This method will be responsible for preparing the `ScanContext` with the new line data, resetting the `pattern_search_done` flag in the WASM instance to force a new Aho-Corasick search for the current line, and then triggering the WASM `main` function for evaluation. This method must explicitly *not* reset the overall scanner state (e.g., `pattern_matches`, `rule_match_bitmap`).
*   **Acceptance Criteria:**
    *   A `StreamingScanner::scan_line(line: &[u8])` method is implemented.
    *   Inside `scan_line`, the `scanned_data` and `scanned_data_len` fields within the `ScanContext` are updated to point to the current `line`'s data.
    *   The WASM `filesize` global variable is updated to reflect the length of the *current line*.
    *   The `pattern_search_done` global in the WASM instance is explicitly reset to `0` (false) before the WASM `main` function is called.
    *   The WASM `main` function (`wasm_main_func.call(...)`) is invoked to trigger the scan logic.
    *   The `scan_line` method ensures that the `StreamingScanner`'s overall state (e.g., `pattern_matches` list, `rule_match_bitmap`) is preserved and not reset.
    *   The `total_offset` field is correctly incremented by `line.len() as u64 + 1` (to account for the newline character) after each line scan.

#### **Test Story 2: Verify `scan_line` Functionality and WASM Interaction**

*   **Title:** Verify `scan_line` method's incremental processing and WASM interaction.
*   **Description:** Write unit and integration tests for the `scan_line` method, focusing on its correct interaction with the `ScanContext` and the WASM instance.
*   **Test Cases:**
    *   Call `scan_line` with a sample line and verify that `scanned_data`, `scanned_data_len`, and the WASM `filesize` global are updated as expected.
    *   Verify that the `pattern_search_done` global in the WASM instance is reset to `0` (false) before each WASM execution.
    *   Verify that `total_offset` correctly accumulates across multiple `scan_line` calls.
    *   Create a simple YARA rule and input data where a pattern exists on a single line. Use `scan_line` to process that line and confirm the rule matches.

---

#### **Dev Story 3: Adjust Match Offsets for Global Context**

*   **Title:** Modify `search_for_patterns` to report global match offsets.
*   **Description:** Update the `search_for_patterns` function in `lib/src/scanner/context.rs`. When a pattern match is identified by the Aho-Corasick algorithm, its offset is initially relative to the start of the *current line*. This story requires adjusting this offset by adding the `total_offset` from the `StreamingScanner` (accessible via `ScanContext`) to ensure the reported match offset is relative to the beginning of the entire data stream processed so far. This adjusted offset must then be passed to `handle_sub_pattern_match`.
*   **Acceptance Criteria:**
    *   Inside `lib/src/scanner/context.rs`, within the `search_for_patterns` function, the `match_range` (start and end offsets) is correctly adjusted by adding `self.total_offset` (or an equivalent mechanism to access the `StreamingScanner`'s `total_offset`) before being passed to `handle_sub_pattern_match`.
    *   The `handle_sub_pattern_match` function correctly receives and stores these globally adjusted match offsets in the `pattern_matches` list.

#### **Test Story 3: Verify Global Match Offset Calculation**

*   **Title:** Verify global match offset calculation in `search_for_patterns`.
*   **Description:** Write unit and integration tests to ensure that `search_for_patterns` correctly calculates and reports global match offsets when used within the context of a `StreamingScanner`.
*   **Test Cases:**
    *   Define a YARA rule with a pattern (e.g., `$a = "test"`).
    *   Initialize a `StreamingScanner` and simulate processing a few lines to establish a non-zero `total_offset`.
    *   Call `scan_line` with a new line containing the pattern.
    *   Verify that the reported match offset for the pattern is `(line_offset + total_offset)` and not just `line_offset`.
    *   Test with multiple lines and patterns to ensure the cumulative offset is consistently and correctly applied.

---

#### **Dev Story 4: Ensure Cumulative Pattern and Rule Bitmaps**

*   **Title:** Ensure pattern and rule bitmaps accumulate correctly across line scans.
*   **Description:** Verify and, if necessary, adjust the logic in `track_pattern_match` (which updates the pattern bitmap) and the WASM-side logic (which updates the rule bitmap) to ensure that matches from previous lines are preserved. This means that setting a bit to `1` should be an OR operation, preventing previous matches from being overwritten when new lines are scanned.
*   **Acceptance Criteria:**
    *   When `track_pattern_match` is called for a new line, any `1` bits previously set in the `pattern_bitmap` (from prior lines) remain `1`.
    *   When the WASM module re-evaluates rules after a new line scan, the `rule_match_bitmap` correctly reflects all matches from all previously scanned lines, not just the current one.

#### **Test Story 4: Verify Cumulative Bitmap Behavior**

*   **Title:** Verify cumulative behavior of pattern and rule bitmaps.
*   **Description:** Write integration tests to confirm that the shared pattern and rule bitmaps correctly accumulate matches across multiple `scan_line` calls, ensuring no previous matches are lost.
*   **Test Cases:**
    *   Define two YARA rules: Rule A matches a pattern on Line 1. Rule B matches a pattern on Line 2.
    *   Initialize `StreamingScanner`.
    *   Scan Line 1. Verify Rule A matches.
    *   Scan Line 2. Verify Rule B matches, AND Rule A still shows as matched (assuming its condition is still met based on cumulative patterns).
    *   Define a rule that depends on patterns from multiple lines (e.g., `rule multi_line { strings: $a = "first"; $b = "second" condition: $a and $b }`). Scan the lines incrementally (e.g., "first" on line 1, "second" on line 2) and verify the rule matches only when both patterns are present and their offsets are correct relative to the total stream.
