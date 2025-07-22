use std::cell::RefCell;
use std::ops::Deref;
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::Once;
use std::thread;
use std::time::Duration;

use indexmap::IndexMap;
use protobuf::MessageDyn;
use rustc_hash::{FxHashMap, FxHashSet};
use wasmtime::{AsContext, AsContextMut, Global, Store, TypedFunc, Val};

use crate::compiler::{RuleId, Rules};
use crate::models::Rule;
use crate::modules;
use crate::scanner::context::ScanContext;
use crate::scanner::matches::PatternMatches;
use crate::scanner::offset_cache::OffsetCache;
use crate::scanner::{ScanError, HEARTBEAT_COUNTER};
use crate::types::{Struct, TypeValue};
use crate::variables::VariableError;
use crate::wasm::{self, MATCHING_RULES_BITMAP_BASE};

static INIT_HEARTBEAT: Once = Once::new();

/// A streaming scanner that can process data incrementally while maintaining
/// state across multiple scans.
///
/// Unlike the regular [`Scanner`], which resets its state between scans,
/// `StreamingScanner` preserves pattern matches and rule evaluations across
/// multiple calls to [`scan_line`](StreamingScanner::scan_line) or 
/// [`scan_chunk`](StreamingScanner::scan_chunk).
///
/// # Important Notes
///
/// - When using `scan_line`: Patterns must not span across line boundaries
/// - When using `scan_chunk`: Patterns can span across lines within the chunk
/// - Each scan is processed independently for pattern matching
/// - Match offsets are adjusted to be global (relative to the entire stream)
/// - Rule conditions are re-evaluated after each scan with cumulative results
///
/// # Example
///
/// ```no_run
/// # use yara_x;
/// # let rules = yara_x::compile(r#"
/// #     rule test {
/// #         strings:
/// #             $a = "pattern1"
/// #             $b = "pattern2"
/// #         condition:
/// #             $a and $b
/// #     }
/// # "#).unwrap();
/// let mut scanner = yara_x::StreamingScanner::new(&rules);
/// 
/// // Using line-by-line scanning
/// scanner.scan_line(b"first line with pattern1").unwrap();
/// let results = scanner.get_matches();
/// assert_eq!(results.matching_rules().count(), 0); // Rule doesn't match yet
/// 
/// scanner.scan_line(b"second line with pattern2").unwrap();
/// let results = scanner.get_matches();
/// assert_eq!(results.matching_rules().count(), 1); // Now the rule matches
/// 
/// // Or using chunk scanning (can process multiple lines at once)
/// scanner.reset();
/// scanner.scan_chunk(b"first line with pattern1\nsecond line with pattern2\n").unwrap();
/// let results = scanner.get_matches();
/// assert_eq!(results.matching_rules().count(), 1); // Rule matches in single scan
/// ```
pub struct StreamingScanner<'r> {
    rules: &'r Rules,
    wasm_store: Pin<Box<Store<ScanContext<'static>>>>,
    wasm_main_func: TypedFunc<(), i32>,
    wasm_instance: wasmtime::Instance,
    filesize: Global,
    pattern_search_done: Global,
    /// Total number of bytes processed so far
    total_bytes_processed: u64,
    /// Number of lines processed
    line_count: u64,
    /// Timeout for each line scan
    timeout: Option<Duration>,
}

impl<'r> StreamingScanner<'r> {
    /// Creates a new streaming scanner for the given [`Rules`].
    pub fn new(rules: &'r Rules) -> Self {
        let num_rules = rules.num_rules() as u32;
        let num_patterns = rules.num_patterns() as u32;

        let ctx = ScanContext {
            wasm_store: NonNull::dangling(),
            runtime_objects: IndexMap::new(),
            compiled_rules: rules,
            console_log: None,
            current_struct: None,
            root_struct: rules.globals().make_root(),
            scanned_data: std::ptr::null(),
            scanned_data_len: 0,
            private_matching_rules: Vec::new(),
            non_private_matching_rules: Vec::new(),
            matching_rules: IndexMap::new(),
            main_memory: None,
            module_outputs: FxHashMap::default(),
            user_provided_module_outputs: FxHashMap::default(),
            pattern_matches: PatternMatches::new(),
            unconfirmed_matches: FxHashMap::default(),
            deadline: 0,
            limit_reached: FxHashSet::default(),
            regexp_cache: RefCell::new(FxHashMap::default()),
            global_scan_offset: 0,
            #[cfg(feature = "rules-profiling")]
            time_spent_in_pattern: FxHashMap::default(),
            #[cfg(feature = "rules-profiling")]
            time_spent_in_rule: vec![0; num_rules as usize],
            #[cfg(feature = "rules-profiling")]
            rule_execution_start_time: 0,
            #[cfg(feature = "rules-profiling")]
            last_executed_rule: None,
            #[cfg(any(feature = "rules-profiling", feature = "logging"))]
            clock: quanta::Clock::new(),
            offset_cache: None,
        };

        let mut wasm_store =
            Box::pin(Store::new(&crate::wasm::ENGINE, unsafe {
                std::mem::transmute::<ScanContext<'r>, ScanContext<'static>>(ctx)
            }));

        wasm_store.data_mut().wasm_store =
            NonNull::from(wasm_store.as_ref().deref());

        let filesize = Global::new(
            wasm_store.as_context_mut(),
            wasmtime::GlobalType::new(wasmtime::ValType::I64, wasmtime::Mutability::Var),
            Val::I64(0),
        )
        .unwrap();

        let pattern_search_done = Global::new(
            wasm_store.as_context_mut(),
            wasmtime::GlobalType::new(wasmtime::ValType::I32, wasmtime::Mutability::Var),
            Val::I32(0),
        )
        .unwrap();

        let matching_patterns_bitmap_base =
            MATCHING_RULES_BITMAP_BASE as u32 + num_rules.div_ceil(8);

        let mem_size = u32::div_ceil(
            matching_patterns_bitmap_base + num_patterns.div_ceil(8),
            65536,
        );

        let matching_patterns_bitmap_base = Global::new(
            wasm_store.as_context_mut(),
            wasmtime::GlobalType::new(wasmtime::ValType::I32, wasmtime::Mutability::Const),
            Val::I32(matching_patterns_bitmap_base as i32),
        )
        .unwrap();

        let main_memory = wasmtime::Memory::new(
            wasm_store.as_context_mut(),
            wasmtime::MemoryType::new(mem_size, Some(mem_size)),
        )
        .unwrap();

        let wasm_instance = wasm::new_linker()
            .define(wasm_store.as_context(), "yara_x", "filesize", filesize)
            .unwrap()
            .define(
                wasm_store.as_context(),
                "yara_x",
                "pattern_search_done",
                pattern_search_done,
            )
            .unwrap()
            .define(
                wasm_store.as_context(),
                "yara_x",
                "matching_patterns_bitmap_base",
                matching_patterns_bitmap_base,
            )
            .unwrap()
            .define(wasm_store.as_context(), "yara_x", "main_memory", main_memory)
            .unwrap()
            .instantiate(wasm_store.as_context_mut(), rules.wasm_mod())
            .unwrap();

        let main_fn = wasm_instance
            .get_typed_func::<(), i32>(wasm_store.as_context_mut(), "main")
            .unwrap();

        wasm_store.data_mut().main_memory = Some(main_memory);

        Self {
            rules,
            wasm_store,
            wasm_main_func: main_fn,
            wasm_instance,
            filesize,
            pattern_search_done,
            total_bytes_processed: 0,
            line_count: 0,
            timeout: None,
        }
    }

    /// Sets a timeout for scan operations.
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Enables the offset cache for storing input data by trace ID.
    /// This allows offset-based data access across chunk boundaries.
    pub fn enable_offset_cache(&mut self, cache_path: &str) -> Result<&mut Self, ScanError> {
        match OffsetCache::new(cache_path) {
            Ok(cache) => {
                let cache_rc = Rc::new(cache);
                // Update the wasm store context with the cache
                self.wasm_store.data_mut().offset_cache = Some(cache_rc);
                Ok(self)
            }
            Err(e) => Err(ScanError::Internal(format!("Failed to create offset cache: {}", e))),
        }
    }

    /// Sets the value of a global variable.
    pub fn set_global<T: TryInto<TypeValue>>(
        &mut self,
        ident: &str,
        value: T,
    ) -> Result<&mut Self, VariableError>
    where
        VariableError: From<<T as TryInto<TypeValue>>::Error>,
    {
        let type_value = value.try_into()?;
        let ctx = self.wasm_store.data_mut();
        
        // Update the root struct with the new global value
        ctx.root_struct.add_field(ident, type_value.into());
        
        Ok(self)
    }

    /// Sets a callback that is invoked every time a YARA rule calls the
    /// `console` module.
    pub fn console_log<F>(&mut self, callback: F) -> &mut Self
    where
        F: FnMut(String) + 'static,
    {
        self.wasm_store.data_mut().console_log = Some(Box::new(callback));
        self
    }

    /// Scans a chunk of data that may contain multiple lines.
    ///
    /// This method processes the provided chunk and updates the cumulative
    /// pattern matches. Rule conditions are re-evaluated with the updated
    /// pattern information. The chunk can contain any number of lines,
    /// including partial lines.
    ///
    /// # Arguments
    ///
    /// * `chunk` - The chunk of data to scan (may contain multiple lines)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the scan was successful, or an error if the scan
    /// timed out or encountered another issue.
    pub fn scan_chunk(&mut self, chunk: &[u8]) -> Result<(), ScanError> {
        self._scan_data(chunk, true)
    }

    /// Scans a single line of data.
    ///
    /// This method processes the provided line and updates the cumulative
    /// pattern matches. Rule conditions are re-evaluated with the updated
    /// pattern information.
    ///
    /// # Arguments
    ///
    /// * `line` - The line of data to scan (without line terminator)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the scan was successful, or an error if the scan
    /// timed out or encountered another issue.
    pub fn scan_line(&mut self, line: &[u8]) -> Result<(), ScanError> {
        self._scan_data(line, false)
    }

    /// Internal method that handles both line and chunk scanning.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to scan (either a line or a chunk)
    /// * `count_lines` - Whether to count lines within the data
    fn _scan_data(&mut self, data: &[u8], count_lines: bool) -> Result<(), ScanError> {
        // Set deadline for timeout (following the same logic as regular scanner)
        let timeout_secs = if let Some(timeout) = self.timeout {
            std::cmp::min(
                timeout.as_secs_f32().ceil() as u64,
                315_360_000, // One year in seconds
            )
        } else {
            315_360_000 // Default timeout like regular scanner
        };
        
        // Reset the heartbeat counter
        HEARTBEAT_COUNTER.store(0, Ordering::Relaxed);

        // Set up epoch deadline for timeout
        self.wasm_store.set_epoch_deadline(timeout_secs);
        self.wasm_store
            .epoch_deadline_callback(|_| Err(ScanError::Timeout.into()));

        // Initialize heartbeat thread for timeout handling if timeout is set
        if self.timeout.is_some() {
            INIT_HEARTBEAT.call_once(|| {
                thread::spawn(|| loop {
                    thread::sleep(Duration::from_secs(1));
                    crate::wasm::ENGINE.increment_epoch();
                    HEARTBEAT_COUNTER
                        .fetch_update(
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                            |x| Some(x + 1),
                        )
                        .unwrap();
                });
            });
        }

        // Initialize modules if this is the first scan
        {
            let ctx = self.wasm_store.data_mut();
            
    // Update the context to point to the current data
            ctx.scanned_data = data.as_ptr();
            ctx.scanned_data_len = data.len();
            
            // Store the global offset in the context so search_for_patterns can use it
            ctx.global_scan_offset = self.total_bytes_processed;
            
            ctx.deadline = HEARTBEAT_COUNTER.load(Ordering::Relaxed) + timeout_secs;

            // We only do module initialization once per scanner instance to avoid overhead
            if ctx.module_outputs.is_empty() {
                // Free all runtime objects from previous scans
                ctx.runtime_objects.clear();

                // Process imported modules
                for module_name in ctx.compiled_rules.imports() {
                    let module = modules::BUILTIN_MODULES.get(module_name)
                        .unwrap_or_else(|| panic!("module `{}` not found", module_name));

                    let root_struct_name = module.root_struct_descriptor.full_name();

                    let module_output = if let Some(output) = 
                        ctx.user_provided_module_outputs.remove(root_struct_name) {
                        Some(output)
                    } else if let Some(main_fn) = module.main_fn {
                        // For streaming scanner, we pass empty data to module initialization
                        Some(main_fn(&[], None).map_err(|err| {
                            ScanError::ModuleError {
                                module: module_name.to_string(),
                                err,
                            }
                        })?)
                    } else {
                        None
                    };

                    let generate_fields_for_enums = !cfg!(feature = "constant-folding");
                    let module_struct = Struct::from_proto_descriptor_and_msg(
                        &module.root_struct_descriptor,
                        module_output.as_deref(),
                        generate_fields_for_enums,
                    );

                    if let Some(module_output) = module_output {
                        ctx.module_outputs
                            .insert(root_struct_name.to_string(), module_output);
                    }

                    ctx.root_struct.add_field(
                        module_name,
                        TypeValue::Struct(std::rc::Rc::new(module_struct)),
                    );
                }
            }
        }

        // CRITICAL: Reset pattern_search_done to force new search
        self.pattern_search_done
            .set(self.wasm_store.as_context_mut(), Val::I32(0))
            .expect("can't set pattern_search_done");

        // Set filesize to current data length
        self.filesize
            .set(self.wasm_store.as_context_mut(), Val::I64(data.len() as i64))
            .expect("can't set filesize");

        // Call the WASM main function
        let main_fn_result = self.wasm_main_func.call(self.wasm_store.as_context_mut(), ());

        // Handle the result from the WASM main function
        match main_fn_result {
            Ok(0) => {},
            Ok(v) => panic!("WASM main returned: {}", v),
            Err(err) if err.is::<ScanError>() => {
                return Err(err.downcast::<ScanError>().unwrap());
            }
            Err(err) => panic!(
                "unexpected error while executing WASM main function: {}",
                err
            ),
        }

        // After WASM execution, move matching rules from the map to the vectors
        // This is different from the regular scanner - we keep accumulating rules
        {
            let ctx = self.wasm_store.data_mut();
            
            // Move newly matched rules from the matching_rules map to the vectors
            for rules_vec in ctx.matching_rules.values_mut() {
                for rule_id in rules_vec.drain(0..) {
                    if ctx.compiled_rules.get(rule_id).is_private {
                        if !ctx.private_matching_rules.contains(&rule_id) {
                            ctx.private_matching_rules.push(rule_id);
                        }
                    } else {
                        if !ctx.non_private_matching_rules.contains(&rule_id) {
                            ctx.non_private_matching_rules.push(rule_id);
                        }
                    }
                }
            }
        }

        // Update counters
        self.total_bytes_processed += data.len() as u64;
        
        // Count lines if requested (for chunk scanning)
        if count_lines {
            // Count newlines, but if data is non-empty and doesn't end with newline,
            // that's an additional line
            let mut line_count = data.iter().filter(|&&b| b == b'\n').count() as u64;
            if !data.is_empty() && !data.ends_with(b"\n") {
                line_count += 1;
            }
            self.line_count += line_count;
        } else {
            // For single line scanning, increment by 1
            self.line_count += 1;
        }

        Ok(())
    }

    /// Returns the current scan results.
    ///
    /// This provides access to all rules that have matched based on the
    /// cumulative pattern matches from all lines scanned so far.
    pub fn get_matches(&self) -> StreamingScanResults<'_> {
        StreamingScanResults {
            scanner: self,
        }
    }

    /// Resets the scanner to its initial state.
    ///
    /// This clears all pattern matches and resets all counters, effectively
    /// starting a new stream.
    pub fn reset(&mut self) {
        let ctx = self.wasm_store.data_mut();
        
        // Clear all match data
        ctx.pattern_matches.clear();
        ctx.matching_rules.clear();
        ctx.non_private_matching_rules.clear();
        ctx.private_matching_rules.clear();
        ctx.unconfirmed_matches.clear();
        ctx.limit_reached.clear();
        
        // Reset counters
        self.total_bytes_processed = 0;
        self.line_count = 0;
        
        // Reset global scan offset
        ctx.global_scan_offset = 0;
        
        // Clear the bitmaps in WASM memory
        let mem = ctx.main_memory.unwrap().data_mut(unsafe { ctx.wasm_store.as_mut() });
        let num_rules = ctx.compiled_rules.num_rules();
        let num_patterns = ctx.compiled_rules.num_patterns();
        
        // Clear rule matching bitmap
        let rule_bitmap_size = num_rules.div_ceil(8);
        let rule_bitmap_start = MATCHING_RULES_BITMAP_BASE as usize;
        mem[rule_bitmap_start..rule_bitmap_start + rule_bitmap_size].fill(0);
        
        // Clear pattern matching bitmap
        let pattern_bitmap_start = rule_bitmap_start + rule_bitmap_size;
        let pattern_bitmap_size = num_patterns.div_ceil(8);
        mem[pattern_bitmap_start..pattern_bitmap_start + pattern_bitmap_size].fill(0);
    }

    /// Returns the total number of bytes processed so far.
    pub fn bytes_processed(&self) -> u64 {
        self.total_bytes_processed
    }

    /// Returns the number of lines processed so far.
    pub fn lines_processed(&self) -> u64 {
        self.line_count
    }
    
    /// Debug method to access scan context for testing
    #[cfg(test)]
    pub(crate) fn debug_context(&self) -> &ScanContext {
        self.wasm_store.data()
    }
}

/// Results from a streaming scan.
pub struct StreamingScanResults<'s> {
    scanner: &'s StreamingScanner<'s>,
}

impl<'s> StreamingScanResults<'s> {
    /// Returns an iterator that yields the rules that matched during the scan.
    pub fn matching_rules(&self) -> StreamingMatchingRules<'s> {
        StreamingMatchingRules::new(self.scanner)
    }

    /// Returns a map containing all the module outputs produced during the scan.
    pub fn module_outputs(&self) -> &FxHashMap<String, Box<dyn MessageDyn>> {
        &self.scanner.wasm_store.data().module_outputs
    }
}

/// Iterator that yields the rules that matched in a streaming scan.
pub struct StreamingMatchingRules<'s> {
    scanner: &'s StreamingScanner<'s>,
    rule_iter: std::slice::Iter<'s, RuleId>,
}

impl<'s> StreamingMatchingRules<'s> {
    fn new(scanner: &'s StreamingScanner<'s>) -> Self {
        let ctx = scanner.wasm_store.data();
        Self { 
            scanner, 
            rule_iter: ctx.non_private_matching_rules.iter()
        }
    }
}

impl<'s> Iterator for StreamingMatchingRules<'s> {
    type Item = Rule<'s, 's>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(rule_id) = self.rule_iter.next() {
            let ctx = self.scanner.wasm_store.data();
            let rules = ctx.compiled_rules;
            let rule_info = rules.get(*rule_id);
            Some(Rule {
                ctx: Some(ctx),
                data: None, // Streaming scanner doesn't have access to the full data
                rule_info,
                rules,
            })
        } else {
            None
        }
    }
}