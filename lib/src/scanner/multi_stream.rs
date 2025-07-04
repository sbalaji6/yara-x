use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::atomic::Ordering;
use std::sync::Once;
use std::thread;
use std::time::Duration;

use indexmap::IndexMap;
use protobuf::MessageDyn;
use rustc_hash::{FxHashMap, FxHashSet};
use uuid::Uuid;
use wasmtime::{AsContext, AsContextMut, Global, Store, TypedFunc, Val};

use crate::compiler::{NamespaceId, RuleId, Rules, SubPatternId, PatternId};
use crate::models::Rule;
use crate::modules;
use crate::scanner::context::ScanContext;
use crate::scanner::matches::{PatternMatches, UnconfirmedMatch};
use crate::scanner::{ScanError, HEARTBEAT_COUNTER};
use crate::types::{Struct, TypeValue};
use crate::variables::VariableError;
use crate::wasm::{self, MATCHING_RULES_BITMAP_BASE};

static INIT_HEARTBEAT: Once = Once::new();

/// Helper struct to access WASM memory bitmaps
struct StreamBitmaps {
    rule_bitmap: Vec<u8>,
    pattern_bitmap: Vec<u8>,
}

/// Context for a single stream, containing all mutable state
struct StreamContext {
    /// Pattern matches accumulated for this stream
    pattern_matches: PatternMatches,
    /// Non-private rules that have matched
    non_private_matching_rules: Vec<RuleId>,
    /// Private rules that have matched
    private_matching_rules: Vec<RuleId>,
    /// Temporary storage for newly matched rules (cleared after each scan)
    matching_rules: IndexMap<NamespaceId, Vec<RuleId>>,
    /// Unconfirmed matches for chained patterns
    unconfirmed_matches: FxHashMap<SubPatternId, Vec<UnconfirmedMatch>>,
    /// Patterns that have reached their match limit
    limit_reached: FxHashSet<PatternId>,
    /// Total bytes processed in this stream
    total_bytes_processed: u64,
    /// Number of lines processed in this stream
    line_count: u64,
    /// Module outputs for this stream
    module_outputs: FxHashMap<String, Box<dyn MessageDyn>>,
    /// Global offset for pattern matching
    global_scan_offset: u64,
    /// WASM memory bitmaps for rules and patterns
    rule_bitmap: Vec<u8>,
    pattern_bitmap: Vec<u8>,
}

impl StreamContext {
    fn new(num_rules: usize, num_patterns: usize) -> Self {
        Self {
            pattern_matches: PatternMatches::new(),
            non_private_matching_rules: Vec::new(),
            private_matching_rules: Vec::new(),
            matching_rules: IndexMap::new(),
            unconfirmed_matches: FxHashMap::default(),
            limit_reached: FxHashSet::default(),
            total_bytes_processed: 0,
            line_count: 0,
            module_outputs: FxHashMap::default(),
            global_scan_offset: 0,
            rule_bitmap: vec![0; num_rules.div_ceil(8)],
            pattern_bitmap: vec![0; num_patterns.div_ceil(8)],
        }
    }

    /// Save the current scanner context to this stream context
    fn save_from_scanner(&mut self, ctx: &ScanContext, bitmaps: &StreamBitmaps) {
        // Clone pattern matches to preserve scanner state for continued accumulation
        self.pattern_matches = ctx.pattern_matches.clone();
        
        // Clone rule matches
        self.non_private_matching_rules = ctx.non_private_matching_rules.clone();
        self.private_matching_rules = ctx.private_matching_rules.clone();
        self.matching_rules = ctx.matching_rules.clone();
        
        // Clone other state
        self.unconfirmed_matches = ctx.unconfirmed_matches.clone();
        self.limit_reached = ctx.limit_reached.clone();
        self.global_scan_offset = ctx.global_scan_offset;
        
        // Save the WASM bitmaps
        self.rule_bitmap.copy_from_slice(&bitmaps.rule_bitmap);
        self.pattern_bitmap.copy_from_slice(&bitmaps.pattern_bitmap);
        
        // Note: module_outputs are not cloned as they're managed separately
    }

    /// Restore this stream context to the scanner context
    fn restore_to_scanner(&self, ctx: &mut ScanContext, bitmaps: &mut StreamBitmaps) {
        // Clone pattern matches from stream to scanner
        ctx.pattern_matches = self.pattern_matches.clone();
        
        // Restore rule matches
        ctx.non_private_matching_rules = self.non_private_matching_rules.clone();
        ctx.private_matching_rules = self.private_matching_rules.clone();
        ctx.matching_rules = self.matching_rules.clone();
        
        // Clone other state
        ctx.unconfirmed_matches = self.unconfirmed_matches.clone();
        ctx.limit_reached = self.limit_reached.clone();
        ctx.global_scan_offset = self.global_scan_offset;
        
        // Restore the WASM bitmaps
        bitmaps.rule_bitmap.copy_from_slice(&self.rule_bitmap);
        bitmaps.pattern_bitmap.copy_from_slice(&self.pattern_bitmap);
    }
}

/// A multi-stream scanner that can process multiple independent streams concurrently.
///
/// Unlike the regular [`StreamingScanner`], which maintains state for a single stream,
/// `MultiStreamScanner` can handle multiple streams identified by UUID, switching
/// between them efficiently while sharing WASM resources.
///
/// # Example
///
/// ```no_run
/// # use yara_x;
/// # use uuid::Uuid;
/// # let rules = yara_x::compile(r#"
/// #     rule test {
/// #         strings:
/// #             $a = "pattern1"
/// #             $b = "pattern2"
/// #         condition:
/// #             $a and $b
/// #     }
/// # "#).unwrap();
/// let mut scanner = yara_x::MultiStreamScanner::new(&rules);
/// 
/// // Create two different streams
/// let stream1 = Uuid::new_v4();
/// let stream2 = Uuid::new_v4();
/// 
/// // Scan data in stream 1
/// scanner.scan_chunk(&stream1, b"data with pattern1\n").unwrap();
/// 
/// // Switch to stream 2
/// scanner.scan_chunk(&stream2, b"different data\n").unwrap();
/// 
/// // Back to stream 1 - state is preserved
/// scanner.scan_chunk(&stream1, b"more data with pattern2\n").unwrap();
/// 
/// // Get results for stream 1
/// let results = scanner.get_matches(&stream1).unwrap();
/// assert_eq!(results.matching_rules().count(), 1); // Both patterns found
/// ```
pub struct MultiStreamScanner<'r> {
    rules: &'r Rules,
    wasm_store: Pin<Box<Store<ScanContext<'static>>>>,
    wasm_main_func: TypedFunc<(), i32>,
    wasm_instance: wasmtime::Instance,
    filesize: Global,
    pattern_search_done: Global,
    /// Map of stream contexts indexed by UUID
    contexts: HashMap<Uuid, StreamContext>,
    /// Currently active stream
    active_stream: Option<Uuid>,
    /// Timeout for scan operations
    timeout: Option<Duration>,
    /// Flag to track if modules have been initialized
    modules_initialized: bool,
}

impl<'r> MultiStreamScanner<'r> {
    /// Creates a new multi-stream scanner for the given [`Rules`].
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
            contexts: HashMap::new(),
            active_stream: None,
            timeout: None,
            modules_initialized: false,
        }
    }

    /// Sets a timeout for scan operations.
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the value of a global variable for all streams.
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

    /// Scans a chunk of data for the specified stream.
    pub fn scan_chunk(&mut self, stream_id: &Uuid, chunk: &[u8]) -> Result<(), ScanError> {
        self._scan_data(stream_id, chunk, true)
    }

    /// Scans a single line of data for the specified stream.
    pub fn scan_line(&mut self, stream_id: &Uuid, line: &[u8]) -> Result<(), ScanError> {
        self._scan_data(stream_id, line, false)
    }

    /// Internal method that handles both line and chunk scanning.
    fn _scan_data(&mut self, stream_id: &Uuid, data: &[u8], count_lines: bool) -> Result<(), ScanError> {
        // Switch to the requested stream
        self.switch_to_stream(stream_id)?;

        // Set deadline for timeout
        let timeout_secs = if let Some(timeout) = self.timeout {
            std::cmp::min(
                timeout.as_secs_f32().ceil() as u64,
                315_360_000, // One year in seconds
            )
        } else {
            315_360_000 // Default timeout
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
        if !self.modules_initialized {
            self.initialize_modules()?;
            self.modules_initialized = true;
        }

        // Get the current stream context to update counters
        let stream_context = self.contexts.get_mut(stream_id).unwrap();
        
        // Update the scanner context
        {
            let ctx = self.wasm_store.data_mut();
            
            // Update the context to point to the current data
            ctx.scanned_data = data.as_ptr();
            ctx.scanned_data_len = data.len();
            
            // Use the stream's global offset
            ctx.global_scan_offset = stream_context.total_bytes_processed;
            
            ctx.deadline = HEARTBEAT_COUNTER.load(Ordering::Relaxed) + timeout_secs;
            
            // Clear the temporary matching_rules map before each scan
            ctx.matching_rules.clear();
        }

        // Reset pattern_search_done to force new search
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
            
            // Pattern matches and rules have been updated
        }

        // Save the updated scanner state back to the stream context first
        let bitmaps = self.read_bitmaps_from_wasm();
        let stream_context = self.contexts.get_mut(stream_id).unwrap();
        stream_context.save_from_scanner(self.wasm_store.data(), &bitmaps);
        
        // Then update stream counters
        stream_context.total_bytes_processed += data.len() as u64;
        stream_context.global_scan_offset = stream_context.total_bytes_processed;
        
        // Count lines if requested (for chunk scanning)
        if count_lines {
            // Count newlines, but if data is non-empty and doesn't end with newline,
            // that's an additional line
            let mut line_count = data.iter().filter(|&&b| b == b'\n').count() as u64;
            if !data.is_empty() && !data.ends_with(b"\n") {
                line_count += 1;
            }
            stream_context.line_count += line_count;
        } else {
            // For single line scanning, increment by 1
            stream_context.line_count += 1;
        }

        Ok(())
    }

    /// Switch to a different stream, saving current state if needed
    fn switch_to_stream(&mut self, stream_id: &Uuid) -> Result<(), ScanError> {
        // If already on this stream, nothing to do
        if self.active_stream == Some(*stream_id) {
            return Ok(());
        }

        // Save current stream state if there is one
        if let Some(current_id) = self.active_stream {
            let bitmaps = self.read_bitmaps_from_wasm();
            if let Some(current_context) = self.contexts.get_mut(&current_id) {
                current_context.save_from_scanner(self.wasm_store.data(), &bitmaps);
            }
        }

        // Get or create the stream context
        if let Some(stream_context) = self.contexts.get(stream_id) {
            // Restore existing context
            let mut bitmaps = StreamBitmaps {
                rule_bitmap: vec![0; stream_context.rule_bitmap.len()],
                pattern_bitmap: vec![0; stream_context.pattern_bitmap.len()],
            };
            stream_context.restore_to_scanner(self.wasm_store.data_mut(), &mut bitmaps);
            self.write_bitmaps_to_wasm(&bitmaps);
        } else {
            // Create new context for this stream
            let num_rules = self.rules.num_rules();
            let num_patterns = self.rules.num_patterns();
            let new_context = StreamContext::new(num_rules, num_patterns);
            let mut bitmaps = StreamBitmaps {
                rule_bitmap: vec![0; num_rules.div_ceil(8)],
                pattern_bitmap: vec![0; num_patterns.div_ceil(8)],
            };
            new_context.restore_to_scanner(self.wasm_store.data_mut(), &mut bitmaps);
            self.write_bitmaps_to_wasm(&bitmaps);
            self.contexts.insert(*stream_id, new_context);
        }

        self.active_stream = Some(*stream_id);
        Ok(())
    }

    /// Initialize modules (called once on first scan)
    fn initialize_modules(&mut self) -> Result<(), ScanError> {
        let ctx = self.wasm_store.data_mut();
        
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

        Ok(())
    }

    /// Read bitmaps from WASM memory
    fn read_bitmaps_from_wasm(&self) -> StreamBitmaps {
        let ctx = self.wasm_store.data();
        let mem = ctx.main_memory.unwrap().data(unsafe { ctx.wasm_store.as_ref() });
        let num_rules = ctx.compiled_rules.num_rules();
        let num_patterns = ctx.compiled_rules.num_patterns();
        
        let rule_bitmap_size = num_rules.div_ceil(8);
        let rule_bitmap_start = MATCHING_RULES_BITMAP_BASE as usize;
        
        let pattern_bitmap_start = rule_bitmap_start + rule_bitmap_size;
        let pattern_bitmap_size = num_patterns.div_ceil(8);
        
        StreamBitmaps {
            rule_bitmap: mem[rule_bitmap_start..rule_bitmap_start + rule_bitmap_size].to_vec(),
            pattern_bitmap: mem[pattern_bitmap_start..pattern_bitmap_start + pattern_bitmap_size].to_vec(),
        }
    }
    
    /// Write bitmaps to WASM memory
    fn write_bitmaps_to_wasm(&mut self, bitmaps: &StreamBitmaps) {
        let ctx = self.wasm_store.data_mut();
        let mem = ctx.main_memory.unwrap().data_mut(unsafe { ctx.wasm_store.as_mut() });
        let num_rules = ctx.compiled_rules.num_rules();
        
        let rule_bitmap_size = num_rules.div_ceil(8);
        let rule_bitmap_start = MATCHING_RULES_BITMAP_BASE as usize;
        
        let pattern_bitmap_start = rule_bitmap_start + rule_bitmap_size;
        
        mem[rule_bitmap_start..rule_bitmap_start + rule_bitmap_size]
            .copy_from_slice(&bitmaps.rule_bitmap);
        mem[pattern_bitmap_start..pattern_bitmap_start + bitmaps.pattern_bitmap.len()]
            .copy_from_slice(&bitmaps.pattern_bitmap);
    }

    /// Returns the current scan results for a specific stream.
    pub fn get_matches(&self, stream_id: &Uuid) -> Option<MultiStreamScanResults<'_>> {
        // Check if the stream exists
        if !self.contexts.contains_key(stream_id) {
            return None;
        }

        Some(MultiStreamScanResults {
            scanner: self,
            stream_id: *stream_id,
        })
    }

    /// Closes a stream and returns its final results.
    pub fn close_stream(&mut self, stream_id: &Uuid) -> Option<FinalStreamResults> {
        // If this is the active stream, save its state first
        if self.active_stream == Some(*stream_id) {
            let bitmaps = self.read_bitmaps_from_wasm();
            if let Some(context) = self.contexts.get_mut(stream_id) {
                context.save_from_scanner(self.wasm_store.data(), &bitmaps);
            }
            self.active_stream = None;
        }

        // Remove and return the context
        self.contexts.remove(stream_id).map(|context| {
            FinalStreamResults {
                non_private_matching_rules: context.non_private_matching_rules,
                bytes_processed: context.total_bytes_processed,
                lines_processed: context.line_count,
            }
        })
    }

    /// Returns a list of active stream IDs.
    pub fn active_streams(&self) -> Vec<Uuid> {
        self.contexts.keys().copied().collect()
    }

    /// Resets a specific stream to its initial state.
    pub fn reset_stream(&mut self, stream_id: &Uuid) -> Result<(), ScanError> {
        if let Some(context) = self.contexts.get_mut(stream_id) {
            let num_rules = self.rules.num_rules();
            let num_patterns = self.rules.num_patterns();
            *context = StreamContext::new(num_rules, num_patterns);
            
            // If this is the active stream, clear the scanner state too
            if self.active_stream == Some(*stream_id) {
                let mut bitmaps = StreamBitmaps {
                    rule_bitmap: vec![0; num_rules.div_ceil(8)],
                    pattern_bitmap: vec![0; num_patterns.div_ceil(8)],
                };
                context.restore_to_scanner(self.wasm_store.data_mut(), &mut bitmaps);
                self.write_bitmaps_to_wasm(&bitmaps);
            }
        }
        Ok(())
    }

    /// Returns the number of bytes processed for a specific stream.
    pub fn bytes_processed(&self, stream_id: &Uuid) -> Option<u64> {
        if self.active_stream == Some(*stream_id) {
            // If this is the active stream, get the current count
            self.contexts.get(stream_id).map(|ctx| ctx.total_bytes_processed)
        } else {
            self.contexts.get(stream_id).map(|ctx| ctx.total_bytes_processed)
        }
    }

    /// Returns the number of lines processed for a specific stream.
    pub fn lines_processed(&self, stream_id: &Uuid) -> Option<u64> {
        if self.active_stream == Some(*stream_id) {
            // If this is the active stream, get the current count
            self.contexts.get(stream_id).map(|ctx| ctx.line_count)
        } else {
            self.contexts.get(stream_id).map(|ctx| ctx.line_count)
        }
    }

    /// Estimates the memory usage of all cached stream contexts in bytes.
    pub fn contexts_memory_usage(&self) -> usize {
        let mut total = 0;
        
        // Base HashMap overhead (approximately)
        total += std::mem::size_of::<HashMap<Uuid, StreamContext>>();
        
        for (uuid, context) in &self.contexts {
            // UUID size
            total += std::mem::size_of::<Uuid>();
            
            // StreamContext struct itself
            total += std::mem::size_of::<StreamContext>();
            
            // Dynamic allocations within StreamContext:
            
            // Vectors of RuleIds
            total += context.non_private_matching_rules.capacity() * std::mem::size_of::<RuleId>();
            total += context.private_matching_rules.capacity() * std::mem::size_of::<RuleId>();
            
            // Bitmaps
            total += context.rule_bitmap.capacity();
            total += context.pattern_bitmap.capacity();
            
            // IndexMap for matching_rules (approximate)
            total += context.matching_rules.capacity() * 
                (std::mem::size_of::<NamespaceId>() + std::mem::size_of::<Vec<RuleId>>());
            for (_, rules) in &context.matching_rules {
                total += rules.capacity() * std::mem::size_of::<RuleId>();
            }
            
            // FxHashSet for limit_reached
            total += context.limit_reached.capacity() * std::mem::size_of::<PatternId>();
            
            // Note: pattern_matches, unconfirmed_matches, and module_outputs 
            // would need their own size calculation methods to be accurate
        }
        
        total
    }

    /// Returns detailed memory statistics for debugging.
    pub fn memory_stats(&self) -> String {
        let mut stats = String::new();
        stats.push_str(&format!("Total streams cached: {}\n", self.contexts.len()));
        stats.push_str(&format!("Total contexts memory (estimate): {} bytes\n", self.contexts_memory_usage()));
        
        for (i, (uuid, context)) in self.contexts.iter().enumerate() {
            stats.push_str(&format!("\nStream {}: {}\n", i, uuid));
            stats.push_str(&format!("  - Bytes processed: {}\n", context.total_bytes_processed));
            stats.push_str(&format!("  - Lines processed: {}\n", context.line_count));
            stats.push_str(&format!("  - Non-private rules matched: {}\n", context.non_private_matching_rules.len()));
            stats.push_str(&format!("  - Private rules matched: {}\n", context.private_matching_rules.len()));
            stats.push_str(&format!("  - Rule bitmap size: {} bytes\n", context.rule_bitmap.len()));
            stats.push_str(&format!("  - Pattern bitmap size: {} bytes\n", context.pattern_bitmap.len()));
        }
        
        stats
    }
}

/// Results from a multi-stream scan for a specific stream.
pub struct MultiStreamScanResults<'s> {
    scanner: &'s MultiStreamScanner<'s>,
    stream_id: Uuid,
}

impl<'s> MultiStreamScanResults<'s> {
    /// Returns an iterator that yields the rules that matched during the scan.
    pub fn matching_rules(&self) -> MultiStreamMatchingRules<'s> {
        MultiStreamMatchingRules::new(self.scanner, self.stream_id)
    }

    /// Returns a map containing all the module outputs produced during the scan.
    pub fn module_outputs(&self) -> Option<&FxHashMap<String, Box<dyn MessageDyn>>> {
        // For now, we return the module outputs from the scanner context
        // In a real implementation, we might want to store these per stream
        if self.scanner.active_stream == Some(self.stream_id) {
            Some(&self.scanner.wasm_store.data().module_outputs)
        } else {
            None
        }
    }
}

/// Final results when closing a stream
pub struct FinalStreamResults {
    /// Non-private rules that matched
    pub non_private_matching_rules: Vec<RuleId>,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Total lines processed
    pub lines_processed: u64,
}

/// Iterator that yields the rules that matched in a multi-stream scan.
pub struct MultiStreamMatchingRules<'s> {
    scanner: &'s MultiStreamScanner<'s>,
    stream_id: Uuid,
    rule_iter: std::vec::IntoIter<RuleId>,
}

impl<'s> MultiStreamMatchingRules<'s> {
    fn new(scanner: &'s MultiStreamScanner<'s>, stream_id: Uuid) -> Self {
        // Get the matching rules for this stream
        let rules = if scanner.active_stream == Some(stream_id) {
            // If this is the active stream, get rules from the scanner context
            scanner.wasm_store.data().non_private_matching_rules.clone()
        } else {
            // Otherwise get from the saved context
            scanner.contexts.get(&stream_id)
                .map(|ctx| ctx.non_private_matching_rules.clone())
                .unwrap_or_default()
        };
        
        Self { 
            scanner, 
            stream_id,
            rule_iter: rules.into_iter(),
        }
    }
}

impl<'s> Iterator for MultiStreamMatchingRules<'s> {
    type Item = Rule<'s, 's>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(rule_id) = self.rule_iter.next() {
            let rules = self.scanner.rules;
            let rule_info = rules.get(rule_id);
            
            // We need to provide a context, but for multi-stream scanner
            // we can't easily provide the correct context without switching streams
            // For now, we'll return rules without context access
            Some(Rule {
                ctx: None,
                data: None,
                rule_info,
                rules,
            })
        } else {
            None
        }
    }
}