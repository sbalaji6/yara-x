use anyhow::Result;
use clap::Parser;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;
use yara_x::{Compiler, MultiStreamScanner};

#[derive(Parser, Debug)]
#[command(name = "multi-input-stream-perf")]
struct Args {
    #[arg(short = 'r', long = "rules", required = true, num_args = 1..)]
    yara_files: Vec<PathBuf>,

    #[arg(short = 'i', long = "input", num_args = 1.., conflicts_with = "directory")]
    input_files: Vec<String>,

    #[arg(short = 'd', long = "directory", conflicts_with = "input_files")]
    directory: Option<PathBuf>,

    #[arg(short = 'p', long = "parallel", default_value = "10", help = "Number of files to process in parallel")]
    parallel_count: usize,

    #[arg(short = 'c', long = "chunk-size", required = true)]
    chunk_size: usize,

    #[arg(long, help = "Use a more relaxed syntax check while parsing regular expressions")]
    relaxed_re_syntax: bool,
}

fn scan_directory_recursive(dir: &PathBuf) -> Result<Vec<String>> {
    let mut files = Vec::new();
    
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            files.push(path.to_string_lossy().to_string());
        } else if path.is_dir() {
            // Recursively scan subdirectories
            let sub_files = scan_directory_recursive(&path)?;
            files.extend(sub_files);
        }
    }
    
    Ok(files)
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Load rules
    println!("Loading {} YARA file(s):", args.yara_files.len());
    for yara_file in &args.yara_files {
        println!("  - {}", yara_file.display());
    }
    println!();
    
    let mut compiler = Compiler::new();
    compiler.relaxed_re_syntax(args.relaxed_re_syntax);
    for yara_file in &args.yara_files {
        let source = std::fs::read_to_string(yara_file)?;
        compiler.add_source(source.as_str())?;
    }
    let rules = compiler.build();
    
    println!("Compiled {} YARA rules", rules.iter().len());
    println!();
    
    // Get all input files
    let all_input_files = if let Some(dir) = args.directory {
        // Scan directory recursively for files
        println!("Scanning directory recursively: {}", dir.display());
        let files = scan_directory_recursive(&dir)?;
        println!("Found {} files in directory tree", files.len());
        files
    } else {
        // Use provided input files
        args.input_files.clone()
    };
    
    if all_input_files.is_empty() {
        println!("No input files found");
        return Ok(());
    }
    
    // Process files in batches
    let total_files = all_input_files.len();
    let mut batch_start = 0;
    let mut batch_num = 1;
    
    // Create scanner once for all batches
    let mut scanner = MultiStreamScanner::new(&rules);
    
    while batch_start < total_files {
        let batch_end = std::cmp::min(batch_start + args.parallel_count, total_files);
        let batch_files = &all_input_files[batch_start..batch_end];
        
        println!("\n===== Processing batch {} ({} files) =====", batch_num, batch_files.len());
        println!("Files {} to {} of {}", batch_start + 1, batch_end, total_files);
        
        // Parse input files and UUIDs
        let mut readers = Vec::new();
        let mut uuids = Vec::new();
        let mut file_paths = Vec::new();
        let mut active_files = Vec::new();  // Track which files are still active
        
        for (i, input) in batch_files.iter().enumerate() {
        let (path, uuid) = if let Some(colon_pos) = input.rfind(':') {
            // Check if what follows the colon looks like a UUID
            let potential_uuid = &input[colon_pos + 1..];
            if let Ok(parsed_uuid) = Uuid::parse_str(potential_uuid) {
                // Valid UUID found
                let path = PathBuf::from(&input[..colon_pos]);
                (path, parsed_uuid)
            } else {
                // Not a valid UUID, treat the whole thing as a path
                (PathBuf::from(input), Uuid::new_v4())
            }
        } else {
            // No colon found, treat as path and generate UUID
            (PathBuf::from(input), Uuid::new_v4())
        };
        
        println!("Processing file: {} with UUID: {}", path.display(), uuid);
        
        let file = File::open(&path)?;
        readers.push(BufReader::new(file));
        uuids.push(uuid);
        file_paths.push(path);
        active_files.push(i);
        }
        
        println!("\nProcessing {} files with chunk size {}", file_paths.len(), args.chunk_size);
        
        let batch_start_time = Instant::now();
        let mut round = 1;
        
        // Track previous match counts for each stream
        let mut prev_matches: Vec<usize> = vec![0; file_paths.len()];
        
        // Process in round-robin
        while !active_files.is_empty() {
        let mut processed = 0;
        let mut exhausted_indices = Vec::new();
        
        for (idx, &file_idx) in active_files.iter().enumerate() {
            let mut chunk = Vec::new();
            
            for _ in 0..args.chunk_size {
                let mut line = String::new();
                if readers[file_idx].read_line(&mut line)? == 0 {
                    break;
                }
                chunk.extend_from_slice(line.as_bytes());
            }
            
            if !chunk.is_empty() {
                let chunk_start = Instant::now();
                scanner.scan_chunk(&uuids[file_idx], &chunk)?;
                let chunk_elapsed = chunk_start.elapsed();
                
                // Get current matches for this stream
                let (current_matches, new_matches) = if let Some(results) = scanner.get_matches(&uuids[file_idx]) {
                    let count = results.matching_rules().count();
                    let new = count - prev_matches[file_idx];
                    prev_matches[file_idx] = count;
                    (count, new)
                } else {
                    // No matches yet for this stream
                    (0, 0)
                };
                
                println!("Round {} - File {} ({}): {} bytes in {:?}, {} new matches (total: {})", 
                    round, file_idx, file_paths[file_idx].display(), 
                    chunk.len(), chunk_elapsed, new_matches, current_matches);
                
                // Show all currently matching rules
                if current_matches > 0 {
                    if let Some(results) = scanner.get_matches(&uuids[file_idx]) {
                        println!("        Currently matching rules:");
                        for rule in results.matching_rules() {
                            println!("          - {}", rule.identifier());
                        }
                    }
                }
                
                // Print memory usage after each chunk
                println!("        Cache memory usage: {} KB ({} active streams)", 
                    scanner.contexts_memory_usage() / 1024, 
                    scanner.active_streams().len());
                
                processed += 1;
            } else {
                // Mark this file index for removal
                exhausted_indices.push(idx);
                println!("Round {} - File {} ({}) exhausted", round, file_idx, file_paths[file_idx].display());
            }
        }
        
        // Remove exhausted files from active list (in reverse order to maintain indices)
        for &idx in exhausted_indices.iter().rev() {
            active_files.remove(idx);
        }
        
        if processed > 0 {
            round += 1;
        }
        }
        
        println!("\nBatch {} completed in {:?}", batch_num, batch_start_time.elapsed());
        
        // Print final match summary for this batch
        println!("\nBatch {} match summary:", batch_num);
        for i in 0..uuids.len() {
            let total_matches = if let Some(results) = scanner.get_matches(&uuids[i]) {
                results.matching_rules().count()
            } else {
                0
            };
            println!("  File {} (UUID: {}): {} total rules matched", i, uuids[i], total_matches);
        }
        
        // Print detailed memory statistics for this batch
        println!("\nBatch {} memory statistics:", batch_num);
        println!("{}", scanner.memory_stats());
        
        // Move to next batch
        batch_start = batch_end;
        batch_num += 1;
    }
    
    println!("\n===== All batches completed =====");
    println!("Total files processed: {}", total_files);
    
    // Calculate total lines processed across all streams
    let mut total_lines_processed = 0u64;
    for stream_id in scanner.active_streams() {
        if let Some(lines) = scanner.lines_processed(&stream_id) {
            total_lines_processed += lines;
        }
    }
    println!("Total lines processed: {}", total_lines_processed);
    
    // Print final memory statistics
    println!("\nFinal memory statistics:");
    println!("{}", scanner.memory_stats());
    println!("Total memory consumed for cache: {} bytes", scanner.contexts_memory_usage());
    
    Ok(())
}