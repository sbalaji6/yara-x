use anyhow::Result;
use clap::Parser;
use std::fs::File;
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

    #[arg(short = 'i', long = "input", required = true, num_args = 1..)]
    input_files: Vec<PathBuf>,

    #[arg(short = 'c', long = "chunk-size", required = true)]
    chunk_size: usize,

    #[arg(long, help = "Use a more relaxed syntax check while parsing regular expressions")]
    relaxed_re_syntax: bool,
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
    
    // Create scanner
    let mut scanner = MultiStreamScanner::new(&rules);
    
    // Open files
    let mut readers = Vec::new();
    let mut uuids = Vec::new();
    let mut active_files = Vec::new();  // Track which files are still active
    for (i, path) in args.input_files.iter().enumerate() {
        let file = File::open(path)?;
        readers.push(BufReader::new(file));
        uuids.push(Uuid::new_v4());
        active_files.push(i);  // Initially all files are active
    }
    
    println!("Processing {} files with chunk size {}", args.input_files.len(), args.chunk_size);
    
    let start = Instant::now();
    let mut round = 1;
    
    // Track previous match counts for each stream
    let mut prev_matches: Vec<usize> = vec![0; args.input_files.len()];
    
    // Process in round-robin
    while !active_files.is_empty() {
        let mut processed = 0;
        let mut exhausted_indices = Vec::new();
        
        for (idx, &file_idx) in active_files.iter().enumerate() {
            let mut chunk = Vec::new();
            let mut lines = 0;
            
            for _ in 0..args.chunk_size {
                let mut line = String::new();
                if readers[file_idx].read_line(&mut line)? == 0 {
                    break;
                }
                chunk.extend_from_slice(line.as_bytes());
                lines += 1;
            }
            
            if !chunk.is_empty() {
                let chunk_start = Instant::now();
                scanner.scan_chunk(&uuids[file_idx], &chunk)?;
                let chunk_elapsed = chunk_start.elapsed();
                
                // Get current matches for this stream
                let results = scanner.get_matches(&uuids[file_idx]).unwrap();
                let current_matches = results.matching_rules().count();
                let new_matches = current_matches - prev_matches[file_idx];
                prev_matches[file_idx] = current_matches;
                
                println!("Round {} - File {} ({}): {} bytes in {:?}, {} new matches (total: {})", 
                    round, file_idx, args.input_files[file_idx].display(), 
                    chunk.len(), chunk_elapsed, new_matches, current_matches);
                
                // Show all currently matching rules
                if current_matches > 0 {
                    println!("        Currently matching rules:");
                    for rule in results.matching_rules() {
                        println!("          - {}", rule.identifier());
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
                println!("Round {} - File {} ({}) exhausted", round, file_idx, args.input_files[file_idx].display());
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
    
    println!("\nCompleted in {:?}", start.elapsed());
    
    // Print final match summary
    println!("\nFinal match summary:");
    for i in 0..uuids.len() {
        let results = scanner.get_matches(&uuids[i]).unwrap();
        let total_matches = results.matching_rules().count();
        println!("  File {}: {} total rules matched", i, total_matches);
    }
    
    // Print detailed memory statistics
    println!("\nFinal memory statistics:");
    println!("{}", scanner.memory_stats());
    
    Ok(())
}