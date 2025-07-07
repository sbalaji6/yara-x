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
    #[arg(short = 'r', long = "rules", required = true)]
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
    let mut compiler = Compiler::new();
    compiler.relaxed_re_syntax(args.relaxed_re_syntax);
    for yara_file in &args.yara_files {
        let source = std::fs::read_to_string(yara_file)?;
        compiler.add_source(source.as_str())?;
    }
    let rules = compiler.build();
    
    // Create scanner
    let mut scanner = MultiStreamScanner::new(&rules);
    
    // Open files
    let mut readers = Vec::new();
    let mut uuids = Vec::new();
    for path in &args.input_files {
        let file = File::open(path)?;
        readers.push(BufReader::new(file));
        uuids.push(Uuid::new_v4());
    }
    
    println!("Processing {} files with chunk size {}", args.input_files.len(), args.chunk_size);
    
    let start = Instant::now();
    let mut active = args.input_files.len();
    let mut round = 1;
    
    // Track previous match counts for each stream
    let mut prev_matches: Vec<usize> = vec![0; args.input_files.len()];
    
    // Process in round-robin
    while active > 0 {
        let mut processed = 0;
        
        for i in 0..readers.len() {
            let mut chunk = Vec::new();
            let mut lines = 0;
            
            for _ in 0..args.chunk_size {
                let mut line = String::new();
                if readers[i].read_line(&mut line)? == 0 {
                    break;
                }
                chunk.extend_from_slice(line.as_bytes());
                lines += 1;
            }
            
            if !chunk.is_empty() {
                let chunk_start = Instant::now();
                scanner.scan_chunk(&uuids[i], &chunk)?;
                let chunk_elapsed = chunk_start.elapsed();
                
                // Get current matches for this stream
                let results = scanner.get_matches(&uuids[i]).unwrap();
                let current_matches = results.matching_rules().count();
                let new_matches = current_matches - prev_matches[i];
                prev_matches[i] = current_matches;
                
                println!("Round {} - File {}: {} bytes in {:?}, {} new matches (total: {})", 
                    round, i, chunk.len(), chunk_elapsed, new_matches, current_matches);
                
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
                active -= 1;
            }
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