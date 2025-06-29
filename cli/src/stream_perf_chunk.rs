use anyhow::{anyhow, Result};
use clap::Parser;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;
use yara_x::{Compiler, Rules, StreamingScanner};

#[derive(Parser, Debug)]
#[command(
    name = "stream-perf-chunk",
    about = "YARA-X streaming scanner performance test using scan_chunk",
    long_about = "Tests streaming scanner performance with scan_chunk method for chunk-based processing"
)]
struct Args {
    #[arg(
        short = 'r',
        long = "rules",
        help = "YARA rule files to load",
        required = true,
        num_args = 1..
    )]
    yara_files: Vec<PathBuf>,

    #[arg(
        short = 'i',
        long = "input",
        help = "Input file to scan",
        required = true
    )]
    input_file: PathBuf,

    #[arg(
        short = 'c',
        long = "chunk-size",
        help = "Number of lines to process per chunk",
        required = true
    )]
    chunk_size: usize,
}

fn load_rules(yara_files: &[PathBuf]) -> Result<Rules> {
    let mut compiler = Compiler::new();
    
    for yara_file in yara_files {
        println!("Loading YARA rules from: {}", yara_file.display());
        let source = std::fs::read_to_string(yara_file)?;
        compiler
            .add_source(source.as_str())
            .map_err(|e| anyhow!("Failed to compile {}: {}", yara_file.display(), e))?;
    }
    
    Ok(compiler.build())
}

fn read_file_lines(file_path: &PathBuf) -> Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let lines: Result<Vec<String>, _> = reader.lines().collect();
    Ok(lines?)
}

fn create_chunk_from_lines(lines: &[String]) -> Vec<u8> {
    let mut chunk = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        chunk.extend_from_slice(line.as_bytes());
        // Add newline after each line except the last one
        if i < lines.len() - 1 {
            chunk.push(b'\n');
        }
    }
    chunk
}

fn test1_cumulative_chunk(rules: &Rules, lines: &[String], chunk_size: usize) -> Result<()> {
    println!("\n=== Test 1: Cumulative Input Testing with scan_chunk ===");
    println!("Processing input cumulatively with chunk size: {}", chunk_size);
    
    let mut current_size = chunk_size;
    let mut iteration = 1;
    let mut total_time = std::time::Duration::ZERO;
    
    while current_size <= lines.len() {
        let mut scanner = StreamingScanner::new(rules);
        let start = Instant::now();
        
        // Create a single chunk from all lines up to current_size
        let chunk_lines = &lines[0..current_size];
        let chunk = create_chunk_from_lines(chunk_lines);
        scanner.scan_chunk(&chunk)?;
        
        let elapsed = start.elapsed();
        total_time += elapsed;
        let results = scanner.get_matches();
        let match_count = results.matching_rules().count();
        
        println!(
            "Iteration {}: Processed {} lines ({} bytes) in {:?}, {} matches found",
            iteration, current_size, chunk.len(), elapsed, match_count
        );
        
        for rule in results.matching_rules() {
            println!("  - Matched rule: {}", rule.identifier());
        }
        
        current_size += chunk_size;
        iteration += 1;
    }
    
    if lines.len() % chunk_size != 0 {
        let mut scanner = StreamingScanner::new(rules);
        let start = Instant::now();
        
        let chunk = create_chunk_from_lines(lines);
        scanner.scan_chunk(&chunk)?;
        
        let elapsed = start.elapsed();
        total_time += elapsed;
        let results = scanner.get_matches();
        let match_count = results.matching_rules().count();
        
        println!(
            "Final iteration: Processed all {} lines ({} bytes) in {:?}, {} matches found",
            lines.len(), chunk.len(), elapsed, match_count
        );
        
        for rule in results.matching_rules() {
            println!("  - Matched rule: {}", rule.identifier());
        }
    }
    
    println!("\nTest 1 Summary:");
    println!("Total time taken by all iterations: {:?}", total_time);
    
    Ok(())
}

fn test2_streaming_chunk(rules: &Rules, lines: &[String], chunk_size: usize) -> Result<()> {
    println!("\n=== Test 2: True Streaming Processing with scan_chunk ===");
    println!("Processing input in {} line chunks", chunk_size);
    
    let mut scanner = StreamingScanner::new(rules);
    let test_start = Instant::now();
    let mut total_lines_processed = 0;
    let mut total_bytes_processed = 0;
    let mut chunk_number = 1;
    
    for chunk_lines in lines.chunks(chunk_size) {
        let chunk_start = Instant::now();
        
        // Convert lines chunk to bytes chunk
        let chunk = create_chunk_from_lines(chunk_lines);
        let chunk_bytes = chunk.len();
        scanner.scan_chunk(&chunk)?;
        
        total_lines_processed += chunk_lines.len();
        total_bytes_processed += chunk_bytes;
        let elapsed_since_start = test_start.elapsed();
        let chunk_elapsed = chunk_start.elapsed();
        
        let results = scanner.get_matches();
        let match_count = results.matching_rules().count();
        
        println!(
            "Chunk {}: Processed {} lines ({} bytes) (total: {} lines, {} bytes) in {:?}, total time: {:?}, {} matches so far",
            chunk_number, chunk_lines.len(), chunk_bytes, total_lines_processed, total_bytes_processed, chunk_elapsed, elapsed_since_start, match_count
        );
        
        // Print matches found after this chunk
        if match_count > 0 {
            println!("  Matches after chunk {}:", chunk_number);
            for rule in results.matching_rules() {
                println!("    - {}", rule.identifier());
            }
        }
        
        chunk_number += 1;
    }
    
    let final_results = scanner.get_matches();
    let total_elapsed = test_start.elapsed();
    
    println!("\nFinal results:");
    println!("Total lines processed: {}", total_lines_processed);
    println!("Total bytes processed: {}", total_bytes_processed);
    println!("Total time: {:?}", total_elapsed);
    println!("Total matches: {}", final_results.matching_rules().count());
    
    for rule in final_results.matching_rules() {
        println!("  - Matched rule: {}", rule.identifier());
    }
    
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    let rules = load_rules(&args.yara_files)?;
    println!("Successfully loaded {} YARA file(s)", args.yara_files.len());
    
    let lines = read_file_lines(&args.input_file)?;
    println!("Input file contains {} lines", lines.len());
    
    test1_cumulative_chunk(&rules, &lines, args.chunk_size)?;
    
    test2_streaming_chunk(&rules, &lines, args.chunk_size)?;
    
    println!("\n=== Performance Test Complete (scan_chunk) ===");
    println!("\nNote: scan_chunk allows patterns to match across line boundaries within chunks,");
    println!("while scan_line restricts patterns to single lines only.");
    
    Ok(())
}