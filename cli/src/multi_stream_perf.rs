use anyhow::{anyhow, Result};
use clap::Parser;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;
use yara_x::{Compiler, Rules, MultiStreamScanner};

#[derive(Parser, Debug)]
#[command(
    name = "multi-stream-perf",
    about = "YARA-X multi-stream scanner performance test",
    long_about = "Tests multi-stream scanner performance with two concurrent streams processing different data"
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
        help = "Input file to scan (will be split between streams)",
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

    #[arg(
        long = "relaxed-re-syntax",
        help = "Use a more relaxed syntax check while parsing regular expressions",
        default_value = "false"
    )]
    relaxed_re_syntax: bool,
}

fn load_rules(yara_files: &[PathBuf], relaxed_re_syntax: bool) -> Result<Rules> {
    let mut compiler = Compiler::new();
    
    if relaxed_re_syntax {
        compiler.relaxed_re_syntax(true);
    }
    
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

fn test1_alternating_streams(rules: &Rules, lines: &[String], chunk_size: usize) -> Result<()> {
    println!("\n=== Test 1: Alternating Between Two Streams ===");
    println!("Processing input alternating between two streams with chunk size: {}", chunk_size);
    
    let mut scanner = MultiStreamScanner::new(rules);
    let stream1 = Uuid::new_v4();
    let stream2 = Uuid::new_v4();
    
    println!("Stream 1 ID: {}", stream1);
    println!("Stream 2 ID: {}", stream2);
    
    let test_start = Instant::now();
    let mut stream1_lines = 0;
    let mut stream2_lines = 0;
    let mut stream1_bytes = 0;
    let mut stream2_bytes = 0;
    let mut chunk_number = 1;
    
    // Process chunks alternating between streams
    for (idx, chunk_lines) in lines.chunks(chunk_size).enumerate() {
        let chunk_start = Instant::now();
        let chunk = create_chunk_from_lines(chunk_lines);
        let chunk_bytes = chunk.len();
        
        // Alternate between stream1 and stream2
        let (stream_id, stream_name) = if idx % 2 == 0 {
            stream1_lines += chunk_lines.len();
            stream1_bytes += chunk_bytes;
            (&stream1, "Stream 1")
        } else {
            stream2_lines += chunk_lines.len();
            stream2_bytes += chunk_bytes;
            (&stream2, "Stream 2")
        };
        
        scanner.scan_chunk(stream_id, &chunk)?;
        
        let chunk_elapsed = chunk_start.elapsed();
        let results = scanner.get_matches(stream_id).unwrap();
        let match_count = results.matching_rules().count();
        
        println!(
            "Chunk {} ({}): Processed {} lines ({} bytes) in {:?}, {} matches",
            chunk_number, stream_name, chunk_lines.len(), chunk_bytes, chunk_elapsed, match_count
        );
        
        if match_count > 0 {
            for rule in results.matching_rules() {
                println!("  - {}: {}", stream_name, rule.identifier());
            }
        }
        
        chunk_number += 1;
    }
    
    let total_elapsed = test_start.elapsed();
    
    // Get final results for both streams
    println!("\n--- Final Results ---");
    
    let results1 = scanner.get_matches(&stream1).unwrap();
    println!("\nStream 1 Summary:");
    println!("  Lines processed: {}", stream1_lines);
    println!("  Bytes processed: {}", stream1_bytes);
    println!("  Total matches: {}", results1.matching_rules().count());
    for rule in results1.matching_rules() {
        println!("  - Matched rule: {}", rule.identifier());
    }
    
    if let Some(results2) = scanner.get_matches(&stream2) {
        println!("\nStream 2 Summary:");
        println!("  Lines processed: {}", stream2_lines);
        println!("  Bytes processed: {}", stream2_bytes);
        println!("  Total matches: {}", results2.matching_rules().count());
        for rule in results2.matching_rules() {
            println!("  - Matched rule: {}", rule.identifier());
        }
    } else {
        println!("\nStream 2: No data processed");
    }
    
    println!("\nTotal time: {:?}", total_elapsed);
    println!("Active streams: {}", scanner.active_streams().len());
    
    Ok(())
}

fn test2_concurrent_processing(rules: &Rules, lines: &[String], chunk_size: usize) -> Result<()> {
    println!("\n=== Test 2: Concurrent Stream Processing ===");
    println!("Processing even/odd lines in separate streams");
    
    let mut scanner = MultiStreamScanner::new(rules);
    let stream1 = Uuid::new_v4();  // Even lines
    let stream2 = Uuid::new_v4();  // Odd lines
    
    println!("Stream 1 (even lines) ID: {}", stream1);
    println!("Stream 2 (odd lines) ID: {}", stream2);
    
    let test_start = Instant::now();
    let mut stream1_buffer = Vec::new();
    let mut stream2_buffer = Vec::new();
    let mut chunk_number = 1;
    
    // Split lines into even/odd
    for (idx, line) in lines.iter().enumerate() {
        if idx % 2 == 0 {
            stream1_buffer.push(line.clone());
        } else {
            stream2_buffer.push(line.clone());
        }
        
        // Process when buffers reach chunk_size
        if stream1_buffer.len() >= chunk_size {
            let chunk_start = Instant::now();
            let chunk = create_chunk_from_lines(&stream1_buffer);
            scanner.scan_chunk(&stream1, &chunk)?;
            let elapsed = chunk_start.elapsed();
            
            let results = scanner.get_matches(&stream1).unwrap();
            println!(
                "Stream 1 Chunk {}: {} lines ({} bytes) in {:?}, {} matches",
                chunk_number, stream1_buffer.len(), chunk.len(), elapsed, results.matching_rules().count()
            );
            
            stream1_buffer.clear();
        }
        
        if stream2_buffer.len() >= chunk_size {
            let chunk_start = Instant::now();
            let chunk = create_chunk_from_lines(&stream2_buffer);
            scanner.scan_chunk(&stream2, &chunk)?;
            let elapsed = chunk_start.elapsed();
            
            let results = scanner.get_matches(&stream2).unwrap();
            println!(
                "Stream 2 Chunk {}: {} lines ({} bytes) in {:?}, {} matches",
                chunk_number, stream2_buffer.len(), chunk.len(), elapsed, results.matching_rules().count()
            );
            
            stream2_buffer.clear();
            chunk_number += 1;
        }
    }
    
    // Process remaining lines
    if !stream1_buffer.is_empty() {
        let chunk = create_chunk_from_lines(&stream1_buffer);
        scanner.scan_chunk(&stream1, &chunk)?;
        println!("Stream 1 Final: {} lines ({} bytes)", stream1_buffer.len(), chunk.len());
    }
    
    if !stream2_buffer.is_empty() {
        let chunk = create_chunk_from_lines(&stream2_buffer);
        scanner.scan_chunk(&stream2, &chunk)?;
        println!("Stream 2 Final: {} lines ({} bytes)", stream2_buffer.len(), chunk.len());
    }
    
    let total_elapsed = test_start.elapsed();
    
    // Get final results with stream stats
    println!("\n--- Final Results ---");
    
    let results1 = scanner.get_matches(&stream1).unwrap();
    let bytes1 = scanner.bytes_processed(&stream1).unwrap_or(0);
    let lines1 = scanner.lines_processed(&stream1).unwrap_or(0);
    
    println!("\nStream 1 (even lines) Summary:");
    println!("  Lines processed: {}", lines1);
    println!("  Bytes processed: {}", bytes1);
    println!("  Total matches: {}", results1.matching_rules().count());
    for rule in results1.matching_rules() {
        println!("  - Matched rule: {}", rule.identifier());
    }
    
    let results2 = scanner.get_matches(&stream2).unwrap();
    let bytes2 = scanner.bytes_processed(&stream2).unwrap_or(0);
    let lines2 = scanner.lines_processed(&stream2).unwrap_or(0);
    
    println!("\nStream 2 (odd lines) Summary:");
    println!("  Lines processed: {}", lines2);
    println!("  Bytes processed: {}", bytes2);
    println!("  Total matches: {}", results2.matching_rules().count());
    for rule in results2.matching_rules() {
        println!("  - Matched rule: {}", rule.identifier());
    }
    
    println!("\nTotal time: {:?}", total_elapsed);
    println!("Total lines processed: {}", lines1 + lines2);
    println!("Total bytes processed: {}", bytes1 + bytes2);
    
    // Test stream lifecycle
    println!("\n--- Testing Stream Lifecycle ---");
    
    // Reset stream1
    scanner.reset_stream(&stream1)?;
    println!("Stream 1 reset - lines: {:?}, bytes: {:?}", 
        scanner.lines_processed(&stream1), 
        scanner.bytes_processed(&stream1)
    );
    
    // Close stream2
    if let Some(final_results) = scanner.close_stream(&stream2) {
        println!("Stream 2 closed - final stats: {} lines, {} bytes",
            final_results.lines_processed,
            final_results.bytes_processed
        );
    } else {
        println!("Stream 2 was already closed or never created");
    }
    
    println!("Active streams remaining: {}", scanner.active_streams().len());
    
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    let rules = load_rules(&args.yara_files, args.relaxed_re_syntax)?;
    println!("Successfully loaded {} YARA file(s)", args.yara_files.len());
    
    let lines = read_file_lines(&args.input_file)?;
    println!("Input file contains {} lines", lines.len());
    
    test1_alternating_streams(&rules, &lines, args.chunk_size)?;
    
    test2_concurrent_processing(&rules, &lines, args.chunk_size)?;
    
    println!("\n=== Multi-Stream Performance Test Complete ===");
    println!("\nNote: Multi-stream scanner maintains separate contexts for each stream,");
    println!("allowing independent pattern matching across multiple data sources.");
    
    Ok(())
}