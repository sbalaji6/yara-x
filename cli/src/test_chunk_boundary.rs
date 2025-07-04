use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use uuid::Uuid;
use yara_x::{Compiler, StreamingScanner, MultiStreamScanner};

fn main() -> Result<()> {
    // Load the test rule
    let mut compiler = Compiler::new();
    let rule_content = std::fs::read_to_string("test_simple_chunk.yar")?;
    compiler.add_source(rule_content.as_str())?;
    let rules = compiler.build();
    
    // Test with chunk size 3 to force pattern splits
    let chunk_size = 3;
    
    println!("=== Testing Pattern Matching Across Chunk Boundaries ===\n");
    
    // Test 1: StreamingScanner with first file
    println!("1. StreamingScanner with test_chunk_data1.txt:");
    test_streaming_scanner(&rules, "test_chunk_data1.txt", chunk_size)?;
    
    // Test 2: MultiStreamScanner with both files
    println!("\n2. MultiStreamScanner with both files:");
    test_multi_stream_scanner(&rules, &["test_chunk_data1.txt", "test_chunk_data2.txt"], chunk_size)?;
    
    Ok(())
}

fn test_streaming_scanner(rules: &yara_x::Rules, file_path: &str, chunk_size: usize) -> Result<()> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut scanner = StreamingScanner::new(rules);
    
    let mut chunk_num = 1;
    let mut buffer = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        buffer.push(line);
        
        if buffer.len() >= chunk_size {
            let chunk_data = buffer.join("\n");
            println!("  Chunk {}: {} bytes - {:?}", chunk_num, chunk_data.len(), 
                chunk_data.chars().take(50).collect::<String>());
            scanner.scan_chunk(chunk_data.as_bytes())?;
            
            let results = scanner.get_matches();
            let matches = results.matching_rules().count();
            println!("    Matches so far: {}", matches);
            
            buffer.clear();
            chunk_num += 1;
        }
    }
    
    // Process remaining data
    if !buffer.is_empty() {
        let chunk_data = buffer.join("\n");
        println!("  Chunk {}: {} bytes - {:?}", chunk_num, chunk_data.len(),
            chunk_data.chars().take(50).collect::<String>());
        scanner.scan_chunk(chunk_data.as_bytes())?;
        
        let results = scanner.get_matches();
        let matches = results.matching_rules().count();
        println!("    Matches so far: {}", matches);
    }
    
    let final_results = scanner.get_matches();
    println!("  Final result: {} rules matched", final_results.matching_rules().count());
    
    Ok(())
}

fn test_multi_stream_scanner(rules: &yara_x::Rules, file_paths: &[&str], chunk_size: usize) -> Result<()> {
    let mut scanner = MultiStreamScanner::new(rules);
    let mut readers = Vec::new();
    let mut uuids = Vec::new();
    let mut buffers: Vec<Vec<String>> = Vec::new();
    
    // Initialize files
    for path in file_paths {
        let file = File::open(path)?;
        readers.push(BufReader::new(file));
        uuids.push(Uuid::new_v4());
        buffers.push(Vec::new());
        println!("  Stream {}: {}", uuids.last().unwrap(), path);
    }
    
    let mut round = 1;
    let mut active = file_paths.len();
    
    while active > 0 {
        println!("\n  Round {}:", round);
        let mut processed = 0;
        
        for i in 0..readers.len() {
            // Read chunk_size lines
            let mut lines_read = 0;
            for _ in 0..chunk_size {
                let mut line = String::new();
                if readers[i].read_line(&mut line)? == 0 {
                    break;
                }
                line = line.trim_end().to_string();
                buffers[i].push(line);
                lines_read += 1;
            }
            
            if lines_read > 0 {
                // Process this chunk
                let chunk_data = buffers[i].join("\n");
                println!("    File {}: {} bytes - {:?}", i, chunk_data.len(),
                    chunk_data.chars().take(50).collect::<String>());
                scanner.scan_chunk(&uuids[i], chunk_data.as_bytes())?;
                
                let results = scanner.get_matches(&uuids[i]).unwrap();
                let matches = results.matching_rules().count();
                println!("      Matches so far: {}", matches);
                
                buffers[i].clear();
                processed += 1;
            } else {
                active -= 1;
            }
        }
        
        if processed > 0 {
            round += 1;
        }
    }
    
    println!("\n  Final results:");
    for i in 0..file_paths.len() {
        let results = scanner.get_matches(&uuids[i]).unwrap();
        println!("    Stream {} ({}): {} rules matched", 
            uuids[i], file_paths[i], results.matching_rules().count());
    }
    
    Ok(())
}