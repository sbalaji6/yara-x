# multi_input_stream_perf.rs Usage Documentation

## Overview
`multi_input_stream_perf` is a performance testing tool for YARA-X that allows scanning multiple input files in parallel using chunked streaming. It supports processing files individually or scanning entire directories.

## Command Line Arguments

### Required Arguments

#### `-r, --rules <YARA_FILES>...`
- **Description**: One or more YARA rule files to compile and use for scanning
- **Required**: Yes
- **Example**: `-r rules1.yar rules2.yar` or `--rules malware_rules.yar`

#### `-c, --chunk-size <CHUNK_SIZE>`
- **Description**: Size of chunks to read from each file in bytes
- **Required**: Yes
- **Example**: `-c 4096` or `--chunk-size 8192`

### Input Source Arguments (Mutually Exclusive)

#### `-i, --input <INPUT_FILES>...`
- **Description**: One or more input files to scan
- **Format**: `path/to/file` or `path/to/file:UUID`
- **Note**: If a UUID is not provided, one will be generated automatically
- **Example**: `-i file1.txt file2.bin` or `--input sample.exe:550e8400-e29b-41d4-a716-446655440000`

#### `-d, --directory <DIRECTORY>`
- **Description**: Directory path to scan all files within
- **Note**: Cannot be used together with `-i/--input`
- **Example**: `-d /path/to/samples` or `--directory ./test_files`

### Optional Arguments

#### `-p, --parallel <COUNT>`
- **Description**: Number of files to process in parallel per batch
- **Default**: 10
- **Example**: `-p 20` or `--parallel 5`

#### `--relaxed-re-syntax`
- **Description**: Use a more relaxed syntax check while parsing regular expressions in YARA rules
- **Default**: false
- **Example**: `--relaxed-re-syntax`

## Usage Examples

### Basic usage with individual files
```bash
multi_input_stream_perf -r rules.yar -i file1.txt file2.txt -c 4096
```

### Scanning a directory with custom parallelism
```bash
multi_input_stream_perf -r malware_rules.yar -d /path/to/samples -c 8192 -p 20
```

### Using multiple rule files with UUIDs
```bash
multi_input_stream_perf -r rules1.yar rules2.yar -i sample1.exe:550e8400-e29b-41d4-a716-446655440000 sample2.dll:6ba7b810-9dad-11d1-80b4-00c04fd430c8 -c 4096
```

### Relaxed regex syntax for complex rules
```bash
multi_input_stream_perf -r complex_rules.yar -d ./samples --relaxed-re-syntax -c 16384 -p 15
```

## Output Information

The tool provides detailed information during execution:

1. **Rule Loading**: Shows which YARA files are being loaded
2. **Compilation**: Reports the number of compiled YARA rules
3. **Batch Processing**: Displays progress for each batch of files
4. **Per-File Progress**: Shows:
   - Round number
   - File index and path
   - Bytes processed
   - Processing time
   - New matches found
   - Total matches
   - Currently matching rules
5. **Memory Usage**: Reports cache memory usage and active streams after each chunk
6. **Batch Summary**: Final match count for each file in the batch
7. **Memory Statistics**: Detailed memory usage statistics

## Performance Considerations

- **Chunk Size**: Larger chunks may improve throughput but increase memory usage
- **Parallel Count**: Higher values process more files simultaneously but consume more memory
- **Directory Scanning**: When using `-d`, all files in the directory are processed (non-recursive)

## Exit Status

- **0**: Successful execution
- **Non-zero**: Error occurred (file not found, rule compilation error, etc.)