use std::path::Path;
use std::sync::Arc;
use std::cell::RefCell;
use lru::LruCache;
use rusty_leveldb::{DB, Options, LdbIterator};
use std::sync::Mutex;
use std::num::NonZeroUsize;

/// Cache for storing input data with trace IDs for offset-based access
pub struct OffsetCache {
    /// LevelDB instance for persistent storage
    db: RefCell<DB>,
    /// LRU cache for frequently accessed trace IDs
    lru_cache: Arc<Mutex<LruCache<String, Vec<u8>>>>,
    /// Path to the database directory
    db_path: String,
}

impl OffsetCache {
    /// Creates a new OffsetCache with the specified path
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self, String> {
        let mut opts = Options::default();
        opts.create_if_missing = true;
        opts.write_buffer_size = 128 * 1024 * 1024; // 128MB for write buffer
        opts.block_cache_capacity_bytes = 256 * 1024 * 1024; // 256MB block cache for frequently accessed data
        opts.block_size = 16 * 1024; // 16KB blocks (better for larger line data)
        
        let db = DB::open(db_path.as_ref(), opts)
            .map_err(|e| format!("Failed to open LevelDB: {:?}", e))?;
        let lru_cache = Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap())));
        
        Ok(Self {
            db: RefCell::new(db),
            lru_cache,
            db_path: db_path.as_ref().to_string_lossy().to_string(),
        })
    }
    
    /// Stores data with the given trace ID
    pub fn put(&self, trace_id: &str, data: &[u8]) -> Result<(), String> {
        // Store in LevelDB
        self.db.borrow_mut().put(trace_id.as_bytes(), data)
            .map_err(|e| format!("Failed to put data: {:?}", e))?;
        
        // Also update LRU cache
        if let Ok(mut cache) = self.lru_cache.lock() {
            cache.put(trace_id.to_string(), data.to_vec());
        }
        
        Ok(())
    }
    
    /// Retrieves data for the given trace ID
    pub fn get(&self, trace_id: &str) -> Option<Vec<u8>> {
        // First check LRU cache
        if let Ok(mut cache) = self.lru_cache.lock() {
            if let Some(data) = cache.get(trace_id) {
                return Some(data.clone());
            }
        }
        
        // If not in LRU cache, check LevelDB
        match self.db.borrow_mut().get(trace_id.as_bytes()) {
            Some(data) => {
                // Update LRU cache with the retrieved data
                if let Ok(mut cache) = self.lru_cache.lock() {
                    cache.put(trace_id.to_string(), data.clone());
                }
                Some(data)
            }
            None => None,
        }
    }
    
    /// Batch insert multiple entries for better performance
    pub fn put_batch(&self, entries: &[(String, Vec<u8>)]) -> Result<(), String> {
        // LevelDB doesn't have native batch operations in rusty-leveldb,
        // so we'll do individual puts
        let mut db = self.db.borrow_mut();
        for (trace_id, data) in entries {
            db.put(trace_id.as_bytes(), data)
                .map_err(|e| format!("Failed to put data in batch: {:?}", e))?;
        }
        
        // Update LRU cache
        if let Ok(mut cache) = self.lru_cache.lock() {
            for (trace_id, data) in entries {
                cache.put(trace_id.clone(), data.clone());
            }
        }
        
        Ok(())
    }
    
    /// Clears all data from the cache
    pub fn clear(&self) -> Result<(), String> {
        // Clear LRU cache
        if let Ok(mut cache) = self.lru_cache.lock() {
            cache.clear();
        }
        
        // Clear LevelDB - iterate and delete all keys
        let mut keys_to_delete: Vec<Vec<u8>> = Vec::new();
        {
            let mut db = self.db.borrow_mut();
            let mut iter = db.new_iter().map_err(|e| format!("Failed to create iterator: {:?}", e))?;
            
            // Collect all keys first
            iter.seek_to_first();
            while iter.valid() {
                let mut key = Vec::new();
                let mut val = Vec::new();
                if iter.current(&mut key, &mut val) {
                    keys_to_delete.push(key);
                }
                iter.next();
            }
        }
        
        // Delete all keys
        let mut db = self.db.borrow_mut();
        for key in keys_to_delete {
            db.delete(&key)
                .map_err(|e| format!("Failed to delete key: {:?}", e))?;
        }
        
        Ok(())
    }
    
    /// Deletes a specific entry
    pub fn delete(&self, trace_id: &str) -> Result<(), String> {
        // Remove from LRU cache
        if let Ok(mut cache) = self.lru_cache.lock() {
            cache.pop(trace_id);
        }
        
        // Remove from LevelDB
        self.db.borrow_mut().delete(trace_id.as_bytes())
            .map_err(|e| format!("Failed to delete: {:?}", e))
    }
    
    /// Flushes any pending writes to disk
    pub fn flush(&self) -> Result<(), String> {
        // LevelDB automatically flushes, but we can force a compaction
        self.db.borrow_mut().compact_range(b"", b"\xFF\xFF\xFF\xFF");
        Ok(())
    }
}

impl Drop for OffsetCache {
    fn drop(&mut self) {
        // Flush any pending writes
        let _ = self.flush();
    }
}

/// Extract bytes at a specific offset from the cached line data
pub fn extract_bytes_at_offset(line_data: &[u8], offset: usize, size: usize) -> Option<Vec<u8>> {
    if offset + size <= line_data.len() {
        Some(line_data[offset..offset + size].to_vec())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    
    #[test]
    fn test_offset_cache_basic_operations() {
        let test_dir = "/tmp/test_offset_cache_leveldb";
        let _ = fs::remove_dir_all(test_dir);
        
        let cache = OffsetCache::new(test_dir).unwrap();
        
        // Test put and get
        let trace_id = "trace123";
        let data = b"This is test data";
        
        cache.put(trace_id, data).unwrap();
        
        let retrieved = cache.get(trace_id).unwrap();
        assert_eq!(retrieved, data);
        
        // Test missing key
        assert!(cache.get("missing_key").is_none());
        
        // Test delete
        cache.delete(trace_id).unwrap();
        assert!(cache.get(trace_id).is_none());
        
        // Cleanup
        let _ = fs::remove_dir_all(test_dir);
    }
    
    #[test]
    fn test_batch_operations() {
        let test_dir = "/tmp/test_offset_cache_batch_leveldb";
        let _ = fs::remove_dir_all(test_dir);
        
        let cache = OffsetCache::new(test_dir).unwrap();
        
        let entries = vec![
            ("trace1".to_string(), b"data1".to_vec()),
            ("trace2".to_string(), b"data2".to_vec()),
            ("trace3".to_string(), b"data3".to_vec()),
        ];
        
        cache.put_batch(&entries).unwrap();
        
        assert_eq!(cache.get("trace1").unwrap(), b"data1");
        assert_eq!(cache.get("trace2").unwrap(), b"data2");
        assert_eq!(cache.get("trace3").unwrap(), b"data3");
        
        // Cleanup
        let _ = fs::remove_dir_all(test_dir);
    }
}