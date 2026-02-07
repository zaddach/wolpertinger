use unicorn_engine::{Unicorn, Prot};
use anyhow::{Result, anyhow};

pub type Protection = u32;

pub const PROT_NONE: Protection = 0;
pub const PROT_READ: Protection = 1;
pub const PROT_WRITE: Protection = 2;
pub const PROT_EXEC: Protection = 4;
pub const PROT_ALL: Protection = PROT_READ | PROT_WRITE | PROT_EXEC;

const PAGE_SIZE: u64 = 0x1000;

#[derive(Debug, Clone)]
pub struct MapInfo {
    pub start: u64,
    pub end: u64,
    pub perms: Protection,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub addr: u64,
    pub size: u64,
}

pub struct HeapManager {
    #[allow(dead_code)]
    start_address: u64,
    end_address: u64,
    chunks: Vec<Chunk>,
    current_alloc: u64,
    current_use: u64,
}

impl HeapManager {
    pub fn new(start_address: u64, end_address: u64) -> Self {
        let mut hm = Self {
            start_address,
            end_address,
            chunks: Vec::new(),
            current_alloc: start_address,
            current_use: 0,
        };

        // Initialize single free chunk covering the whole heap
        let total = end_address.saturating_sub(start_address);
        if total > 0 {
            hm.chunks.push(Chunk { addr: start_address, size: total });
        }

        hm
    }

    pub fn alloc(&mut self, size: u64) -> Option<u64> {
        // Bump-style allocation with simple chunk splitting
        if size == 0 { return None; }
        // align to 8 bytes
        let align = 8u64;
        let size = (size + align - 1) & !(align - 1);

        // Try quick bump using current_alloc
        let mut candidate = self.current_alloc;
        // Align candidate
        if (candidate & (align - 1)) != 0 {
            candidate = (candidate + align - 1) & !(align - 1);
        }

        if candidate + size <= self.end_address {
            self.current_alloc = candidate + size;
            self.current_use += size;
            return Some(candidate);
        }

        // Fallback: search free chunks list
        for i in 0..self.chunks.len() {
            if self.chunks[i].size >= size {
                let addr = self.chunks[i].addr;
                // shrink chunk
                self.chunks[i].addr += size;
                self.chunks[i].size -= size;
                if self.chunks[i].size == 0 {
                    self.chunks.remove(i);
                }
                self.current_use += size;
                return Some(addr);
            }
        }

        None // Out of memory
    }

    pub fn free(&mut self, _addr: u64) {
        // No-op for now; a real implementation would coalesce freed blocks
    }
}

pub struct MemoryManager {
    map_info: Vec<MapInfo>,
    heap_manager: Option<HeapManager>,
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryManager {
    pub fn new() -> Self {
        Self {
            map_info: Vec::new(),
            heap_manager: None,
        }
    }

    pub fn set_heap(&mut self, start: u64, end: u64) {
        self.heap_manager = Some(HeapManager::new(start, end));
    }

    pub fn map(&mut self, unicorn: &mut Unicorn<'_, ()>, addr: u64, size: u64, perms: Protection, label: &str) -> Result<()> {
        // Align address down to page boundary
        let aligned_addr = addr & !(PAGE_SIZE - 1);
        // Align size up to page boundary
        let aligned_size = size.div_ceil(PAGE_SIZE) * PAGE_SIZE;

        if !self.is_available(aligned_addr, aligned_size) {
            return Err(anyhow!("Memory not available"));
        }

        unicorn.mem_map(aligned_addr, aligned_size, Prot(perms))?;
        self.map_info.push(MapInfo {
            start: aligned_addr,
            end: aligned_addr + aligned_size,
            perms,
            label: label.to_string(),
        });

        Ok(())
    }

    pub fn is_available(&self, addr: u64, size: u64) -> bool {
        let end = addr + size;
        for info in &self.map_info {
            if addr < info.end && end > info.start {
                return false;
            }
        }
        true
    }

    pub fn is_region_free(&self, addr: u64, size: u64) -> bool {
        self.is_available(addr, size)
    }

    pub fn find_free_region(&self, size: u64) -> Option<u64> {
        // Simple strategy: try addresses starting from 0x40000000
        let mut candidate = 0x40000000u64;
        loop {
            if self.is_available(candidate, size) {
                return Some(candidate);
            }
            candidate += 0x100000; // Try next 1MB boundary
            if candidate > 0x80000000 { // Don't go too high
                break;
            }
        }
        None
    }

    pub fn read(&self, unicorn: &Unicorn<'_, ()>, addr: u64, size: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        unicorn.mem_read(addr, &mut buf)?;
        Ok(buf)
    }

    pub fn write(&mut self, unicorn: &mut Unicorn<'_, ()>, addr: u64, data: &[u8]) -> Result<()> {
        unicorn.mem_write(addr, data)?;
        Ok(())
    }

    pub fn write_u64(&mut self, unicorn: &mut Unicorn<'_, ()>, addr: u64, value: u64) -> Result<()> {
        let data = value.to_le_bytes();
        self.write(unicorn, addr, &data)
    }

    pub fn write_u32(&mut self, unicorn: &mut Unicorn<'_, ()>, addr: u64, value: u32) -> Result<()> {
        let data = value.to_le_bytes();
        self.write(unicorn, addr, &data)
    }

    pub fn map_region(&mut self, unicorn: &mut Unicorn<'_, ()>, address: u64, size: u64) -> Result<()> {
        self.map(unicorn, address, size, PROT_ALL, "[mapped]")
    }

    pub fn heap_alloc(&mut self, size: u64) -> Option<u64> {
        if let Some(ref mut heap) = self.heap_manager {
            heap.alloc(size)
        } else {
            None
        }
    }

    pub fn heap_free(&mut self, addr: u64) {
        if let Some(ref mut heap) = self.heap_manager {
            heap.free(addr);
        }
    }

    pub fn get_memory_layout(&self) -> &[MapInfo] {
        &self.map_info
    }
}
