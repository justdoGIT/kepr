// daemon_vault/testio.rs — in-memory image IO for the crash tests:
// `MemIo` is a shared byte buffer; `Faulty` stops after a byte budget,
// writing the head of the write that crosses it (a torn write) and
// failing every write and fsync after that, like a power cut.

use std::io;
use std::sync::{Arc, Mutex};

use super::image::SlotIo;

#[derive(Clone)]
pub struct MemIo(pub Arc<Mutex<Vec<u8>>>);

impl MemIo {
    pub fn new(len: usize) -> Self {
        Self(Arc::new(Mutex::new(vec![0u8; len])))
    }
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self(Arc::new(Mutex::new(b)))
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl SlotIo for MemIo {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<()> {
        let d = self.0.lock().unwrap();
        let o = off as usize;
        let src = d
            .get(o..o + buf.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        buf.copy_from_slice(src);
        Ok(())
    }
    fn write_at(&mut self, buf: &[u8], off: u64) -> io::Result<()> {
        let mut d = self.0.lock().unwrap();
        let o = off as usize;
        if d.len() < o + buf.len() {
            d.resize(o + buf.len(), 0);
        }
        d[o..o + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn size(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().len() as u64)
    }
}

pub struct Faulty {
    pub inner: MemIo,
    pub budget: usize,
    /// Bytes actually written (to size a full run).
    pub written: usize,
}

impl Faulty {
    pub fn new(inner: MemIo, budget: usize) -> Self {
        Self {
            inner,
            budget,
            written: 0,
        }
    }
}

fn crash() -> io::Error {
    io::Error::other("injected crash")
}

impl SlotIo for Faulty {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<()> {
        self.inner.read_at(buf, off)
    }
    fn write_at(&mut self, buf: &[u8], off: u64) -> io::Result<()> {
        if self.budget == 0 {
            return Err(crash());
        }
        let n = buf.len().min(self.budget);
        self.inner.write_at(&buf[..n], off)?;
        self.budget -= n;
        self.written += n;
        if n < buf.len() {
            return Err(crash());
        }
        Ok(())
    }
    fn sync(&mut self) -> io::Result<()> {
        if self.budget == 0 {
            return Err(crash());
        }
        Ok(())
    }
    fn size(&self) -> io::Result<u64> {
        self.inner.size()
    }
}
