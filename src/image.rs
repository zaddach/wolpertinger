use std::fs;
use std::path::Path;
use anyhow::Result;
use goblin::Object;

use crate::config::Architecture;

pub struct Image {
    _buffer: Vec<u8>,
    pub object: Object<'static>,
}

impl Image {
    pub fn parse(path: &Path) -> Result<Self> {
        let buffer = fs::read(path)?;
        let leaked: &'static [u8] = Box::leak(buffer.into_boxed_slice());
        let object = Object::parse(leaked)?;
        let object = unsafe { std::mem::transmute::<Object<'_>, Object<'static>>(object) };
        Ok(Image { _buffer: leaked.to_vec(), object })
    }

    pub fn architecture(&self) -> Result<Architecture> {
        match &self.object {
            Object::Elf(_) => Ok(Architecture::X86_64), // TODO: detect properly
            Object::PE(_) => Ok(Architecture::X86_64), // TODO: detect properly
            _ => Err(anyhow::anyhow!("Unsupported architecture")),
        }
    }
}