pub struct HandleManager;

impl Default for HandleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleManager {
    pub fn new() -> Self {
        Self {}
    }

    pub fn allocate(&self) {
        todo!()
    }
}
