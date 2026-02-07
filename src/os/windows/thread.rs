pub struct ThreadManager;

impl Default for ThreadManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadManager {
    pub fn new() -> Self {
        Self {}
    }

    pub fn schedule(&self) {
        todo!()
    }
}
