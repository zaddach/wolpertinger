use std::path::Path;

pub struct PathUtils;

impl PathUtils {
    pub fn canonicalize(path: &Path) -> Option<String> {
        path.canonicalize().ok().map(|p| p.to_string_lossy().into_owned())
    }
}
