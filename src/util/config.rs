use std::path::{Path, PathBuf};

/// If `path` is relative, joins it to `base`; otherwise returns it unchanged.
pub fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_relative() {
        base.join(path)
    } else {
        path.to_path_buf()
    }
}

/// Computes the per-node state directory, allowing a relative state root to be relative to a config file.
pub fn state_dir_for_node(config_path: &Path, state_root: &Path, node_id: &str) -> PathBuf {
    let base = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let root = if state_root.is_absolute() {
        state_root.to_path_buf()
    } else {
        base.join(state_root)
    };
    root.join(node_id)
}
