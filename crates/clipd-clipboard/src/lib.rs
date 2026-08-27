//! Platform clipboard backends.
//!
//! MVP uses `arboard` (cross-platform text + image). Platform-specific
//! modules (`macos`, `windows`) will implement change-notification later:
//!   - macOS: NSPasteboard changeCount polling (~50ms) — cheap and reliable
//!   - Windows: AddClipboardFormatListener + WM_CLIPBOARDUPDATE (push)

use anyhow::Result;
use arboard::Clipboard;

/// Read current clipboard as UTF-8 text, if any.
pub fn read_text() -> Result<Option<String>> {
    let mut cb = Clipboard::new()?;
    Ok(cb.get_text().ok())
}

/// Write text to clipboard.
pub fn write_text(text: &str) -> Result<()> {
    let mut cb = Clipboard::new()?;
    cb.set_text(text.to_string())?;
    Ok(())
}
