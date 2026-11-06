#[cfg(target_os = "macos")]
pub fn menu(app: &tauri::AppHandle) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{Menu, MenuItem, MenuItemKind};
    let menu = Menu::default(app)?;
    if let Some(MenuItemKind::Submenu(application)) = menu.items()?.first() {
        application.remove_at(0)?;
        application.insert(&MenuItem::with_id(app, "openaidr-about", "About OpenAIDR", true, None::<&str>)?, 0)?;
    }
    Ok(menu)
}
