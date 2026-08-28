# Shutdown Behavior

MSAA distinguishes the GUI viewer from the protected/background monitor.

Quit behavior:

- Tray quit, Dock quit, Cmd+Q, menu quit, and window close route through `AppShutdownCoordinator`.
- GUI quit stops UI timers, cancels background tasks, flushes DB state, and closes GUI DB handles.
- Quitting the GUI does not stop the protected/system daemon unless the user explicitly chooses monitor stop.
- Window close may hide to tray when the tray icon is active; explicit tray/menu quit exits the viewer.
