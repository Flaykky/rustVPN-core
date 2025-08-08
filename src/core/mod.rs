/// Модуль `core` отвечает за центральное управление и координацию работы всего VPN-приложения.
/// Он содержит:
/// - Контроллер (`controller.rs`): основной управляющий компонент.
/// - Состояние приложения (`state.rs`): текущее состояние VPN (подключен, отключен и т.д.).
/// - Жизненный цикл (`lifecycle.rs`): управление запуском, остановкой и перезапуском сервиса.

pub mod controller;
pub mod state;
pub mod lifecycle;

// Экспортируем основные типы для удобства
pub use controller::VpnController;
pub use state::{VpnState, StateEvent};
pub use lifecycle::VpnLifecycle;
