use log::{Level, LevelFilter, Metadata, Record};
use std::env;
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;

// Структура логгера с уровнем логирования и опциональным файлом
struct Logger {
    level: LevelFilter,
    file: Option<Mutex<File>>,
}

impl Logger {
    // Создание нового экземпляра логгера
    fn new(level: LevelFilter, file_path: Option<&str>) -> Self {
        let file = file_path.map(|path| {
            let file = File::create(path).expect("Не удалось создать файл логов");
            Mutex::new(file)
        });
        Logger { level, file }
    }
}

// Реализация трейта Log для кастомного логгера
impl log::Log for Logger {
    // Проверка, включён ли данный уровень логирования
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    // Обработка и вывод логов
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level = record.level();
            let message = format!("[{}] {} - {}", level, record.target(), record.args());

            // Цветной вывод в терминале с помощью ANSI-кодов
            let colored_message = match level {
                Level::Error => format!("\x1b[31m{}\x1b[0m", message), // Красный
                Level::Warn => format!("\x1b[33m{}\x1b[0m", message),  // Жёлтый
                Level::Info => format!("\x1b[32m{}\x1b[0m", message),  // Зелёный
                Level::Debug => format!("\x1b[34m{}\x1b[0m", message), // Синий
                Level::Trace => format!("\x1b[35m{}\x1b[0m", message), // Фиолетовый
            };

            // Вывод в терминал
            println!("{}", colored_message);

            // Запись в файл, если он указан
            if let Some(file_mutex) = &self.file {
                let mut file = file_mutex.lock().expect("Не удалось заблокировать файл логов");
                writeln!(file, "{}", message).expect("Не удалось записать в файл логов");
            }
        }
    }

    // Сброс буфера файла
    fn flush(&self) {
        if let Some(file_mutex) = &self.file {
            let mut file = file_mutex.lock().expect("Не удалось заблокировать файл логов");
            file.flush().expect("Не удалось сбросить буфер файла логов");
        }
    }
}

// Инициализация логгера с заданным уровнем и путём к файлу
pub fn init_logging(level: LevelFilter, file_path: Option<&str>) {
    let logger = Logger::new(level, file_path);
    log::set_boxed_logger(Box::new(logger)).expect("Не удалось установить логгер");
    log::set_max_level(level);
}

// Настройка логирования через переменные окружения
pub fn setup_logging() {
    // Чтение уровня логирования из RUST_LOG, по умолчанию "info"
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let level = match log_level.to_lowercase().as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };

    // Чтение пути к файлу логов из LOG_FILE, если указано
    let log_file = env::var("LOG_FILE").ok();

    // Инициализация логгера
    init_logging(level, log_file.as_deref());
}

// Пример использования в коде:
// fn main() {
//     setup_logging();
//     log::info!("Программа запущена");
//     log::debug!("Отладочная информация");
//     log::error!("Произошла ошибка");
// }
