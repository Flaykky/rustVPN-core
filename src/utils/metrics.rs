// src/utils/metrics.rs

use prometheus::{IntCounter, IntGauge, Histogram, Registry, TextEncoder, Encoder, HistogramOpts};
use std::sync::Arc;
use std::time::Instant;
use log::error;

/// Структура для управления метриками VPN.
pub struct VpnMetrics {
    registry: Registry,
    bytes_sent: IntCounter,
    bytes_received: IntCounter,
    active_connections: IntGauge,
    connection_time: Histogram,
    connection_errors: IntCounter,
    latency: Histogram,
}

impl VpnMetrics {
    /// Инициализирует новый экземпляр `VpnMetrics` с регистрацией всех метрик.
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let bytes_sent = IntCounter::new("vpn_bytes_sent", "Общее количество отправленных байтов")?;
        let bytes_received = IntCounter::new("vpn_bytes_received", "Общее количество полученных байтов")?;
        let active_connections = IntGauge::new("vpn_active_connections", "Количество активных соединений")?;
        let connection_time = Histogram::with_opts(
            HistogramOpts::new("vpn_connection_time", "Время подключения в секундах")
                .buckets(vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]),
        )?;
        let connection_errors = IntCounter::new("vpn_connection_errors", "Количество ошибок подключения")?;
        let latency = Histogram::with_opts(
            HistogramOpts::new("vpn_latency", "Латентность в миллисекундах")
                .buckets(vec![10.0, 50.0, 100.0, 200.0, 500.0, 1000.0]),
        )?;

        registry.register(Box::new(bytes_sent.clone()))?;
        registry.register(Box::new(bytes_received.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(connection_time.clone()))?;
        registry.register(Box::new(connection_errors.clone()))?;
        registry.register(Box::new(latency.clone()))?;

        Ok(Self {
            registry,
            bytes_sent,
            bytes_received,
            active_connections,
            connection_time,
            connection_errors,
            latency,
        })
    }

    /// Увеличивает счетчик отправленных байтов на заданное значение.
    pub fn increment_bytes_sent(&self, amount: u64) {
        self.bytes_sent.inc_by(amount);
    }

    /// Увеличивает счетчик полученных байтов на заданное значение.
    pub fn increment_bytes_received(&self, amount: u64) {
        self.bytes_received.inc_by(amount);
    }

    /// Увеличивает количество активных соединений на 1.
    pub fn increment_active_connections(&self) {
        self.active_connections.inc();
    }

    /// Уменьшает количество активных соединений на 1.
    pub fn decrement_active_connections(&self) {
        self.active_connections.dec();
    }

    /// Устанавливает количество активных соединений в заданное значение.
    pub fn set_active_connections(&self, value: i64) {
        self.active_connections.set(value);
    }

    /// Начинает отсчет времени подключения, возвращая момент начала.
    pub fn start_connection_timer(&self) -> Instant {
        Instant::now()
    }

    /// Завершает отсчет времени подключения и записывает результат в гистограмму.
    pub fn stop_connection_timer(&self, start: Instant) {
        let duration = start.elapsed().as_secs_f64();
        self.connection_time.observe(duration);
    }

    /// Увеличивает счетчик ошибок подключения на 1.
    pub fn increment_connection_errors(&self) {
        self.connection_errors.inc();
    }

    /// Записывает значение латентности в миллисекундах в гистограмму.
    pub fn observe_latency(&self, latency_ms: f64) {
        self.latency.observe(latency_ms);
    }

    /// Возвращает текущие значения метрик в текстовом формате для Prometheus.
    pub fn expose_metrics(&self) -> String {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            error!("Ошибка при экспонировании метрик: {}", e);
            return String::new();
        }
        String::from_utf8(buffer).unwrap_or_else(|_| String::new())
    }
}

/// Тесты для проверки корректности работы модуля метрик.
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_metrics_initialization() {
        let metrics = VpnMetrics::new().expect("Ошибка инициализации метрик");
        assert_eq!(metrics.bytes_sent.get(), 0);
        assert_eq!(metrics.bytes_received.get(), 0);
        assert_eq!(metrics.active_connections.get(), 0);
        assert_eq!(metrics.connection_errors.get(), 0);
    }

    #[test]
    fn test_bytes_counters() {
        let metrics = VpnMetrics::new().unwrap();
        metrics.increment_bytes_sent(500);
        metrics.increment_bytes_received(1000);
        assert_eq!(metrics.bytes_sent.get(), 500);
        assert_eq!(metrics.bytes_received.get(), 1000);
    }

    #[test]
    fn test_active_connections() {
        let metrics = VpnMetrics::new().unwrap();
        metrics.increment_active_connections();
        metrics.increment_active_connections();
        assert_eq!(metrics.active_connections.get(), 2);
        metrics.decrement_active_connections();
        assert_eq!(metrics.active_connections.get(), 1);
        metrics.set_active_connections(5);
        assert_eq!(metrics.active_connections.get(), 5);
    }

    #[test]
    fn test_connection_time() {
        let metrics = VpnMetrics::new().unwrap();
        let start = metrics.start_connection_timer();
        sleep(Duration::from_millis(150));
        metrics.stop_connection_timer(start);
        assert!(metrics.connection_time.get_sample_count() == 1);
    }

    #[test]
    fn test_connection_errors() {
        let metrics = VpnMetrics::new().unwrap();
        metrics.increment_connection_errors();
        metrics.increment_connection_errors();
        assert_eq!(metrics.connection_errors.get(), 2);
    }

    #[test]
    fn test_latency() {
        let metrics = VpnMetrics::new().unwrap();
        metrics.observe_latency(75.0);
        metrics.observe_latency(150.0);
        assert!(metrics.latency.get_sample_count() == 2);
    }

    #[test]
    fn test_expose_metrics() {
        let metrics = VpnMetrics::new().unwrap();
        metrics.increment_bytes_sent(100);
        metrics.observe_latency(50.0);
        let output = metrics.expose_metrics();
        assert!(!output.is_empty());
        assert!(output.contains("vpn_bytes_sent"));
        assert!(output.contains("vpn_latency"));
    }
}
