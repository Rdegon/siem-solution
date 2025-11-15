"""
services.stream_corr

Потоковый коррелятор:
  - Redis Stream: siem:filtered -> ClickHouse: siem.alerts_raw
  - Правила: siem.correlation_rules_stream
"""
