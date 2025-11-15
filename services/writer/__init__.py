"""
services.writer

Микросервис записи событий в ClickHouse:
  - Redis Stream: siem:filtered -> ClickHouse siem.events
"""
