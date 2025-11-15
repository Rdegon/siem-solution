"""
services.filter

Микросервис фильтрации событий:
  - Redis Stream: siem:normalized -> siem:filtered
  - Правила в ClickHouse: siem.filter_rules
"""
