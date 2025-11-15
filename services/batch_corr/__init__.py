"""
services.batch_corr

Batch-коррелятор:
  - периодически выполняет SQL-шаблоны из siem.correlation_rules_batch
  - шаблон должен быть одиночным INSERT ... SELECT ... c плейсхолдером {WINDOW_S}
"""
