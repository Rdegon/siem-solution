"""
services.alert_agg

Агрегатор алертов:
  - периодически агрегирует siem.alerts_raw -> siem.alerts_agg
  - группировка по (rule_id, entity_key)
"""
