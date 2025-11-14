-- 01_init_db_and_rbac.sql
-- Назначение:
--   - создать БД siem
--   - создать роли siem_reader/siem_writer
--   - создать пользователей siem_admin и siem_ro
--   - выдать привилегии

-- Параметры, ожидаемые от clickhouse-client:
--   {siem_admin_pass:String} - пароль siem_admin
--   {siem_ro_pass:String}    - пароль siem_ro

CREATE DATABASE IF NOT EXISTS siem ENGINE = Atomic;

-- Роли
CREATE ROLE IF NOT EXISTS siem_reader;
CREATE ROLE IF NOT EXISTS siem_writer;

-- Пользователи
CREATE USER IF NOT EXISTS siem_admin
    IDENTIFIED BY {siem_admin_pass:String}
    DEFAULT ROLE siem_reader, siem_writer;

CREATE USER IF NOT EXISTS siem_ro
    IDENTIFIED BY {siem_ro_pass:String}
    DEFAULT ROLE siem_reader
    SETTINGS PROFILE 'readonly';

-- Привилегии для ролей
GRANT SELECT ON siem.* TO siem_reader;
GRANT SHOW DATABASES, SHOW TABLES ON *.* TO siem_reader;

GRANT INSERT, ALTER, CREATE, DROP, TRUNCATE ON siem.* TO siem_writer;
GRANT SELECT ON system.* TO siem_writer;

-- Привязка ролей к пользователям (на случай, если создавались раньше)
GRANT siem_reader, siem_writer TO siem_admin;
GRANT siem_reader TO siem_ro;
