ALTER TABLE siem.filter_rules DELETE WHERE id IN (3001, 3002, 3003, 3004, 3005, 3006);

INSERT INTO siem.filter_rules
(id, name, description, priority, expr, action, tags, enabled)
VALUES
(
    3001,
    'Drop Linux session success chatter',
    'Suppresses high-volume successful session lifecycle events that do not add triage value.',
    10,
    'event.category == ''session'' and event.outcome == ''success''',
    'drop',
    [],
    1
),
(
    3002,
    'Drop low-severity service lifecycle events',
    'Removes service start/stop audit noise after normalization.',
    20,
    'event.category == ''service'' and severity == ''low''',
    'drop',
    [],
    1
),
(
    3003,
    'Tag Linux audit detail records',
    'Marks PATH/CWD/PROCTITLE detail records as low-priority audit context.',
    30,
    'subcategory == ''audit_path'' or subcategory == ''audit_cwd'' or subcategory == ''audit_proctitle''',
    'tag',
    ['noise.audit_detail'],
    1
),
(
    3004,
    'Tag Linux firewall block noise',
    'Marks UFW block events as perimeter noise unless promoted by another detector.',
    40,
    'subcategory == ''linux_firewall_blocked''',
    'tag',
    ['noise.firewall'],
    1
),
(
    3005,
    'Tag SSH invalid-user probes',
    'Marks SSH invalid-user probes as internet exposure noise for easier filtering.',
    50,
    'subcategory == ''ssh_invalid_user''',
    'tag',
    ['noise.auth_probe'],
    1
),
(
    3006,
    'Drop systemd informational syslog',
    'Suppresses repetitive low-value systemd informational messages from Linux hosts.',
    60,
    'category == ''syslog'' and severity == ''info'' and process.name == ''systemd''',
    'drop',
    [],
    1
);
