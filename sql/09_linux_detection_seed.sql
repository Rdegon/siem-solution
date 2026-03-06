-- Seed Linux-focused stream correlation rules for the lab deployment.
-- Re-runnable: replaces current stream and batch correlation seeds.

TRUNCATE TABLE siem.correlation_rules_stream;
TRUNCATE TABLE siem.correlation_rules_batch;

INSERT INTO siem.correlation_rules_stream
(
    id,
    name,
    description,
    enabled,
    severity,
    pattern,
    window_s,
    threshold,
    expr,
    entity_field
)
VALUES
(
    1001,
    'linux_ssh_failed_password_burst',
    'Multiple SSH authentication failures from the same source IP within 5 minutes.',
    1,
    'high',
    'threshold',
    300,
    5,
    'event.provider == ''linux.sshd'' and event.action == ''authentication_failed''',
    'source.ip'
),
(
    1002,
    'linux_audit_user_login_failures',
    'Repeated auditd USER_LOGIN failures from the same source IP within 5 minutes.',
    1,
    'medium',
    'threshold',
    300,
    3,
    'event.provider == ''linux.auditd'' and event.type == ''audit_user_login_failure''',
    'source.ip'
),
(
    1003,
    'linux_sudo_to_root',
    'Direct sudo command execution targeting root.',
    1,
    'medium',
    'threshold',
    300,
    1,
    'event.provider == ''linux.sudo'' and event.type == ''sudo_command'' and user.target.name == ''root''',
    'user.name'
),
(
    1004,
    'linux_exec_as_root_burst',
    'Repeated auditd exec_as_root events on the same host within 10 minutes.',
    1,
    'high',
    'threshold',
    600,
    3,
    'event.provider == ''linux.auditd'' and event.type == ''audit_exec_as_root''',
    'log_source'
);
