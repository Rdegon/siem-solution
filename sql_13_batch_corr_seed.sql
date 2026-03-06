ALTER TABLE siem.correlation_rules_batch DELETE WHERE id IN (4001, 4002);

INSERT INTO siem.correlation_rules_batch
(id, name, description, enabled, severity, window_s, sql_template)
VALUES
(
    4001,
    'Linux SSH Success After Failures',
    'Creates a batch alert when a source IP succeeds after multiple SSH failures within the time window.',
    1,
    'high',
    900,
    '
INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now() AS ts,
    generateUUIDv4() AS alert_id,
    4001 AS rule_id,
    ''Linux SSH Success After Failures'' AS rule_name,
    ''high'' AS severity,
    candidate.ts_first,
    candidate.ts_last,
    {WINDOW_S} AS window_s,
    candidate.entity_key,
    candidate.hits,
    candidate.context_json,
    candidate.source,
    ''open'' AS status
FROM
(
    SELECT
        src_ip_text AS entity_key,
        any(source_name) AS source,
        min(failure_ts) AS ts_first,
        max(success_ts) AS ts_last,
        failures AS hits,
        concat(
            ''{"source":"'', any(source_name),
            ''","event_type":"batch_ssh_success_after_failures","source_ip":"'', src_ip_text,
            ''","failures":'', toString(failures),
            ''}''
        ) AS context_json
    FROM
    (
        SELECT
            if(src_ip = 0, '''', IPv4NumToString(src_ip)) AS src_ip_text,
            if(host_name != '''' AND host_name != ''-'', host_name, log_source) AS source_name,
            countIf(subcategory IN (''ssh_login_failure'', ''audit_user_login_failure'', ''ssh_invalid_user'', ''audit_user_err'')) AS failures,
            minIf(ts, subcategory IN (''ssh_login_failure'', ''audit_user_login_failure'', ''ssh_invalid_user'', ''audit_user_err'')) AS failure_ts,
            maxIf(ts, subcategory = ''ssh_login_success'') AS success_ts
        FROM siem.events
        WHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
        GROUP BY src_ip_text, source_name
    )
    WHERE src_ip_text != ''''
      AND failures >= 3
      AND success_ts > toDateTime(0)
      AND success_ts >= failure_ts
    GROUP BY src_ip_text, failures
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = 4001
      AND ts_last >= now() - INTERVAL {WINDOW_S} SECOND
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''''
'
),
(
    4002,
    'Linux Multi-Host SSH Brute Force',
    'Creates a batch alert when a source IP fails authentication against multiple Linux hosts within the time window.',
    1,
    'high',
    900,
    '
INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now() AS ts,
    generateUUIDv4() AS alert_id,
    4002 AS rule_id,
    ''Linux Multi-Host SSH Brute Force'' AS rule_name,
    ''high'' AS severity,
    candidate.ts_first,
    candidate.ts_last,
    {WINDOW_S} AS window_s,
    candidate.entity_key,
    candidate.hits,
    candidate.context_json,
    candidate.source,
    ''open'' AS status
FROM
(
    SELECT
        src_ip_text AS entity_key,
        min(first_seen) AS ts_first,
        max(last_seen) AS ts_last,
        sum(host_failures) AS hits,
        any(hosts_csv) AS source,
        concat(
            ''{"event_type":"batch_multi_host_ssh_bruteforce","source_ip":"'', src_ip_text,
            ''","hosts":"'', any(hosts_csv),
            ''","host_count":'', toString(host_count),
            ''","failures":'', toString(sum(host_failures)),
            ''}''
        ) AS context_json
    FROM
    (
        SELECT
            if(src_ip = 0, '''', IPv4NumToString(src_ip)) AS src_ip_text,
            countDistinct(if(host_name != '''' AND host_name != ''-'', host_name, log_source)) AS host_count,
            arrayStringConcat(groupUniqArray(8)(if(host_name != '''' AND host_name != ''-'', host_name, log_source)), '','') AS hosts_csv,
            sumIf(1, subcategory IN (''ssh_login_failure'', ''audit_user_login_failure'', ''ssh_invalid_user'', ''audit_user_err'')) AS host_failures,
            min(ts) AS first_seen,
            max(ts) AS last_seen
        FROM siem.events
        WHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
        GROUP BY src_ip_text
    )
    WHERE src_ip_text != ''''
      AND host_count >= 2
      AND host_failures >= 6
    GROUP BY src_ip_text, host_count
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = 4002
      AND ts_last >= now() - INTERVAL {WINDOW_S} SECOND
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''''
'
);
