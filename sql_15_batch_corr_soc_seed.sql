ALTER TABLE siem.correlation_rules_batch DELETE WHERE id IN (4003, 4004, 4005);

INSERT INTO siem.correlation_rules_batch
(id, name, description, enabled, severity, window_s, sql_template)
VALUES
(
    4003,
    'Internet Multi-Port Probe',
    'Creates a batch alert when the same source hits multiple destination ports across monitored hosts within the time window.',
    1,
    'high',
    900,
    '
INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now() AS ts,
    generateUUIDv4() AS alert_id,
    4003 AS rule_id,
    ''Internet Multi-Port Probe'' AS rule_name,
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
        min(ts_first) AS ts_first,
        max(ts_last) AS ts_last,
        sum(hits) AS hits,
        any(targets_csv) AS source,
        concat(
            ''{"event_type":"batch_multi_port_probe","source_ip":"'', src_ip_text,
            ''","ports":"'', any(ports_csv),
            ''","port_count":'', toString(any(port_count)),
            ''","targets":"'', any(targets_csv),
            ''","hits":'', toString(sum(hits)),
            ''}'' 
        ) AS context_json
    FROM
    (
        SELECT
            if(src_ip = 0, '''', IPv4NumToString(src_ip)) AS src_ip_text,
            count() AS hits,
            min(ts) AS ts_first,
            max(ts) AS ts_last,
            countDistinct(
                if(
                    dst_port = 0 AND subcategory IN (''ssh_login_success'', ''ssh_login_failure'', ''ssh_invalid_user'', ''linux_root_ssh_login''),
                    22,
                    dst_port
                )
            ) AS port_count,
            arrayStringConcat(groupUniqArray(8)(toString(if(dst_port = 0 AND subcategory IN (''ssh_login_success'', ''ssh_login_failure'', ''ssh_invalid_user'', ''linux_root_ssh_login''), 22, dst_port))), '','') AS ports_csv,
            arrayStringConcat(groupUniqArray(8)(if(host_name != '''' AND host_name != ''-'', host_name, log_source)), '','') AS targets_csv
        FROM siem.events
        WHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
          AND (
                subcategory = ''linux_firewall_blocked''
                OR subcategory IN (''ssh_login_success'', ''ssh_login_failure'', ''ssh_invalid_user'', ''linux_root_ssh_login'')
              )
        GROUP BY src_ip_text
    )
    WHERE src_ip_text != ''''
      AND port_count >= 4
      AND hits >= 12
    GROUP BY src_ip_text
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = 4003
      AND ts_last >= now() - INTERVAL {WINDOW_S} SECOND
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''''
'
),
(
    4004,
    'Linux Recon Followed By Privileged Execution',
    'Creates a batch alert when reconnaissance-like activity is followed by privileged execution or control changes on the same host.',
    1,
    'high',
    900,
    '
INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now() AS ts,
    generateUUIDv4() AS alert_id,
    4004 AS rule_id,
    ''Linux Recon Followed By Privileged Execution'' AS rule_name,
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
        source_name AS entity_key,
        source_name AS source,
        min(recon_first) AS ts_first,
        max(priv_last) AS ts_last,
        sum(recon_hits) + sum(priv_hits) AS hits,
        concat(
            ''{"event_type":"batch_recon_then_privileged_execution","source":"'', source_name,
            ''","recon_hits":'', toString(sum(recon_hits)),
            ''","privileged_hits":'', toString(sum(priv_hits)),
            ''}'' 
        ) AS context_json
    FROM
    (
        SELECT
            if(host_name != '''' AND host_name != ''-'', host_name, log_source) AS source_name,
            countIf(subcategory = ''linux_system_recon'') AS recon_hits,
            minIf(ts, subcategory = ''linux_system_recon'') AS recon_first,
            countIf(subcategory IN (''audit_exec_as_root'', ''sudo_command'', ''linux_sudoers_modified'', ''linux_ld_preload_modified'', ''linux_systemd_service_disabled'')) AS priv_hits,
            maxIf(ts, subcategory IN (''audit_exec_as_root'', ''sudo_command'', ''linux_sudoers_modified'', ''linux_ld_preload_modified'', ''linux_systemd_service_disabled'')) AS priv_last
        FROM siem.events
        WHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
        GROUP BY source_name
    )
    WHERE source_name != ''''
      AND recon_hits >= 2
      AND priv_hits >= 1
      AND priv_last >= recon_first
    GROUP BY source_name
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = 4004
      AND ts_last >= now() - INTERVAL {WINDOW_S} SECOND
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''''
'
),
(
    4005,
    'Threat Intel Hit On Critical Asset',
    'Creates a batch alert when a threat intel indicator is observed on an asset marked as high or critical in CMDB.',
    1,
    'critical',
    1800,
    '
INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now() AS ts,
    generateUUIDv4() AS alert_id,
    4005 AS rule_id,
    ''Threat Intel Hit On Critical Asset'' AS rule_name,
    candidate.severity,
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
        concat(source_name, ''|'', ti_indicator) AS entity_key,
        source_name AS source,
        min(ts) AS ts_first,
        max(ts) AS ts_last,
        count() AS hits,
        if(max(lower(ti_severity)) = ''critical'', ''critical'', ''high'') AS severity,
        concat(
            ''{"event_type":"batch_ti_hit_on_critical_asset","source":"'', source_name,
            ''","asset_id":"'', any(asset_id),
            ''","asset_criticality":"'', any(asset_criticality),
            ''","ti_indicator":"'', any(ti_indicator),
            ''","ti_provider":"'', any(ti_provider),
            ''","hits":'', toString(count()),
            ''}'' 
        ) AS context_json
    FROM
    (
        SELECT
            if(host_name != '''' AND host_name != ''-'', host_name, log_source) AS source_name,
            asset_id,
            lower(asset_criticality) AS asset_criticality,
            ti_indicator,
            ti_provider,
            lower(ti_severity) AS ti_severity,
            ts
        FROM siem.events
        WHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
          AND ti_indicator != ''''
          AND asset_id != ''''
          AND lower(asset_criticality) IN (''high'', ''critical'')
    )
    GROUP BY source_name, ti_indicator
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = 4005
      AND ts_last >= now() - INTERVAL {WINDOW_S} SECOND
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''''
'
);
