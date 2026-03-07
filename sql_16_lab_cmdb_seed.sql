ALTER TABLE siem.cmdb_assets DELETE WHERE asset_id IN
(
    'asset-siem-ingest',
    'asset-siem-processing',
    'asset-siem-storage',
    'asset-siem-web',
    'asset-jump-host',
    'asset-vpn-host'
);

INSERT INTO siem.cmdb_assets
(asset_id, asset_type, hostname, ip, owner, criticality, environment, business_service, os_family, expected_ports, tags, notes, enabled)
VALUES
('asset-siem-ingest', 'server', 'siem-ingest', '192.168.1.35', 'rdegon', 'high', 'lab', 'Rdegon SIEM ingest', 'linux', '22,443,1514', 'siem,ingest,edge', 'Ingress node for JSON/syslog intake', 1),
('asset-siem-processing', 'server', 'siem-processing', '192.168.1.37', 'rdegon', 'high', 'lab', 'Rdegon SIEM processing', 'linux', '22,6379', 'siem,processing,redis', 'Normalizer and filter node', 1),
('asset-siem-storage', 'server', 'siem-storage', '192.168.1.38', 'rdegon', 'critical', 'lab', 'Rdegon SIEM storage', 'linux', '22,8123,9000', 'siem,storage,clickhouse', 'ClickHouse and correlation node', 1),
('asset-siem-web', 'server', 'siem-web', '192.168.1.39', 'rdegon', 'critical', 'lab', 'Rdegon SIEM web', 'linux', '22,443', 'siem,web,critical-asset', 'Web console node', 1),
('asset-jump-host', 'vpn', 'vpn-host-khanov', '176.108.250.215', 'rdegon', 'high', 'prod', 'Jump host', 'linux', '22', 'vpn,jump,edge', 'Public jump host with reverse access into the lab', 1),
('asset-vpn-host', 'vpn', 'vm15611031', '45.89.111.208', 'rdegon', 'high', 'prod', 'VPN gateway', 'linux', '22,443', 'vpn,edge,critical-asset', 'Public VLESS/Reality endpoint', 1);
