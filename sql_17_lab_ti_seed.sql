ALTER TABLE siem.threat_intel_iocs DELETE WHERE provider = 'Rdegon Lab TI';

INSERT INTO siem.threat_intel_iocs
(indicator_type, indicator, provider, severity, confidence, description, tags, enabled, expires_ts)
VALUES
('ip', '79.124.62.122', 'Rdegon Lab TI', 'high', 80, 'Observed repeated blocked TCP probing against the public VPN host across multiple high ports.', 'scanner,botnet,port-probe', 1, NULL),
('ip', '204.76.203.83', 'Rdegon Lab TI', 'high', 75, 'Observed repeated invalid-user SSH authentication attempts against the public jump host.', 'ssh,bruteforce,invalid-user', 1, NULL),
('ip', '103.186.0.127', 'Rdegon Lab TI', 'high', 75, 'Observed repeated invalid-user SSH authentication attempts against the public VPN host.', 'ssh,bruteforce,invalid-user', 1, NULL),
('ip', '172.234.218.34', 'Rdegon Lab TI', 'medium', 65, 'Observed unsolicited connection attempts to uncommon TCP ports on the public VPN host.', 'scanner,uncommon-port', 1, NULL),
('ip', '45.205.1.5', 'Rdegon Lab TI', 'medium', 65, 'Observed unsolicited MikroTik-style probing against TCP/8728 on the public VPN host.', 'scanner,mikrotik,management-port', 1, NULL),
('ip', '62.3.56.187', 'Rdegon Lab TI', 'high', 70, 'Observed historical multi-host brute-force behavior in the lab telemetry.', 'bruteforce,history', 1, NULL);

