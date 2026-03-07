# Windows Collection Foundation

Rdegon SIEM now contains a first-pass Windows normalizer for:

- Winlogbeat / Logstash-style JSON
- Windows Event XML
- Sysmon event payloads shipped as JSON or XML

Supported normalized event families:

- `windows_logon_success` (`4624`)
- `windows_logon_failure` (`4625`)
- `windows_process_create` (`4688`, Sysmon `1`)
- `windows_network_connection` (Sysmon `3`)
- `windows_user_created` (`4720`)
- `windows_user_deleted` (`4726`)
- `windows_user_added_to_privileged_group` (`4728`, `4732`, `4756`)
- `windows_scheduled_task_created` (`4698`)
- `windows_service_installed` (`7045`)
- `windows_audit_log_cleared` (`1102`)
- `windows_firewall_connection` (`5156`, `5157`)
- `windows_powershell_encoded_command`

## Recommended shipping options

1. Winlogbeat or Elastic Agent -> HTTP JSON into SIEM ingest.
2. NxLog / syslog-ng -> forward Windows Event XML or JSON payloads.
3. Sysmon + Winlogbeat -> same HTTP JSON path.

## Minimal JSON example

```json
{
  "source_type": "json",
  "message": "{\"winlog\":{\"event_id\":4625,\"channel\":\"Security\",\"computer_name\":\"win-lab-01\",\"event_data\":{\"TargetUserName\":\"Administrator\",\"IpAddress\":\"10.10.10.5\",\"IpPort\":\"49823\",\"LogonType\":\"3\"}},\"event\":{\"code\":\"4625\"},\"host\":{\"name\":\"win-lab-01\"}}",
  "source": "10.10.10.10"
}
```

## Minimal XML example

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4625</EventID>
    <Channel>Security</Channel>
    <Computer>win-lab-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="IpAddress">10.10.10.5</Data>
    <Data Name="IpPort">49823</Data>
  </EventData>
</Event>
```

## Initial Windows detections

- Windows Logon Failure Burst
- Windows Audit Log Cleared
- Windows Privileged Group Membership Changed
- Windows Suspicious PowerShell Encoded Command
- Windows Service Installed
- Windows User Created
