from __future__ import annotations

import json
import logging
import re
import shlex
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jmespath
from clickhouse_driver import Client

from .config import NormalizerSettings

logger = logging.getLogger(__name__)

SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<body>.*)$"
)
SYSLOG_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<program>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<structured>(?:-|\[[^\]]*\](?:\[[^\]]*\])*))\s*(?P<body>.*)$"
)
KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=(".*?"|\'.*?\'|[^ ]+)')
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
SSHD_ACCEPT_RE = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSHD_FAIL_RE = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSHD_SESSION_RE = re.compile(
    r"pam_unix\(sshd:session\): session (?P<state>opened|closed) for user (?P<user>\S+)",
    re.IGNORECASE,
)
SUDO_COMMAND_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*PWD=(?P<pwd>[^;]+)\s*;\s*USER=(?P<target>[^;]+)\s*;\s*COMMAND=(?P<command>.+)$"
)
SUDO_SESSION_RE = re.compile(
    r"pam_unix\(sudo:session\): session (?P<state>opened|closed) for user (?P<target>\S+)",
    re.IGNORECASE,
)
SU_SESSION_RE = re.compile(
    r"pam_unix\(su:session\): session (?P<state>opened|closed) for user (?P<target>\S+) by (?P<user>\S+)",
    re.IGNORECASE,
)
CRON_CMD_RE = re.compile(r"\((?P<user>[^)]+)\)\s+CMD\s+\((?P<command>.+)\)")
PASSWD_CHANGE_RE = re.compile(r"password changed for (?P<user>\S+)", re.IGNORECASE)
USERADD_RE = re.compile(r"new user:\s+name=(?P<user>[^,\s]+)", re.IGNORECASE)
USERDEL_RE = re.compile(r"delete user\s+'(?P<user>[^']+)'", re.IGNORECASE)
USERMOD_RE = re.compile(r"(?:add|adding)\s+'?(?P<user>[^'\s]+)'?\s+to\s+(?:group|groups?)\s+'?(?P<group>[^'\s]+)'?", re.IGNORECASE)
SYSLOG_LEVEL_MAP = {
    0: "critical",
    1: "critical",
    2: "high",
    3: "high",
    4: "medium",
    5: "low",
    6: "info",
    7: "low",
}
HIGH_RISK_EVENT_TYPES = {
    "audit_exec_as_root",
    "linux_root_ssh_login",
    "linux_reverse_shell_possible",
    "linux_authorized_keys_modified",
    "linux_ld_preload_modified",
    "linux_firewall_disabled",
    "linux_sudoers_modified",
    "linux_systemd_unit_modified",
}
MEDIUM_RISK_EVENT_TYPES = {
    "audit_user_login_failure",
    "audit_user_auth_failure",
    "linux_user_created",
    "linux_user_deleted",
    "linux_user_added_to_admin_group",
    "linux_password_changed",
    "linux_cron_modified",
    "linux_audit_config_changed",
    "linux_audit_rules_cleared",
    "linux_download_utility",
    "linux_network_tool",
    "linux_packet_capture",
    "linux_exec_from_tmp",
    "linux_system_recon",
    "linux_passwd_shadow_access",
}


@dataclass
class NormalizerRule:
    id: int
    priority: int
    source_type: str
    event_matcher_expr: str
    compiled_matcher: Optional[jmespath.parser.ParsedResult]
    compiled_mapping: Dict[str, jmespath.parser.ParsedResult]


def _clean_value(value: Any) -> str:
    return str(value or "").replace("\x1d", " ").strip()


def _is_ipv4(value: str) -> bool:
    return bool(value and IPV4_RE.match(value))


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _decode_hex(value: str) -> str:
    raw = value.strip()
    if not raw or len(raw) % 2 != 0 or not re.fullmatch(r"[0-9A-Fa-f]+", raw):
        return raw
    try:
        decoded = bytes.fromhex(raw).decode("utf-8", errors="replace").replace("\x00", " ").strip()
    except Exception:
        return raw
    return decoded or raw


def _merge_non_empty(target: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in updates.items():
        if value in (None, "", [], {}, "?"):
            continue
        target[key] = value
    return target


def _parse_key_values(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for key, value in KV_RE.findall(text):
        parsed[key] = _strip_quotes(value)
    return parsed


def _derive_outcome(values: Dict[str, str]) -> str:
    for key in ("res", "success", "result"):
        raw = values.get(key, "")
        lowered = raw.lower()
        if lowered in {"success", "yes", "ok", "opened"}:
            return "success"
        if lowered in {"failed", "failure", "no", "denied", "closed"}:
            return "failure"
    return "unknown"


def _derive_severity(program: str, event_type: str, outcome: str, default_level: str) -> str:
    if program == "sshd" and outcome == "failure":
        return "medium"
    if program == "sudo" and event_type == "sudo_command":
        return "medium"
    if event_type in HIGH_RISK_EVENT_TYPES:
        return "high"
    if event_type in MEDIUM_RISK_EVENT_TYPES:
        return "medium"
    return default_level or "info"


def _basename(value: str) -> str:
    raw = _clean_value(value).replace("\\", "/")
    return raw.rsplit("/", 1)[-1].lower()


def _extract_execve_command(values: Dict[str, str], fallback: str) -> str:
    args: List[str] = []
    for key in sorted((item for item in values if re.fullmatch(r"a\d+", item)), key=lambda item: int(item[1:])):
        candidate = _decode_hex(values.get(key, ""))
        if candidate:
            args.append(candidate)
    if args:
        return " ".join(args).strip()
    return _decode_hex(values.get("cmd", "")) or _decode_hex(values.get("proctitle", "")) or fallback


def _extract_target_user(command_line: str) -> str:
    try:
        tokens = shlex.split(command_line)
    except Exception:
        tokens = command_line.split()
    for token in reversed(tokens):
        if token.startswith("-"):
            continue
        return token.strip("'\"")
    return ""


def _set_event_shape(result: Dict[str, Any], *, category: str, action: str, event_type: str) -> None:
    result["event.category"] = category
    result["event.action"] = action
    result["event.type"] = event_type


def _classify_file_path_event(result: Dict[str, Any], path_value: str) -> None:
    path_lower = _clean_value(path_value).lower()
    if not path_lower:
        return
    if path_lower.endswith(".ssh/authorized_keys"):
        _set_event_shape(result, category="persistence", action="file_modify", event_type="linux_authorized_keys_modified")
    elif path_lower == "/etc/sudoers" or path_lower.startswith("/etc/sudoers.d/"):
        _set_event_shape(result, category="privilege", action="sudoers_modify", event_type="linux_sudoers_modified")
    elif path_lower in {"/etc/passwd", "/etc/shadow"}:
        _set_event_shape(result, category="credential", action="file_modify", event_type="linux_passwd_shadow_access")
    elif path_lower.startswith("/etc/cron") or path_lower.endswith("/crontab") or path_lower.startswith("/var/spool/cron"):
        _set_event_shape(result, category="persistence", action="scheduled_task_modify", event_type="linux_cron_modified")
    elif path_lower.startswith("/etc/systemd/system") or path_lower.startswith("/usr/lib/systemd/system") or path_lower.startswith("/lib/systemd/system"):
        _set_event_shape(result, category="persistence", action="service_unit_modify", event_type="linux_systemd_unit_modified")
    elif path_lower == "/etc/ld.so.preload":
        _set_event_shape(result, category="defense_evasion", action="preload_modify", event_type="linux_ld_preload_modified")
    elif path_lower.startswith("/etc/audit/"):
        _set_event_shape(result, category="defense_evasion", action="audit_config_change", event_type="linux_audit_config_changed")
    elif path_lower.startswith("/etc/ufw") or path_lower.startswith("/etc/firewalld"):
        _set_event_shape(result, category="defense_evasion", action="firewall_modify", event_type="linux_firewall_modified")


def _classify_execve_activity(result: Dict[str, Any]) -> None:
    command_line = _clean_value(result.get("process.command_line", ""))
    command_lower = command_line.lower()
    executable = _basename(result.get("process.executable", "") or result.get("process.name", ""))
    target_user = _extract_target_user(command_line)
    if target_user and not result.get("user.target.name"):
        result["user.target.name"] = target_user

    if executable in {"useradd", "adduser"}:
        _set_event_shape(result, category="identity", action="account_create", event_type="linux_user_created")
    elif executable in {"userdel", "deluser"}:
        _set_event_shape(result, category="identity", action="account_delete", event_type="linux_user_deleted")
    elif executable == "usermod":
        if any(group in command_lower for group in (" sudo", " wheel", "-g sudo", "-g wheel", "-ag sudo", "-ag wheel")):
            _set_event_shape(result, category="privilege", action="group_modify", event_type="linux_user_added_to_admin_group")
        else:
            _set_event_shape(result, category="identity", action="account_modify", event_type="linux_user_modified")
    elif executable == "passwd":
        _set_event_shape(result, category="credential", action="password_change", event_type="linux_password_changed")
    elif executable in {"crontab", "at"} or "/etc/cron" in command_lower:
        _set_event_shape(result, category="persistence", action="scheduled_task_modify", event_type="linux_cron_modified")
    elif executable == "systemctl":
        if " enable " in f" {command_lower} ":
            _set_event_shape(result, category="persistence", action="service_enable", event_type="linux_systemd_service_enabled")
        elif " disable " in f" {command_lower} ":
            _set_event_shape(result, category="defense_evasion", action="service_disable", event_type="linux_systemd_service_disabled")
        elif " start " in f" {command_lower} " or " restart " in f" {command_lower} ":
            _set_event_shape(result, category="execution", action="service_start", event_type="linux_systemd_service_started")
        elif " stop " in f" {command_lower} ":
            _set_event_shape(result, category="impact", action="service_stop", event_type="linux_systemd_service_stopped")
    elif executable in {"auditctl", "augenrules"} or "audit.rules" in command_lower:
        if " -d" in command_lower or " -D" in command_line:
            _set_event_shape(result, category="defense_evasion", action="audit_rules_clear", event_type="linux_audit_rules_cleared")
        else:
            _set_event_shape(result, category="defense_evasion", action="audit_config_change", event_type="linux_audit_config_changed")
    elif executable in {"iptables", "ufw", "firewall-cmd"} or "firewalld" in command_lower:
        if any(token in command_lower for token in ("disable", "stop", "flush", " -f")):
            _set_event_shape(result, category="defense_evasion", action="firewall_disable", event_type="linux_firewall_disabled")
        else:
            _set_event_shape(result, category="defense_evasion", action="firewall_modify", event_type="linux_firewall_modified")
    elif executable in {"tar", "zip", "gzip", "bzip2", "xz", "7z"}:
        _set_event_shape(result, category="exfiltration", action="archive", event_type="linux_data_compressed")
    elif executable in {"curl", "wget"}:
        _set_event_shape(result, category="command_and_control", action="download", event_type="linux_download_utility")
    elif executable in {"nc", "ncat", "socat"}:
        _set_event_shape(result, category="command_and_control", action="network_tool", event_type="linux_network_tool")
    elif executable in {"tcpdump", "tshark"}:
        _set_event_shape(result, category="discovery", action="sniff", event_type="linux_packet_capture")
    elif executable in {"setcap", "setfattr"}:
        _set_event_shape(result, category="privilege", action="capability_modify", event_type="linux_file_capability_modified")
    elif executable == "chmod" and (" u+s" in f" {command_lower} " or " g+s" in f" {command_lower} " or " 4755 " in f" {command_lower} "):
        _set_event_shape(result, category="privilege", action="setuid_modify", event_type="linux_setuid_bit_modified")

    if any(token in command_lower for token in ("bash -i", "/dev/tcp/", "nc -e", "ncat -e", "mkfifo ", "socat exec", "python -c", "perl -e", "php -r")):
        _set_event_shape(result, category="command_and_control", action="reverse_shell", event_type="linux_reverse_shell_possible")
    elif any(token in command_lower for token in ("whoami", "uname", "hostnamectl", "ip a", "ifconfig", "netstat", "ss -", "lsof -i", "cat /etc/passwd", "getent passwd", "last ", "w ", "who ")):
        _set_event_shape(result, category="discovery", action="recon", event_type="linux_system_recon")
    elif "/tmp/" in command_lower:
        _set_event_shape(result, category="execution", action="exec_tmp", event_type="linux_exec_from_tmp")
    elif "authorized_keys" in command_lower:
        _set_event_shape(result, category="persistence", action="authorized_keys_modify", event_type="linux_authorized_keys_modified")
    elif any(token in command_lower for token in ("/etc/passwd", "/etc/shadow")):
        _set_event_shape(result, category="credential", action="credential_file_access", event_type="linux_passwd_shadow_access")
    elif "ld.so.preload" in command_lower:
        _set_event_shape(result, category="defense_evasion", action="preload_modify", event_type="linux_ld_preload_modified")


def _parse_auditd(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    values = _parse_key_values(body)
    inner_msg = values.get("msg", "")
    if "=" in inner_msg:
        _merge_non_empty(values, _parse_key_values(inner_msg))

    event_type_raw = values.get("type", "UNKNOWN").upper()
    outcome = _derive_outcome(values)
    acct = values.get("acct", "")
    addr = values.get("addr", "")
    exe = values.get("exe", "")
    command_hex = values.get("cmd", "")
    proctitle_hex = values.get("proctitle", "")
    audit_key = values.get("key", "")
    file_path = values.get("name", "")
    cwd = values.get("cwd", "")
    command_line = _extract_execve_command(values, _decode_hex(command_hex) or _decode_hex(proctitle_hex))

    event_category = "audit"
    event_action = "audit"
    event_type = f"audit_{event_type_raw.lower()}"

    if event_type_raw in {"USER_AUTH", "USER_ACCT", "USER_LOGIN"}:
        event_category = "authentication"
        event_action = "authentication" if event_type_raw != "USER_LOGIN" else "login"
        if outcome in {"success", "failure"}:
            event_type = f"audit_{event_type_raw.lower()}_{outcome}"
    elif event_type_raw in {"USER_START", "USER_END", "CRED_ACQ", "CRED_DISP", "CRED_REFR"}:
        event_category = "session"
        event_action = "session"
        if outcome in {"success", "failure"}:
            event_type = f"audit_{event_type_raw.lower()}_{outcome}"
    elif event_type_raw == "USER_CMD":
        event_category = "privilege"
        event_action = "command"
        event_type = "audit_user_command"
    elif event_type_raw in {"EXECVE", "SYSCALL", "PROCTITLE", "PATH", "CWD"}:
        event_category = "process"
        event_action = "execute"
        if audit_key == "exec_as_root":
            event_category = "privilege"
            event_action = "execute_as_root"
            event_type = "audit_exec_as_root"
        else:
            event_type = f"audit_{event_type_raw.lower()}"

    result = {
        "event.provider": "linux.auditd",
        "event.category": event_category,
        "event.action": event_action,
        "event.type": event_type,
        "event.outcome": outcome,
        "audit.type": event_type_raw,
        "audit.id": values.get("msg", ""),
        "audit.key": audit_key,
        "session.id": values.get("ses", ""),
        "user.name": acct,
        "user.id": values.get("uid", ""),
        "user.audit.name": values.get("AUID", "") or values.get("auid", ""),
        "user.target.name": "",
        "source.ip": addr if _is_ipv4(addr) else "",
        "source.port": values.get("src", ""),
        "process.executable": exe,
        "process.name": values.get("comm", "") or base.get("process.name", ""),
        "process.command_line": command_line,
        "process.working_directory": cwd,
        "process.tty": values.get("terminal", "") or values.get("tty", ""),
        "file.path": file_path,
        "file.mode": values.get("mode", ""),
        "file.type": values.get("nametype", ""),
        "host.name": values.get("hostname", "") or base.get("host.name", ""),
    }
    if event_type_raw == "PATH":
        _classify_file_path_event(result, file_path)
    if event_type_raw in {"EXECVE", "SYSCALL", "PROCTITLE"}:
        _classify_execve_activity(result)
    result["event.severity"] = _derive_severity("auditd", result["event.type"], outcome, str(base.get("log.level", "info")))
    return result


def _parse_sshd(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    accepted = SSHD_ACCEPT_RE.search(body)
    if accepted:
        return {
            "event.provider": "linux.sshd",
            "event.category": "authentication",
            "event.action": "authentication_success",
            "event.type": "linux_root_ssh_login" if accepted.group("user") == "root" else "ssh_login_success",
            "event.outcome": "success",
            "event.severity": "high" if accepted.group("user") == "root" else "info",
            "user.name": accepted.group("user"),
            "source.ip": accepted.group("ip"),
            "source.port": accepted.group("port"),
            "network.transport": "tcp",
            "auth.method": accepted.group("method").lower(),
        }

    failed = SSHD_FAIL_RE.search(body)
    if failed:
        return {
            "event.provider": "linux.sshd",
            "event.category": "authentication",
            "event.action": "authentication_failed",
            "event.type": "ssh_login_failure",
            "event.outcome": "failure",
            "event.severity": "medium",
            "user.name": failed.group("user"),
            "source.ip": failed.group("ip"),
            "source.port": failed.group("port"),
            "network.transport": "tcp",
            "auth.method": failed.group("method").lower(),
        }

    session = SSHD_SESSION_RE.search(body)
    if session:
        state = session.group("state").lower()
        return {
            "event.provider": "linux.sshd",
            "event.category": "session",
            "event.action": f"session_{state}",
            "event.type": f"ssh_session_{state}",
            "event.outcome": "success",
            "event.severity": "info",
            "user.name": session.group("user"),
        }

    return {
        "event.provider": "linux.sshd",
        "event.category": "authentication",
        "event.type": "ssh_event",
        "event.action": "observe",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_sudo(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    command = SUDO_COMMAND_RE.search(body)
    if command:
        target_user = command.group("target").strip()
        severity = "high" if target_user == "root" else "medium"
        return {
            "event.provider": "linux.sudo",
            "event.category": "privilege",
            "event.action": "command",
            "event.type": "sudo_command",
            "event.outcome": "success",
            "event.severity": severity,
            "user.name": command.group("user").strip(),
            "user.target.name": target_user,
            "process.command_line": command.group("command").strip(),
            "process.working_directory": command.group("pwd").strip(),
        }

    session = SUDO_SESSION_RE.search(body)
    if session:
        state = session.group("state").lower()
        return {
            "event.provider": "linux.sudo",
            "event.category": "session",
            "event.action": f"session_{state}",
            "event.type": f"sudo_session_{state}",
            "event.outcome": "success",
            "event.severity": "info",
            "user.target.name": session.group("target"),
        }

    return {
        "event.provider": "linux.sudo",
        "event.category": "privilege",
        "event.type": "sudo_event",
        "event.action": "observe",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_su(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    session = SU_SESSION_RE.search(body)
    if session:
        state = session.group("state").lower()
        return {
            "event.provider": "linux.su",
            "event.category": "privilege",
            "event.action": f"session_{state}",
            "event.type": f"linux_su_session_{state}",
            "event.outcome": "success",
            "event.severity": "medium",
            "user.name": session.group("user"),
            "user.target.name": session.group("target"),
        }
    return {
        "event.provider": "linux.su",
        "event.category": "privilege",
        "event.action": "observe",
        "event.type": "linux_su_event",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_cron(program: str, body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    command = CRON_CMD_RE.search(body)
    if command:
        return {
            "event.provider": f"linux.{program}",
            "event.category": "persistence",
            "event.action": "scheduled_task_execute",
            "event.type": "linux_cron_command",
            "event.outcome": "success",
            "event.severity": "low",
            "user.name": command.group("user").strip(),
            "process.command_line": command.group("command").strip(),
        }
    return {
        "event.provider": f"linux.{program}",
        "event.category": "persistence",
        "event.action": "observe",
        "event.type": "linux_cron_event",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_account_tools(program: str, body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    if program == "passwd":
        change = PASSWD_CHANGE_RE.search(body)
        return {
            "event.provider": "linux.passwd",
            "event.category": "credential",
            "event.action": "password_change",
            "event.type": "linux_password_changed",
            "event.outcome": "success" if change else "unknown",
            "event.severity": "medium",
            "user.target.name": change.group("user") if change else "",
        }

    if program == "useradd":
        created = USERADD_RE.search(body)
        return {
            "event.provider": "linux.useradd",
            "event.category": "identity",
            "event.action": "account_create",
            "event.type": "linux_user_created",
            "event.outcome": "success" if created else "unknown",
            "event.severity": "medium",
            "user.target.name": created.group("user") if created else "",
        }

    if program == "userdel":
        deleted = USERDEL_RE.search(body)
        return {
            "event.provider": "linux.userdel",
            "event.category": "identity",
            "event.action": "account_delete",
            "event.type": "linux_user_deleted",
            "event.outcome": "success" if deleted else "unknown",
            "event.severity": "medium",
            "user.target.name": deleted.group("user") if deleted else "",
        }

    if program == "usermod":
        modified = USERMOD_RE.search(body)
        event_type = "linux_user_added_to_admin_group" if modified and modified.group("group").lower() in {"sudo", "wheel"} else "linux_user_modified"
        return {
            "event.provider": "linux.usermod",
            "event.category": "privilege" if event_type == "linux_user_added_to_admin_group" else "identity",
            "event.action": "group_modify" if event_type == "linux_user_added_to_admin_group" else "account_modify",
            "event.type": event_type,
            "event.outcome": "success" if modified else "unknown",
            "event.severity": "medium",
            "user.target.name": modified.group("user") if modified else "",
            "group.name": modified.group("group") if modified else "",
        }

    return {
        "event.provider": f"linux.{program}",
        "event.category": "identity",
        "event.action": "observe",
        "event.type": f"linux_{program}_event",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_linux_syslog(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    message = _clean_value(raw_event.get("message"))
    source_ip = _clean_value(raw_event.get("source"))
    match = SYSLOG_RE.match(message)
    match_rfc5424 = SYSLOG_RFC5424_RE.match(message)

    enriched: Dict[str, Any] = {
        "event.original": message,
        "log_source": source_ip,
        "source.ip": source_ip if _is_ipv4(source_ip) else "",
        "event.provider": "linux.syslog",
        "event.category": "syslog",
        "event.type": "syslog",
        "event.action": "observe",
        "event.severity": "info",
    }

    body = message
    program = ""
    if match_rfc5424:
        body = _clean_value(match_rfc5424.group("body"))
        program = _clean_value(match_rfc5424.group("program")).lower()
        pri = int(match_rfc5424.group("pri") or 13)
        severity_code = pri % 8
        level = SYSLOG_LEVEL_MAP.get(severity_code, "info")
        host_name = _clean_value(match_rfc5424.group("host"))
        process_pid = _clean_value(match_rfc5424.group("pid"))
        if process_pid == "-":
            process_pid = ""
        _merge_non_empty(
            enriched,
            {
                "log.level": level,
                "host.name": host_name,
                "log_source": host_name or source_ip,
                "process.name": "" if program == "-" else program,
                "process.pid": process_pid,
                "event.provider": f"linux.{program}" if program and program != "-" else "linux.syslog",
            },
        )
        enriched["event.severity"] = level
    elif match:
        body = _clean_value(match.group("body"))
        program = _clean_value(match.group("program")).lower()
        pri = int(match.group("pri") or 13)
        severity_code = pri % 8
        level = SYSLOG_LEVEL_MAP.get(severity_code, "info")
        host_name = _clean_value(match.group("host"))
        _merge_non_empty(
            enriched,
            {
                "log.level": level,
                "host.name": host_name,
                "log_source": host_name or source_ip,
                "process.name": program,
                "process.pid": _clean_value(match.group("pid")),
                "event.provider": f"linux.{program}" if program else "linux.syslog",
            },
        )
        enriched["event.severity"] = level

    if program == "auditd" or " auditd:" in message.lower():
        return _merge_non_empty(enriched, _parse_auditd(body, enriched))
    if program == "sshd":
        return _merge_non_empty(enriched, _parse_sshd(body, enriched))
    if program == "sudo":
        return _merge_non_empty(enriched, _parse_sudo(body, enriched))
    if program == "su":
        return _merge_non_empty(enriched, _parse_su(body, enriched))
    if program in {"cron", "crond"}:
        return _merge_non_empty(enriched, _parse_cron(program, body, enriched))
    if program in {"passwd", "useradd", "userdel", "usermod"}:
        return _merge_non_empty(enriched, _parse_account_tools(program, body, enriched))

    return enriched


def _enrich_raw_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(raw_event)
    source_type = _clean_value(raw_event.get("source_type")).lower()
    if source_type == "syslog" or _clean_value(raw_event.get("message")).startswith("<"):
        _merge_non_empty(enriched, _parse_linux_syslog(raw_event))
    return enriched


def load_rules(settings: NormalizerSettings) -> List[NormalizerRule]:
    client = Client(
        host=settings.ch_host,
        port=settings.ch_port,
        user=settings.ch_user,
        password=settings.ch_password,
        database=settings.ch_db,
        send_receive_timeout=settings.ch_timeout_secs,
    )
    rows = client.execute(
        """
        SELECT id, priority, source_type, event_matcher, uem_mapping
        FROM siem.normalizer_rules
        WHERE enabled = 1
        ORDER BY priority ASC, id ASC
        """
    )
    rules: List[NormalizerRule] = []
    for rule_id, priority, source_type, event_matcher, uem_mapping_str in rows:
        try:
            mapping_dict = json.loads(uem_mapping_str)
            if not isinstance(mapping_dict, dict):
                raise ValueError("uem_mapping must be a JSON object")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to parse uem_mapping JSON", extra={"extra": {"rule_id": rule_id, "error": str(exc)}})
            continue

        compiled_matcher: Optional[jmespath.parser.ParsedResult] = None
        if event_matcher and str(event_matcher).strip():
            try:
                compiled_matcher = jmespath.compile(event_matcher)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to compile normalizer matcher", extra={"extra": {"rule_id": rule_id, "matcher": event_matcher, "error": str(exc)}})
                continue

        compiled_mapping: Dict[str, jmespath.parser.ParsedResult] = {}
        for uem_field, expr in mapping_dict.items():
            try:
                compiled_mapping[uem_field] = jmespath.compile(expr)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to compile JMESPath expression in uem_mapping", extra={"extra": {"rule_id": rule_id, "uem_field": uem_field, "expr": expr, "error": str(exc)}})

        rules.append(
            NormalizerRule(
                id=rule_id,
                priority=priority,
                source_type=str(source_type or "").strip(),
                event_matcher_expr=event_matcher,
                compiled_matcher=compiled_matcher,
                compiled_mapping=compiled_mapping,
            )
        )

    logger.info("Loaded normalizer rules", extra={"extra": {"count": len(rules)}})
    return rules


def _source_type_matches(rule: NormalizerRule, raw_event: Dict[str, Any]) -> bool:
    source_type = str(raw_event.get("source_type", "") or "").strip()
    expected = rule.source_type.lower()
    if expected in {"", "*", "generic", "any"}:
        return True
    return source_type.lower() == expected


def _matcher_matches(rule: NormalizerRule, raw_event: Dict[str, Any]) -> bool:
    if rule.compiled_matcher is None:
        return True
    try:
        return bool(rule.compiled_matcher.search(raw_event))
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to evaluate normalizer matcher", extra={"extra": {"rule_id": rule.id, "matcher": rule.event_matcher_expr, "error": str(exc)}})
        return False


def _build_uem(rule: Optional[NormalizerRule], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    uem: Dict[str, Any] = {}
    compiled_mapping = rule.compiled_mapping if rule else {}

    for uem_field, compiled_expr in compiled_mapping.items():
        try:
            value = compiled_expr.search(raw_event)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to apply JMESPath mapping", extra={"extra": {"rule_id": rule.id if rule else "builtin", "uem_field": uem_field, "error": str(exc)}})
            value = None
        if value not in (None, "", [], {}):
            uem[uem_field] = value

    for key, value in raw_event.items():
        if "." in str(key) or str(key) in {"message", "severity", "log_source", "source_type", "source"}:
            if value not in (None, "", [], {}):
                uem[str(key)] = value

    if "event.provider" not in uem or uem.get("event.provider") in (None, ""):
        uem["event.provider"] = raw_event.get("source_type", "") or ""
    if "event.original" not in uem or uem.get("event.original") in (None, ""):
        uem["event.original"] = raw_event.get("message", "") or str(raw_event)
    if "host.name" not in uem or uem.get("host.name") in (None, ""):
        uem["host.name"] = raw_event.get("source", "") or raw_event.get("log_source", "") or ""
    if "log_source" not in uem or uem.get("log_source") in (None, ""):
        uem["log_source"] = raw_event.get("host.name", "") or raw_event.get("source", "") or raw_event.get("log_source", "") or ""
    elif raw_event.get("host.name") and raw_event.get("log_source") == raw_event.get("source"):
        uem["log_source"] = raw_event.get("host.name") or uem.get("log_source")
    return uem


def apply_rules(rules: List[NormalizerRule], raw_event: Dict[str, Any]) -> Dict[str, Any] | None:
    enriched_event = _enrich_raw_event(raw_event)
    for rule in rules:
        if not _source_type_matches(rule, enriched_event):
            continue
        if not _matcher_matches(rule, enriched_event):
            continue
        return _build_uem(rule, enriched_event)

    if enriched_event.get("event.provider") or enriched_event.get("event.category"):
        return _build_uem(None, enriched_event)
    return None
