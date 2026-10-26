"""Pure per-user service specifications. Registration belongs to the installer."""
from __future__ import annotations

import os
from pathlib import Path
import platform as platform_module
import plistlib
import subprocess
from xml.sax.saxutils import escape

from .errors import HostError


def _argv(command) -> list[str]:
    if not isinstance(command, (list, tuple)) or not 1 <= len(command) <= 100 or any(type(item) is not str or not item or len(item) > 4096 or any(char in item for char in "\x00\r\n") for item in command):
        raise HostError("service-command-invalid")
    return list(command)


def service_spec(command: list[str], state_dir: Path, *, platform: str | None = None) -> dict:
    """Return UTF-8 text and fixed argv; this function changes no OS state.

    Every action argv contains the final absolute path, without placeholders.
    Installer creates ``path`` with private permissions before registration.
    ``state_dir`` is used as the working directory, not an unlock/key argument.
    """
    command = _argv(command)
    if not isinstance(state_dir, Path) or not state_dir.is_absolute():
        raise HostError("service-state-invalid")
    selected = (platform or platform_module.system()).lower()
    supported = selected in {"linux", "darwin", "macos", "windows"}
    response = {"platform": selected, "supported": supported, "filename": None, "path": None,
                "content": None, "encoding": "utf-8", "enable_argv": [], "disable_argv": [], "status_argv": [],
                "reload_argv": [], "unattended_requires": "verified-observation-keyring", "native_verified": False}
    if not supported:
        return response
    if selected == "linux":
        def quote(value):
            return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'
        path = Path.home() / ".config/systemd/user/leakguard-buddy.service"
        response.update(filename=path.name, path=str(path), content=(
            "[Unit]\nDescription=LeakGuard Buddy local companion\nAfter=default.target\n\n[Service]\nType=simple\n"
            + "ExecStart=" + " ".join(quote(value) for value in command) + "\n"
            + "WorkingDirectory=" + quote(str(state_dir)) + "\n"
            + "Environment=" + quote("LEAKGUARD_STATE_DIR=" + str(state_dir)) + "\n"
            + "Restart=on-failure\nRestartSec=10\nUMask=0077\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=default.target\n"),
            reload_argv=["systemctl", "--user", "daemon-reload"],
            enable_argv=["systemctl", "--user", "enable", "--now", path.name],
            disable_argv=["systemctl", "--user", "disable", "--now", path.name],
            status_argv=["systemctl", "--user", "is-active", path.name])
    elif selected in {"darwin", "macos"}:
        label = "io.leakguard.buddy"
        path = Path.home() / "Library/LaunchAgents" / (label + ".plist")
        domain = "gui/" + str(os.getuid()) if hasattr(os, "getuid") else "gui/501"
        data = {"Label": label, "ProgramArguments": command, "WorkingDirectory": str(state_dir),
                "EnvironmentVariables": {"LEAKGUARD_STATE_DIR": str(state_dir)},
                "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 10,
                "Umask": 0o077, "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}
        response.update(filename=path.name, path=str(path), content=plistlib.dumps(data).decode(),
            enable_argv=["launchctl", "bootstrap", domain, str(path)],
            disable_argv=["launchctl", "bootout", domain + "/" + label],
            status_argv=["launchctl", "print", domain + "/" + label])
    else:
        path = state_dir / "leakguard-buddy-task.xml"
        arguments = subprocess.list2cmdline(command[1:])
        content = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>'
            '<Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>'
            '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
            '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>'
            '<Actions Context="Author"><Exec><Command>' + escape(command[0]) + '</Command><Arguments>'
            + escape(arguments) + '</Arguments><WorkingDirectory>' + escape(str(state_dir)) + '</WorkingDirectory></Exec></Actions></Task>')
        response.update(filename=path.name, path=str(path), content=content,
            enable_argv=["schtasks.exe", "/Create", "/TN", "LeakGuardBuddy", "/XML", str(path), "/F"],
            disable_argv=["schtasks.exe", "/Delete", "/TN", "LeakGuardBuddy", "/F"],
            status_argv=["schtasks.exe", "/Query", "/TN", "LeakGuardBuddy", "/FO", "LIST"])
    return response
