from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import subprocess
from pathlib import Path


def _signing_team(path: Path) -> str:
    result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, text=True, check=False)
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith("TeamIdentifier="):
            value = line.partition("=")[2].strip()
            return "" if value.lower() in {"not set", "none", "-"} else value
    return ""


def _signing_identifier(path: Path) -> str:
    result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, text=True, check=False)
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith("Identifier="): return line.partition("=")[2].strip()
    return ""


def _uninstall() -> int:
    if os.geteuid() == 0: raise SystemExit("Run uninstall as the logged-in graphical user, not with sudo.")
    plist=Path.home()/"Library/LaunchAgents/com.macos-security-audit-agent.clickfix-guard.plist"
    domain=f"gui/{os.getuid()}"
    subprocess.run(["/bin/launchctl","bootout",domain,str(plist)],capture_output=True,check=False)
    if plist.exists(): plist.unlink()
    destination=Path.home()/"Library/Application Support/MacAuditAgent/ClickFixGuard/MSAAClickFixGuardAgent.app"
    if destination.exists(): shutil.rmtree(destination)
    print("Uninstalled the per-user ClickFix Guard app and LaunchAgent. Evidence and logs were retained.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Install MSAA ClickFix Guard in the current graphical user session.")
    parser.add_argument("--agent-app", type=Path)
    parser.add_argument("--msaa-app", type=Path)
    parser.add_argument("--profile", choices=("AUDIT", "WARN", "PROTECT", "HIGH_ASSURANCE"), default="WARN")
    parser.add_argument("--development-demo", action="store_true", help="Allow an ad-hoc signed, local-only proof-of-concept build.")
    parser.add_argument("--acknowledge-unsigned-demo", action="store_true", help="Acknowledge that the demo is not Developer ID signed or notarized.")
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()
    if args.uninstall: return _uninstall()
    if os.geteuid() == 0: raise SystemExit("Do not install the ClickFix Guard LaunchAgent as root. Run this command as the logged-in graphical user.")
    if args.agent_app is None: raise SystemExit("--agent-app is required")
    if args.development_demo and not args.acknowledge_unsigned_demo: raise SystemExit("Development demo installation requires --acknowledge-unsigned-demo")
    agent = args.agent_app.resolve(); agent_team = _signing_team(agent)
    if args.development_demo:
        if _signing_identifier(agent)!="com.macos-security-audit-agent.clickfix-guard": raise SystemExit("CFX001_SENSOR_NOT_INSTALLED: unexpected demo bundle signing identifier")
        if agent_team: raise SystemExit("Development demo mode accepts only the local ad-hoc build; use production installation for Team-signed artifacts")
        msaa_team=""
    else:
        if args.msaa_app is None: raise SystemExit("--msaa-app is required for production installation")
        msaa = args.msaa_app.resolve(); msaa_team = _signing_team(msaa)
        if not agent_team or agent_team != msaa_team: raise SystemExit("CFX012_XPC_AUTHENTICATION_FAILED: agent and MSAA signing Team Identifiers do not match")
    verify = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "--deep", str(agent)], check=False)
    if verify.returncode: raise SystemExit("CFX001_SENSOR_NOT_INSTALLED: agent signature verification failed")
    destination = Path.home() / "Library/Application Support/MacAuditAgent/ClickFixGuard/MSAAClickFixGuardAgent.app"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists(): shutil.rmtree(destination)
    shutil.copytree(agent, destination)
    template = Path(__file__).resolve().parents[1] / "packaging/clickfix/com.macos-security-audit-agent.clickfix-guard.plist.template"
    text = template.read_text(encoding="utf-8").replace("__AGENT_PATH__", str(destination / "Contents/MacOS/MSAAClickFixGuardAgent")).replace("__PROFILE__", args.profile).replace("__TEAM_IDENTIFIER__", agent_team).replace("__DEVELOPER_MODE__", "1" if args.development_demo else "0").replace("__LOG_DIR__", str(destination.parent))
    payload = plistlib.loads(text.encode("utf-8"))
    launch_agents = Path.home() / "Library/LaunchAgents"; launch_agents.mkdir(parents=True, exist_ok=True)
    plist = launch_agents / "com.macos-security-audit-agent.clickfix-guard.plist"
    plist.write_bytes(plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)); os.chmod(plist, 0o600)
    domain = f"gui/{os.getuid()}"
    subprocess.run(["/bin/launchctl", "bootout", domain, str(plist)], capture_output=True, check=False)
    result = subprocess.run(["/bin/launchctl", "bootstrap", domain, str(plist)], capture_output=True, text=True, check=False)
    if result.returncode: raise SystemExit("CFX002_SENSOR_NOT_RUNNING: " + (result.stderr.strip() or "launchctl bootstrap failed"))
    subprocess.run(["/bin/launchctl", "kickstart", "-k", f"{domain}/com.macos-security-audit-agent.clickfix-guard"], check=False)
    identity=f"Team {agent_team}" if agent_team else "ad-hoc DEVELOPMENT DEMO"
    print(f"Installed ClickFix Guard {args.profile} profile using {identity}")
    if args.development_demo: print("Grant Input Monitoring to MSAAClickFixGuardAgent.app in System Settings. The running agent will recover automatically within 10 seconds. Do not distribute this build.")
    return 0


if __name__ == "__main__": raise SystemExit(main())
