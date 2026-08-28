from __future__ import annotations

import argparse, json, os, platform, re, shutil, subprocess, sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.9/3.10
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

ROOT=Path(__file__).resolve().parents[1]
ENV_MAP={"team_id":"MSAA_TEAM_ID","developer_id_application_identity_name":"MSAA_DEVELOPER_ID_APPLICATION_IDENTITY","developer_id_installer_identity_name":"MSAA_DEVELOPER_ID_INSTALLER_IDENTITY","endpoint_security_provisioning_profile":"MSAA_PROVISIONING_PROFILE","notarytool_keychain_profile_name":"MSAA_NOTARYTOOL_PROFILE","second_team_fixture_path":"MSAA_SECOND_TEAM_FIXTURE","authorized_test_host_file":"MSAA_AUTHORIZED_TEST_HOST_FILE"}

def run(*args):
    try: return subprocess.run(args,capture_output=True,text=True,timeout=15).stdout.strip()
    except (OSError,subprocess.SubprocessError): return ""

def load_config(path: Path|None):
    data={}
    if path and path.is_file():
        if tomllib is None:
            raise RuntimeError("Reading --config on Python 3.9/3.10 requires the 'tomli' dependency. Install the project requirements first.")
        data.update(tomllib.loads(path.read_text(encoding="utf-8")))
    for key,env in ENV_MAP.items():
        if os.getenv(env): data[key]=os.environ[env]
    return data

def main(argv=None):
    parser=argparse.ArgumentParser(); parser.add_argument("--config",type=Path); parser.add_argument("--json",action="store_true"); args=parser.parse_args(argv)
    config=load_config(args.config); identities=run("security","find-identity","-v","-p","codesigning")
    team=str(config.get("team_id", "")); app=str(config.get("developer_id_application_identity_name","")); installer=str(config.get("developer_id_installer_identity_name",""))
    python_ok=sys.version_info[:3]==(3,14,6)
    pyinstaller_probe=subprocess.run([sys.executable,"-m","PyInstaller","--version"],capture_output=True,text=True)
    pyinstaller_version=pyinstaller_probe.stdout.strip() if pyinstaller_probe.returncode==0 else ""
    artifacts={name:str(path) if path.exists() else "" for name,path in {"helper":ROOT/"dist/active-containment/MSAAContainmentHelper","engine":ROOT/"dist/active-containment/MSAAAntiRansomwareEngine/MSAAAntiRansomwareEngine","guardian":ROOT/"dist/active-containment/MSAALeaseGuardian","sensor":ROOT/"dist/active-containment/MSAAEndpointSecuritySensor.app"}.items()}
    endpoint_profile=str(config.get("endpoint_security_provisioning_profile", ""))
    result={"schema_version":"1.0","team_id":{"configured":bool(re.fullmatch(r"[A-Z0-9]{10}",team)),"value":"<configured>" if team else ""},"developer_id_application":{"configured":bool(app),"matching_identity":bool(app and app in identities)},"developer_id_installer":{"configured":bool(installer),"matching_identity":bool(installer and installer in identities)},"endpoint_security_profile":{"configured":bool(endpoint_profile),"readable":bool(endpoint_profile and Path(endpoint_profile).is_file())},"python_3146":python_ok,"pyinstaller":{"available_for_python_3146":bool(pyinstaller_version),"version":pyinstaller_version,"python":sys.executable},"xcode":run("xcodebuild","-version") or "unavailable","sdk":run("xcrun","--show-sdk-version"),"macos":platform.mac_ver()[0],"architecture":platform.machine(),"artifacts":artifacts,"notary_profile_configured":bool(config.get("notarytool_keychain_profile_name")),"second_team_fixture":bool(config.get("second_team_fixture_path") and Path(str(config["second_team_fixture_path"])).is_file()),"host_authorization_file":bool(config.get("authorized_test_host_file") and Path(str(config["authorized_test_host_file"])).is_file()),"authorizations":{"install":os.getenv("MSAA_ALLOW_PRIVILEGED_TEST_INSTALL")=="1","live_containment":os.getenv("MSAA_ALLOW_LIVE_CONTAINMENT_TESTS")=="1","reboot":os.getenv("MSAA_ALLOW_REBOOT_TEST")=="1"}}
    missing=[]
    checks=[("production Team ID",result["team_id"]["configured"],"Project owner","Set MSAA_TEAM_ID; do not provide keys."),("Developer ID Application identity",result["developer_id_application"]["matching_identity"],"Release-signing engineer","Install identity in a controlled Keychain and set its identity name."),("Endpoint Security provisioning profile",result["endpoint_security_profile"]["readable"],"Apple Developer Account Holder","Download the approved Developer ID profile and set MSAA_PROVISIONING_PROFILE; do not commit it."),("Developer ID Installer identity",result["developer_id_installer"]["matching_identity"],"Release-signing engineer","Install installer identity; never commit a p12."),("PyInstaller for Python 3.14.6",bool(pyinstaller_version),"Build engineer","Install PyInstaller into the controlled Python 3.14.6 build environment."),("authorized disposable-host file",result["host_authorization_file"],"Disposable-host operator","Create a non-secret authorization file from the example.")]
    for resource,ok,role,instruction in checks:
        if not ok: missing.append({"resource":resource,"contributor_role":role,"secure_instruction":instruction,"verification":"python3.14 scripts/active_containment_contribution_preflight.py --json"})
    result["missing"]=missing; result["ready_for_signing"]=not missing and python_ok
    print(json.dumps(result,indent=2,sort_keys=True)); return 0 if result["ready_for_signing"] else 2
if __name__=="__main__": raise SystemExit(main())
