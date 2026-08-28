"""Standard-library-only fail-closed boundary before any Qt/AppKit import."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import platform
import site
import subprocess
import sys
import threading
import signal
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path


class GuiFailureCode(str, Enum):
    UNSUPPORTED_PYTHON = "GUI001_UNSUPPORTED_PYTHON"
    NO_AQUA_SESSION = "GUI002_NO_AQUA_SESSION"
    ROOT_FORBIDDEN = "GUI003_ROOT_GUI_FORBIDDEN"
    LAUNCHDAEMON_FORBIDDEN = "GUI004_LAUNCHDAEMON_GUI_FORBIDDEN"
    UNSAFE_PARENT = "GUI005_UNSAFE_PARENT_PROCESS"
    QT_IMPORT_FAILED = "GUI006_QT_IMPORT_FAILED"
    COCOA_PROBE_FAILED = "GUI007_COCOA_PROBE_FAILED"
    ALREADY_INITIALIZED = "GUI008_GUI_ALREADY_INITIALIZED"
    WRONG_THREAD = "GUI009_WRONG_THREAD"
    APPKIT_UNSAFE = "GUI010_APPKIT_REGISTRATION_UNSAFE"


class AquaState(str, Enum):
    AVAILABLE = "AQUA_AVAILABLE"
    UNAVAILABLE = "AQUA_UNAVAILABLE"
    UNKNOWN = "AQUA_UNKNOWN"


@dataclass(frozen=True)
class GuiPreflightResult:
    allowed: bool
    failure_code: str
    message: str
    python_version: str
    python_executable: str
    architecture: str
    macos_version: str
    is_root: bool
    display_session_available: bool
    aqua_state: str
    launch_mode: str
    is_app_bundle_launch: bool
    is_terminal_launch: bool
    is_source_checkout: bool
    parent_process: str
    responsible_process: str | None
    launchservices_safe: bool
    automation_mode: bool
    test_backend: str
    user_site_enabled: bool
    pyside_version: str
    shiboken_version: str
    qt_plugin_path: str
    dependency_roots_consistent: bool

    def to_dict(self) -> dict[str, object]: return asdict(self)


class GuiPreflightError(RuntimeError):
    def __init__(self,result:GuiPreflightResult)->None:
        super().__init__(f"{result.failure_code}: {result.message}");self.result=result;self.code=result.failure_code


def _process_name(pid:int)->str:
    try:
        result=subprocess.run(["/bin/ps","-p",str(pid),"-o","comm="],capture_output=True,text=True,timeout=2,check=False)
        return (result.stdout or "").strip() or "unknown"
    except (OSError,subprocess.SubprocessError):return "unknown"


def _aqua_state(uid:int)->AquaState:
    if sys.platform!="darwin" or os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):return AquaState.UNAVAILABLE
    try:
        result=subprocess.run(["/bin/launchctl","print",f"gui/{uid}"],capture_output=True,text=True,timeout=3,check=False)
        return AquaState.AVAILABLE if result.returncode==0 else AquaState.UNAVAILABLE
    except (OSError,subprocess.SubprocessError):return AquaState.UNKNOWN


def _version(name:str)->str:
    try:return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:return "not installed"


def _dependency_diagnostics()->tuple[str,str,str,bool]:
    pyside,shiboken=_version("PySide6"),_version("shiboken6")
    spec=importlib.util.find_spec("PySide6");root=str(Path(next(iter(spec.submodule_search_locations),"" )).resolve()) if spec and spec.submodule_search_locations else ""
    plugin=os.environ.get("QT_PLUGIN_PATH","")
    consistent=pyside!="not installed" and shiboken!="not installed" and pyside.split(".")[:2]==shiboken.split(".")[:2]
    if plugin and root:
        try: Path(plugin).resolve().relative_to(Path(root).parent.resolve())
        except ValueError: consistent=False
    return pyside,shiboken,plugin,consistent


def _blocked(result:dict[str,object],code:GuiFailureCode,message:str)->GuiPreflightResult:
    result.update(allowed=False,failure_code=code.value,message=message,launchservices_safe=False);return GuiPreflightResult(**result)


def _qt_dependency_message(executable:str,pyside:str,shiboken:str,source_checkout:bool)->str:
    target = ".[gui]" if source_checkout else "macos-security-audit-agent[gui]"
    return "\n".join((
        "PySide6 and Shiboken are missing or inconsistent for the selected Python runtime.",
        "",
        f"Selected interpreter: {executable}",
        f"PySide6: {pyside}",
        f"Shiboken6: {shiboken}",
        "",
        "Recommended isolated setup:",
        f'  "{executable}" -m venv .venv',
        "  . .venv/bin/activate",
        "  python -m pip install --upgrade pip",
        f'  python -m pip install "{target}"',
        "  python launcher.py",
        "",
        "MSAA will automatically prefer the project .venv on the next launch.",
    ))


def evaluate_gui_preflight(*,version_info:tuple[int,int,int]|None=None,euid:int|None=None,parent_process:str|None=None,aqua_state:AquaState|None=None,platform_name:str|None=None)->GuiPreflightResult:
    version=version_info or tuple(sys.version_info[:3]);uid=os.geteuid() if euid is None and hasattr(os,"geteuid") else int(euid or 0)
    # A virtual environment's python is commonly a symlink to its base
    # interpreter. Preserve that path in diagnostics and child probes so the
    # environment's site-packages remain active.
    executable=os.path.abspath(sys.executable);parent=parent_process or _process_name(os.getppid());responsible=os.environ.get("TERM_PROGRAM") or parent
    app_bundle=bool(getattr(sys,"frozen",False)) or ".app/Contents/MacOS/" in executable
    terminal=bool(os.environ.get("TERM_PROGRAM")) or Path(parent).name.lower() in {"zsh","bash","fish","terminal","iterm2"}
    source=(Path(__file__).resolve().parents[2]/"pyproject.toml").is_file() and not app_bundle
    automation=os.environ.get("MSAA_GUI_AUTOMATION_MODE")=="1" or bool(os.environ.get("CODEX_HOME")) or "codex" in parent.lower() or bool(os.environ.get("CI"))
    backend=os.environ.get("MSAA_GUI_TEST_BACKEND","").strip().lower();aqua=aqua_state or _aqua_state(uid)
    pyside,shiboken,plugin,consistent=_dependency_diagnostics()
    base=dict(allowed=True,failure_code="",message="GUI runtime and launch context passed static preflight.",python_version=".".join(map(str,version)),python_executable=executable,architecture=platform.machine(),macos_version=platform.mac_ver()[0] or platform.release(),is_root=uid==0,display_session_available=aqua==AquaState.AVAILABLE,aqua_state=aqua.value,launch_mode="app_bundle" if app_bundle else "terminal_direct" if terminal else "direct",is_app_bundle_launch=app_bundle,is_terminal_launch=terminal,is_source_checkout=source,parent_process=parent,responsible_process=responsible,launchservices_safe=True,automation_mode=automation,test_backend=backend,user_site_enabled=bool(site.ENABLE_USER_SITE),pyside_version=pyside,shiboken_version=shiboken,qt_plugin_path=plugin,dependency_roots_consistent=consistent)
    if version[:2] not in {(3,12),(3,13)}:return _blocked(base,GuiFailureCode.UNSUPPORTED_PYTHON,_unsupported_python_message(executable,version))
    if threading.current_thread() is not threading.main_thread():return _blocked(base,GuiFailureCode.WRONG_THREAD,"QApplication must be created on the original process main thread.")
    if uid==0:return _blocked(base,GuiFailureCode.ROOT_FORBIDDEN,"MSAA GUI startup as root is forbidden; use a headless privileged helper.")
    launchdaemon=os.environ.get("MSAA_LAUNCH_DOMAIN","").lower() in {"system","launchdaemon"} or (Path(parent).name=="launchd" and not app_bundle and aqua!=AquaState.AVAILABLE)
    if launchdaemon:return _blocked(base,GuiFailureCode.LAUNCHDAEMON_FORBIDDEN,"LaunchDaemons must not initialize the MSAA GUI.")
    if automation:
        if backend not in {"offscreen","minimal","interactive-aqua"}:return _blocked(base,GuiFailureCode.UNSAFE_PARENT,"Automated execution requires an explicit MSAA_GUI_TEST_BACKEND.")
        if backend in {"offscreen","minimal"}:
            os.environ.setdefault("QT_QPA_PLATFORM",backend);base.update(launch_mode=f"automation_{backend}",launchservices_safe=True,message=f"Approved non-Cocoa {backend} test backend.");return GuiPreflightResult(**base)
    if (platform_name or sys.platform)!="darwin":return _blocked(base,GuiFailureCode.APPKIT_UNSAFE,"Native MSAA GUI startup is supported only on validated macOS contexts.")
    if aqua!=AquaState.AVAILABLE:return _blocked(base,GuiFailureCode.NO_AQUA_SESSION,"No confirmed Aqua graphical login session is available.")
    if not consistent:return _blocked(base,GuiFailureCode.QT_IMPORT_FAILED,_qt_dependency_message(executable,pyside,shiboken,source))
    return GuiPreflightResult(**base)


def require_gui_preflight(**overrides:object)->GuiPreflightResult:
    result=evaluate_gui_preflight(**overrides)
    if not result.allowed:raise GuiPreflightError(result)
    return result


def _unsupported_python_message(executable:str,version:tuple[int,int,int])->str:
    return f"""MSAA GUI startup blocked.\n\nDetected Python:\n  {executable}\n  Python {'.'.join(map(str,version))}\n\nThis interpreter is supported only for MSAA doctor and limited\nheadless diagnostics. It must not initialize the PySide6 GUI.\n\nLaunch MSAA with Python 3.12 or Python 3.13, for example:\n\n  python3.12 launcher.py\n\nRun diagnostics with:\n\n  python3 launcher.py --doctor"""


def diagnostics_json(result:GuiPreflightResult)->str:return json.dumps(result.to_dict(),indent=2,sort_keys=True)


def run_isolated_cocoa_probe(*,python_executable:str|None=None,timeout:float=10.0,runner=subprocess.run)->dict[str,object]:
    executable=os.path.abspath(python_executable or sys.executable)
    env={key:value for key,value in os.environ.items() if key in {"HOME","LANG","LC_ALL","LOGNAME","PATH","TMPDIR","USER","VIRTUAL_ENV","MSAA_GUI_AUTOMATION_MODE","MSAA_GUI_TEST_BACKEND"}}
    env["PYTHONNOUSERSITE"]="1";env.setdefault("PATH","/usr/bin:/bin:/usr/sbin:/sbin")
    command=[executable,"-m","mac_audit_agent.runtime.qt_probe"]
    try:completed=runner(command,capture_output=True,text=True,timeout=timeout,check=False,env=env)
    except subprocess.TimeoutExpired as exc:return {"safe":False,"failure_code":GuiFailureCode.COCOA_PROBE_FAILED.value,"error_code":"PROBE_TIMEOUT","stdout":exc.stdout or "","stderr":exc.stderr or ""}
    except OSError as exc:return {"safe":False,"failure_code":GuiFailureCode.COCOA_PROBE_FAILED.value,"error_code":type(exc).__name__.upper()}
    terminated=-completed.returncode if completed.returncode<0 else None
    try:payload=json.loads((completed.stdout or "").strip().splitlines()[-1])
    except (ValueError,IndexError,TypeError):payload={"safe":False,"error_code":"PROBE_MALFORMED_OUTPUT"}
    payload.update(exit_code=completed.returncode,signal=terminated,stderr=(completed.stderr or "")[-2000:])
    if terminated==signal.SIGABRT:payload.update(safe=False,failure_code=GuiFailureCode.COCOA_PROBE_FAILED.value,error_code="PROBE_SIGABRT")
    elif completed.returncode!=0:payload.setdefault("failure_code",GuiFailureCode.COCOA_PROBE_FAILED.value)
    return payload
