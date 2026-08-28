"""Symlink-resistant, owner-scoped persistence for sensitive user artifacts."""
from __future__ import annotations

import errno
import fcntl
import json
import os
import secrets
import stat
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class PersistenceResult:
    attempted: bool
    succeeded: bool
    path: Path | None
    error_code: str | None
    error_message: str | None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self); value["path"] = str(self.path) if self.path else None
        return value


@dataclass(frozen=True)
class DirectoryValidation:
    succeeded: bool
    path: Path
    error_code: str | None = None
    error_message: str | None = None
    owner_uid: int | None = None
    mode: int | None = None


@dataclass(frozen=True)
class MigrationResult:
    attempted: bool
    migrated: bool
    source: Path
    destination: Path
    status: str
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempted": self.attempted,
            "migrated": self.migrated,
            "source": str(self.source),
            "destination": str(self.destination),
            "status": self.status,
            "error_code": self.error_code,
        }


_WRITE_LOCK = threading.RLock()
_LAST_RESULT_LOCK = threading.Lock()
_LAST_RESULT: PersistenceResult | None = None
MAX_LEGACY_SUMMARY_BYTES = 2 * 1024 * 1024


def _failure(path: Path | None, code: str, message: str, *, attempted: bool = True) -> PersistenceResult:
    global _LAST_RESULT
    result = PersistenceResult(attempted, False, path, code, message)
    with _LAST_RESULT_LOCK: _LAST_RESULT = result
    return result


def last_persistence_result() -> PersistenceResult | None:
    with _LAST_RESULT_LOCK: return _LAST_RESULT


def _path_components(path: Path) -> list[Path]:
    components = []; current = path
    while current != current.parent:
        components.append(current); current = current.parent
    components.append(current)
    return list(reversed(components))


def validate_secure_directory(base: Path, *, create: bool, expected_uid: int | None = None, enforce_mode: bool = True) -> DirectoryValidation:
    path = Path(os.path.normpath(str(Path(base).expanduser())))
    uid = os.geteuid() if expected_uid is None and hasattr(os, "geteuid") else (expected_uid if expected_uid is not None else os.getuid())
    if not path.is_absolute(): return DirectoryValidation(False, path, "REPORT_PATH_INVALID", "Report directory must be absolute.")
    components = _path_components(path)
    for component in components:
        try: info = os.lstat(component)
        except FileNotFoundError: break
        except OSError: return DirectoryValidation(False, path, "REPORT_PATH_INVALID", "Report directory metadata could not be inspected.")
        if stat.S_ISLNK(info.st_mode): return DirectoryValidation(False, path, "REPORT_DIRECTORY_IS_SYMLINK", "Report directory contains a symbolic-link path component.")
        if not stat.S_ISDIR(info.st_mode): return DirectoryValidation(False, path, "REPORT_PATH_INVALID", "A report directory path component is not a directory.")
    created_directory = not path.exists()
    if created_directory:
        if not create: return DirectoryValidation(False, path, "REPORT_DIRECTORY_NOT_WRITABLE", "Report directory does not exist.")
        missing = [] ; cursor = path
        while not cursor.exists(): missing.append(cursor); cursor = cursor.parent
        try:
            for item in reversed(missing): os.mkdir(item, 0o700)
        except FileExistsError:
            pass
        except PermissionError: return DirectoryValidation(False, path, "REPORT_PERMISSION_DENIED", "Report directory could not be created by the current user.")
        except OSError: return DirectoryValidation(False, path, "REPORT_DIRECTORY_NOT_WRITABLE", "Report directory could not be created.")
    try: info = os.lstat(path)
    except OSError: return DirectoryValidation(False, path, "REPORT_PATH_INVALID", "Report directory metadata could not be inspected.")
    if stat.S_ISLNK(info.st_mode): return DirectoryValidation(False, path, "REPORT_DIRECTORY_IS_SYMLINK", "Report directory is a symbolic link.")
    if not stat.S_ISDIR(info.st_mode): return DirectoryValidation(False, path, "REPORT_PATH_INVALID", "Report directory path is not a directory.")
    if info.st_uid != uid: return DirectoryValidation(False, path, "REPORT_DIRECTORY_WRONG_OWNER", "Report directory is owned by another user.", info.st_uid, stat.S_IMODE(info.st_mode))
    current_mode = stat.S_IMODE(info.st_mode)
    if enforce_mode and (created_directory or current_mode & 0o077):
        restricted_mode = 0o700 if created_directory else current_mode & 0o700
        try: os.chmod(path, restricted_mode, follow_symlinks=False); current_mode = restricted_mode
        except PermissionError: return DirectoryValidation(False, path, "REPORT_PERMISSION_DENIED", "Report directory permissions could not be restricted.", info.st_uid, current_mode)
        except OSError: return DirectoryValidation(False, path, "REPORT_DIRECTORY_NOT_WRITABLE", "Report directory permissions could not be verified.", info.st_uid, current_mode)
    if not os.access(path, os.W_OK | os.X_OK): return DirectoryValidation(False, path, "REPORT_DIRECTORY_NOT_WRITABLE", "Report directory is not writable by the current user.", info.st_uid, stat.S_IMODE(info.st_mode))
    return DirectoryValidation(True, path, owner_uid=info.st_uid, mode=current_mode)


def _validate_target(base: Path, target: Path, uid: int) -> PersistenceResult | None:
    normalized_base = Path(os.path.normpath(str(base)))
    normalized_target = Path(os.path.normpath(str(target)))
    try:
        if Path(os.path.commonpath((str(normalized_base), str(normalized_target)))) != normalized_base or normalized_target.parent != normalized_base:
            return _failure(target, "REPORT_PATH_INVALID", "Report target escapes the selected report directory.")
    except ValueError:
        return _failure(target, "REPORT_PATH_INVALID", "Report target and directory are on incompatible paths.")
    try: info = os.lstat(normalized_target)
    except FileNotFoundError: return None
    except OSError: return _failure(target, "REPORT_PATH_INVALID", "Report target metadata could not be inspected.")
    if stat.S_ISLNK(info.st_mode): return _failure(target, "REPORT_TARGET_IS_SYMLINK", "Report target is a symbolic link.")
    if not stat.S_ISREG(info.st_mode): return _failure(target, "REPORT_PATH_INVALID", "Report target is not a regular file.")
    if info.st_uid != uid: return _failure(target, "REPORT_DIRECTORY_WRONG_OWNER", "Report target is owned by another user.")
    return None


def secure_atomic_write_json(
    value: Any,
    target: Path,
    *,
    base_directory: Path | None = None,
    expected_uid: int | None = None,
    enforce_directory_mode: bool = True,
    replace: Callable[[str, str], None] | None = None,
) -> PersistenceResult:
    """Serialize first, then securely replace one owner-scoped regular file."""
    global _LAST_RESULT
    destination = Path(target).expanduser()
    base = Path(base_directory or destination.parent).expanduser()
    uid = os.geteuid() if expected_uid is None and hasattr(os, "geteuid") else (expected_uid if expected_uid is not None else os.getuid())
    try: encoded = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, OverflowError): return _failure(destination, "REPORT_SERIALIZATION_FAILED", "Report data could not be serialized as JSON.", attempted=False)
    directory = validate_secure_directory(base, create=True, expected_uid=uid, enforce_mode=enforce_directory_mode)
    if not directory.succeeded: return _failure(destination, directory.error_code or "REPORT_PATH_INVALID", directory.error_message or "Report directory validation failed.")
    unsafe = _validate_target(base, destination, uid)
    if unsafe: return unsafe
    temporary: Path | None = None; lock_fd: int | None = None
    replace_function = os.replace if replace is None else replace
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    with _WRITE_LOCK:
        try:
            lock_path = base / ".ai-summary-write.lock"
            existing_lock = None
            try: existing_lock = os.lstat(lock_path)
            except FileNotFoundError: pass
            if existing_lock and (stat.S_ISLNK(existing_lock.st_mode) or not stat.S_ISREG(existing_lock.st_mode) or existing_lock.st_uid != uid):
                return _failure(destination, "REPORT_PATH_INVALID", "Report serialization lock is unsafe.")
            lock_fd = os.open(lock_path, flags & ~os.O_EXCL, 0o600); os.fchmod(lock_fd, 0o600); fcntl.flock(lock_fd, fcntl.LOCK_EX)
            unsafe = _validate_target(base, destination, uid)
            if unsafe: return unsafe
            for _attempt in range(8):
                candidate = base / f".{destination.name}.{secrets.token_hex(12)}.tmp"
                try:
                    fd = os.open(candidate, flags, 0o600); temporary = candidate; break
                except FileExistsError: continue
            else: return _failure(destination, "REPORT_ATOMIC_REPLACE_FAILED", "A unique temporary report file could not be created.")
            try:
                with os.fdopen(fd, "wb", closefd=True) as handle:
                    handle.write(encoded); handle.flush(); os.fsync(handle.fileno())
                replace_function(str(temporary), str(destination)); temporary = None
                os.chmod(destination, 0o600, follow_symlinks=False)
                directory_fd = os.open(base, os.O_RDONLY)
                try: os.fsync(directory_fd)
                except OSError: pass
                finally: os.close(directory_fd)
            except PermissionError: return _failure(destination, "REPORT_PERMISSION_DENIED", "Report could not be written with the current user permissions.")
            except OSError as exc:
                code = "REPORT_ATOMIC_REPLACE_FAILED" if exc.errno not in {errno.EACCES, errno.EPERM, errno.EROFS} else "REPORT_PERMISSION_DENIED"
                return _failure(destination, code, "Atomic report replacement failed." if code.endswith("FAILED") else "Report could not be written with the current user permissions.")
        except PermissionError:
            return _failure(destination, "REPORT_PERMISSION_DENIED", "Report could not be written with the current user permissions.")
        except OSError as exc:
            code = "REPORT_PERMISSION_DENIED" if exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS} else "REPORT_ATOMIC_REPLACE_FAILED"
            message = "Report could not be written with the current user permissions." if code == "REPORT_PERMISSION_DENIED" else "Atomic report setup failed."
            return _failure(destination, code, message)
        finally:
            if temporary is not None:
                try: temporary.unlink()
                except FileNotFoundError: pass
                except OSError: pass
            if lock_fd is not None:
                try: fcntl.flock(lock_fd, fcntl.LOCK_UN); os.close(lock_fd)
                except OSError: pass
    result = PersistenceResult(True, True, destination, None, None)
    with _LAST_RESULT_LOCK: _LAST_RESULT = result
    return result


def probe_report_directory(base: Path, *, expected_uid: int | None = None) -> dict[str, Any]:
    uid = os.geteuid() if expected_uid is None and hasattr(os, "geteuid") else (expected_uid if expected_uid is not None else os.getuid())
    validation = validate_secure_directory(base, create=True, expected_uid=uid)
    payload = {"report_directory": str(base), "report_directory_exists": Path(base).exists(), "report_directory_writable": False,
               "report_directory_owner_uid": validation.owner_uid, "current_uid": uid, "report_directory_is_symlink": validation.error_code == "REPORT_DIRECTORY_IS_SYMLINK"}
    if not validation.succeeded:
        payload.update(ai_summary_persistence_available=False, probe_error_code=validation.error_code); return payload
    probe = Path(base) / f".write-probe-{secrets.token_hex(12)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | (getattr(os, "O_NOFOLLOW", 0))
    fd: int | None = None
    try:
        fd = os.open(probe, flags, 0o600); os.write(fd, b""); os.fsync(fd); os.close(fd); fd = None; probe.unlink()
        payload.update(report_directory_writable=True, ai_summary_persistence_available=True, probe_error_code=None)
    except OSError:
        if fd is not None:
            try: os.close(fd)
            except OSError: pass
        try: probe.unlink()
        except OSError: pass
        payload.update(ai_summary_persistence_available=False, probe_error_code="REPORT_DIRECTORY_NOT_WRITABLE")
    return payload


def migrate_legacy_json(source: Path, destination: Path, *, maximum_bytes: int = MAX_LEGACY_SUMMARY_BYTES) -> MigrationResult:
    source = Path(source); destination = Path(destination)
    try:
        destination_info = os.lstat(destination)
    except FileNotFoundError:
        destination_info = None
    except OSError:
        return MigrationResult(False, False, source, destination, "destination_metadata_unavailable", "REPORT_PATH_INVALID")
    if destination_info is not None:
        code = "REPORT_TARGET_IS_SYMLINK" if stat.S_ISLNK(destination_info.st_mode) else None
        return MigrationResult(False, False, source, destination, "destination_exists", code)
    try: info = os.lstat(source)
    except FileNotFoundError: return MigrationResult(False, False, source, destination, "legacy_absent")
    except OSError: return MigrationResult(True, False, source, destination, "legacy_metadata_unavailable", "REPORT_PATH_INVALID")
    uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if stat.S_ISLNK(info.st_mode): return MigrationResult(True, False, source, destination, "legacy_symlink_rejected", "REPORT_TARGET_IS_SYMLINK")
    if not stat.S_ISREG(info.st_mode): return MigrationResult(True, False, source, destination, "legacy_special_file_rejected", "REPORT_PATH_INVALID")
    if info.st_uid != uid: return MigrationResult(True, False, source, destination, "legacy_foreign_owner_rejected", "REPORT_DIRECTORY_WRONG_OWNER")
    if info.st_size > maximum_bytes: return MigrationResult(True, False, source, destination, "legacy_oversized_rejected", "REPORT_PATH_INVALID")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        opened_info = os.fstat(descriptor)
        if (opened_info.st_dev, opened_info.st_ino) != (info.st_dev, info.st_ino):
            return MigrationResult(True, False, source, destination, "legacy_changed_during_validation", "REPORT_PATH_INVALID")
        if not stat.S_ISREG(opened_info.st_mode) or opened_info.st_uid != uid or opened_info.st_size > maximum_bytes:
            return MigrationResult(True, False, source, destination, "legacy_changed_during_validation", "REPORT_PATH_INVALID")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            data = handle.read(maximum_bytes + 1)
        if len(data) > maximum_bytes: raise ValueError("oversized")
        value = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeError, ValueError):
        return MigrationResult(True, False, source, destination, "legacy_read_failed", "REPORT_SERIALIZATION_FAILED")
    finally:
        if descriptor is not None:
            try: os.close(descriptor)
            except OSError: pass
    result = secure_atomic_write_json(value, destination, base_directory=destination.parent)
    return MigrationResult(True, result.succeeded, source, destination, "migrated" if result.succeeded else "migration_write_failed", result.error_code)


__all__ = ["DirectoryValidation", "MigrationResult", "PersistenceResult", "last_persistence_result", "migrate_legacy_json", "probe_report_directory", "secure_atomic_write_json", "validate_secure_directory"]
