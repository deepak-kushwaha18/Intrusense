import os
import ctypes

def is_admin() -> bool:
    # True if current process has admin rights (Windows-aware)
    try:
        if os.name == 'nt':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False

def can_access_process(pid: int) -> bool:
    if os.name != 'nt':
        return True
    try:
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    except Exception:
        return False
