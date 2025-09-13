from typing import List, Tuple
import psutil

_TOTAL_CPUS = psutil.cpu_count(logical=True) or 1

Row = Tuple[int, str, str, float, float]


def _normalize_cpu_percent(raw_cpu: float) -> float:
    # Normalize CPU% by total logical CPUs (Task Manager style)
    try:
        return float(raw_cpu or 0.0) / _TOTAL_CPUS
    except Exception:
        return 0.0


def _rss_to_mb(mem_info) -> float:
    try:
        return (mem_info.rss if mem_info else 0) / (1024 * 1024)
    except Exception:
        return 0.0


def get_process_rows(pid_digits_filter: str = "") -> List[Row]:
    # Return rows: (pid, name, user, cpu%, memMB); optional PID substring filter
    digits_only = ''.join(ch for ch in (pid_digits_filter or "") if ch.isdigit())

    rows: List[Row] = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
        try:
            name = proc.info.get('name') or "-"
            if name == "System Idle Process":
                continue

            pid = int(proc.info['pid'])
            if digits_only and digits_only not in str(pid):
                continue

            user = proc.info.get('username') or "-"
            cpu = _normalize_cpu_percent(proc.info.get('cpu_percent'))
            mem = _rss_to_mb(proc.info.get('memory_info'))

            rows.append((pid, name, user, cpu, mem))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    return rows
