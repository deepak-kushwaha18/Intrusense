"""
eventlog_module.py

Windows Event Log helper with improved formatting.
APIs:
- list_known_logs() -> Dict[str, List[str]]
- read_events(log_name="Security", max_records=50) -> List[Dict]
- get_full_message(ev_dict) -> str
"""
from typing import List, Dict, Any, Optional
import sys

IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    try:
        import win32evtlog  # type: ignore
        import win32evtlogutil  # type: ignore
    except Exception:
        win32evtlog = None
        win32evtlogutil = None
else:
    win32evtlog = None
    win32evtlogutil = None


def _level_from_event_type(ev_type: Optional[int]) -> str:
    if not win32evtlog:
        return "Unavailable"
    mapping = {
        getattr(win32evtlog, 'EVENTLOG_ERROR_TYPE', 1): "Error",
        getattr(win32evtlog, 'EVENTLOG_WARNING_TYPE', 2): "Warning",
        getattr(win32evtlog, 'EVENTLOG_INFORMATION_TYPE', 4): "Information",
        getattr(win32evtlog, 'EVENTLOG_AUDIT_SUCCESS', 8): "Audit Success",
        getattr(win32evtlog, 'EVENTLOG_AUDIT_FAILURE', 16): "Audit Failure",
    }
    return mapping.get(ev_type, "Information" if ev_type is None else str(ev_type))


def _safe_format_message(ev, log_name: Optional[str] = None) -> str:
    # Try SafeFormatMessage; fall back to insertion strings or str(ev).
    if not IS_WINDOWS or not win32evtlog:
        return "<event formatting not available>"

    try:
        if win32evtlogutil:
            if log_name:
                try:
                    return win32evtlogutil.SafeFormatMessage(ev, log_name)
                except Exception:
                    pass
            try:
                return win32evtlogutil.SafeFormatMessage(ev, ev.SourceName)
            except Exception:
                pass
    except Exception:
        pass

    try:
        inserts = getattr(ev, "StringInserts", None)
        if inserts:
            return " ".join(str(x) for x in inserts if x is not None)
    except Exception:
        pass

    try:
        return str(ev)
    except Exception:
        return "<failed to format event>"


def _best_effort_user(ev) -> str:
    # Try to extract a usable user string.
    try:
        if hasattr(ev, "UserSid") and getattr(ev, "UserSid") is not None:
            return str(getattr(ev, "UserSid"))
        inserts = getattr(ev, "StringInserts", None)
        if inserts:
            for s in inserts:
                try:
                    ss = str(s)
                    if ss and ("\\" in ss or "@" in ss or ss.upper().startswith("S-1-")):
                        return ss
                except Exception:
                    continue
    except Exception:
        pass
    return "Unavailable"


def read_events(log_name: str = "Security", max_records: int = 50) -> List[Dict[str, Any]]:
    # Read events from Windows Event Log, return an error entry if not possible.
    if not IS_WINDOWS or not win32evtlog:
        return [{
            "time": "",
            "source": "",
            "event_id": "",
            "category": "",
            "msg": "(event log reading not available — pywin32 not installed or not running on Windows)",
            "raw": None,
            "computer": "Unavailable",
            "record_number": "Unavailable",
            "level": "Unavailable",
            "opcode": "Unavailable",
            "task": "Unavailable",
            "keywords": "Unavailable",
            "user": "Unavailable",
            "error": True
        }]

    server = "localhost"
    hand = None
    events: List[Dict[str, Any]] = []
    try:
        try:
            hand = win32evtlog.OpenEventLog(server, log_name)
        except Exception as e:
            return [{
                "time": "",
                "source": "",
                "event_id": "",
                "category": "",
                "msg": f"Unable to open '{log_name}' log: {e}. Try running as Administrator to view this log.",
                "raw": None,
                "computer": "Unavailable",
                "record_number": "Unavailable",
                "level": "Unavailable",
                "opcode": "Unavailable",
                "task": "Unavailable",
                "keywords": "Unavailable",
                "user": "Unavailable",
                "error": True
            }]

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        read_count = 0
        while True:
            try:
                records = win32evtlog.ReadEventLog(hand, flags, 0)
            except Exception as e:
                return [{
                    "time": "",
                    "source": "",
                    "event_id": "",
                    "category": "",
                    "msg": f"Unable to read '{log_name}' log: {e}. Try running as Administrator or check event log service.",
                    "raw": None,
                    "computer": "Unavailable",
                    "record_number": "Unavailable",
                    "level": "Unavailable",
                    "opcode": "Unavailable",
                    "task": "Unavailable",
                    "keywords": "Unavailable",
                    "user": "Unavailable",
                    "error": True
                }]
            if not records:
                break
            for ev in records:
                try:
                    ev_id = int(ev.EventID & 0xFFFF)
                    time_str = ev.TimeGenerated.Format("%Y-%m-%d %H:%M:%S") if getattr(ev, "TimeGenerated", None) else ""
                    src = getattr(ev, "SourceName", "") or ""
                    cat = getattr(ev, "EventCategory", None)
                    task = cat if cat is not None else "Unavailable"
                    comp = getattr(ev, "ComputerName", None) or "Unavailable"
                    record_no = getattr(ev, "RecordNumber", None) or "Unavailable"
                    et = getattr(ev, "EventType", None)
                    level = _level_from_event_type(et)
                    opcode = getattr(ev, "Opcode", None) or "Unavailable"
                    keywords = getattr(ev, "Keywords", None) or "Unavailable"
                    user = _best_effort_user(ev)
                    msg = _safe_format_message(ev, log_name=log_name)
                    events.append({
                        "time": time_str,
                        "source": src,
                        "event_id": ev_id,
                        "category": task,
                        "msg": msg,
                        "raw": ev,
                        "computer": comp,
                        "record_number": record_no,
                        "level": level,
                        "opcode": opcode,
                        "task": task,
                        "keywords": keywords,
                        "user": user,
                        "error": False
                    })
                    read_count += 1
                    if read_count >= max_records:
                        break
                except Exception:
                    continue
            if read_count >= max_records:
                break
    finally:
        try:
            if hand:
                win32evtlog.CloseEventLog(hand)
        except Exception:
            pass

    return events


def get_full_message(ev: Dict[str, Any]) -> str:
    # Return fully formatted message when possible.
    if not ev:
        return "<no event>"
    raw = ev.get("raw")
    if raw and IS_WINDOWS and win32evtlog:
        try:
            return _safe_format_message(raw, log_name=None)
        except Exception:
            pass
    return ev.get("msg", "") or ""


def list_known_logs() -> Dict[str, List[str]]:
    # Return two-pane hierarchy: Administrative Views and Windows Logs.
    result: Dict[str, List[str]] = {}
    result["Administrative Views"] = ["Administrative Events"]
    result["Windows Logs"] = ["Application", "Security", "Setup", "System"]
    return result


if __name__ == "__main__":
    import json
    print("eventlog_module test - platform:", sys.platform)
    print("pywin32 loaded:", bool(IS_WINDOWS and win32evtlog))
    print(json.dumps(list_known_logs(), indent=2))
    if IS_WINDOWS and win32evtlog:
        evs = read_events("System", max_records=3)
        print("Read", len(evs), "events from System")
        if evs:
            print(evs[0].get("time"), evs[0].get("source"), evs[0].get("event_id"))
