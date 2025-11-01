# main.py
# Intrusense Phase 1 - main UI with Process UX polish + Network sorting + export
# UPDATED: Added Process Name search and simplified kill messages.

import os
import csv
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil
from datetime import datetime
import logging
import threading
import subprocess
import platform

from typing import Dict, Any

import process_module
import memory_module
import user_module
import rights_module
import network_module

# Try to load event helper; OK if missing.
try:
    import eventlog_module
    HAS_EVENTLOG = True
except Exception:
    eventlog_module = None
    HAS_EVENTLOG = False

# Try to load settings helper (optional)
try:
    import settings_helper
except Exception:
    settings_helper = None

# Load settings (fallback to defaults)
if settings_helper:
    SETTINGS = settings_helper.load_settings()
else:
    SETTINGS = {
        "refresh_ms": 500,
        "show_python_procs": False,
        "event_reading_enabled": True,
        "window_width": 1300,
        "window_height": 750
    }

# App-wide small state
class _MainState:
    pass
main_state = _MainState()
main_state.notebook = None
main_state.events_tab_index = None

def get_refresh_ms() -> int:
    base = int(SETTINGS.get("refresh_ms", 500))
    try:
        if getattr(main_state, "notebook", None) is not None:
            current = main_state.notebook.index(main_state.notebook.select())
            if main_state.events_tab_index is not None and current != main_state.events_tab_index:
                return max(base * 4, 1000)
    except Exception:
        pass
    return base

def set_setting(k, v):
    SETTINGS[k] = v
    if settings_helper:
        settings_helper.save_settings(SETTINGS)

# Skip python processes by default to avoid misleading spikes
IGNORE_PROCESS_NAMES = {"python.exe", "pythonw.exe"}
THIS_PID = os.getpid()

# Process sorting state
sort_priority = [("CPU %", True)]
ALLOWED_SORT_COLUMNS = {"PID", "CPU %", "Memory"}

# Network sorting state (separate)
network_sort_priority = [("Local", False)]
NETWORK_ALLOWED = {"PID", "Local", "Remote", "Status"}


def default_desc(col: str) -> bool:
    return col in ("PID", "CPU %", "Memory")


def header_text(col: str, net=False) -> str:
    # Build header label with arrow + order index
    if not net:
        if col not in ALLOWED_SORT_COLUMNS:
            return col
        for idx, (c, desc) in enumerate(sort_priority):
            if c == col:
                order = f"[{idx + 1}]"
                return f"{col} {'▼' if desc else '▲'}{order}"
        return col
    else:
        if col not in NETWORK_ALLOWED:
            return col
        for idx, (c, desc) in enumerate(network_sort_priority):
            if c == col:
                order = f"[{idx + 1}]"
                return f"{col} {'▼' if desc else '▲'}{order}"
        return col


def set_sort(col: str, additive: bool = False):
    # Update sort for processes
    global sort_priority
    if col not in ALLOWED_SORT_COLUMNS:
        return
    existing = {c: i for i, (c, _) in enumerate(sort_priority)}
    if not additive:
        if sort_priority and sort_priority[0][0] == col:
            sort_priority[0] = (col, not sort_priority[0][1])
        else:
            sort_priority = [(col, default_desc(col))]
    else:
        if col in existing:
            i = existing[col]
            c, d = sort_priority[i]
            sort_priority[i] = (c, not d)
        else:
            sort_priority.append((col, default_desc(col)))
    try:
        refresh_headers(proc_tree, ("PID", "Name", "User", "CPU %", "Memory"))
        update_process_list(proc_tree, proc_status, pid_filter_var, ("PID", "Name", "User", "CPU %", "Memory"))
    except Exception:
        pass


def set_network_sort(col: str, additive: bool = False):
    # Update sort for network table
    global network_sort_priority
    if col not in NETWORK_ALLOWED:
        return
    existing = {c: i for i, (c, _) in enumerate(network_sort_priority)}
    if not additive:
        if network_sort_priority and network_sort_priority[0][0] == col:
            network_sort_priority[0] = (col, not network_sort_priority[0][1])
        else:
            network_sort_priority = [(col, True if col in ("PID",) else False)]
    else:
        if col in existing:
            i = existing[col]
            c, d = network_sort_priority[i]
            network_sort_priority[i] = (c, not d)
        else:
            network_sort_priority.append((col, True if col in ("PID",) else False))
    try:
        update_network_list_sort_and_refresh()
    except Exception:
        pass


# Small category hints for events (unchanged)
_SOURCE_CATEGORY_HINTS = {
    "Kernel-Power": "Kernel-Power",
    "Kernel-General": "Kernel",
    "W32Time": "Time-Service",
    "Time-Service": "Time-Service",
    "Service Control Manager": "Service Control Manager",
    "Application": "Application",
    "Microsoft-Windows-TaskScheduler": "Task Scheduler",
    "Microsoft-Windows-Windows Defender": "Windows Defender",
    "Security": "Security",
    "Microsoft-Windows-Security-Auditing": "Security (Auditing)",
}


def get_friendly_category(ev: Dict[str, Any]) -> str:
    task = ev.get("task")
    if task and isinstance(task, str) and task.strip() and not task.strip().isdigit():
        return task.strip()
    src = (ev.get("source") or "") or (ev.get("_origin_log") or "")
    if src:
        src_lower = src.lower()
        for key, friendly in _SOURCE_CATEGORY_HINTS.items():
            if key.lower() in src_lower:
                return friendly
    cat = ev.get("category")
    try:
        if cat is not None:
            n = int(cat)
            if n == 5:
                return "Kernel / System"
            if n == 0:
                return ""
            return f"Category {n}"
    except Exception:
        pass
    return ""


def refresh_headers(tree, columns):
    # Refresh process headers to show sort indicators
    for idx, c in enumerate(columns):
        text = header_text(c, net=False)
        tree.heading(c, text=text)


# ---------- Processes tab (UPDATED for name search) ----------

def update_process_list(tree, status_var, pid_filter_var, columns):
    # Background worker to gather processes and update UI
    def worker():
        # --- UPDATED: Pass raw text for name search ---
        filter_text = pid_filter_var.get().strip()
        
        # This function expects 5-tuples: (pid, name, user, cpu, mem)
        proc_rows = process_module.get_process_rows(filter_text)
        # --- END UPDATE ---
        
        filtered = []
        for (pid, name, user, cpu, mem) in proc_rows:
            try:
                if int(pid) == THIS_PID:
                    continue
            except Exception:
                pass
            if not SETTINGS.get("show_python_procs", False) and (name or "").lower() in IGNORE_PROCESS_NAMES:
                continue
            filtered.append((pid, name, user, cpu, mem))

        # This key function expects the 5-tuple structure
        def key_for(col: str, row):
            if col == "PID":
                return int(row[0])
            elif col == "Name":
                return (row[1] or "").lower()
            elif col == "User":
                return (row[2] or "").lower()
            elif col == "CPU %":
                return float(row[3])
            elif col == "Memory":
                return float(row[4])
            return 0

        filtered.sort(key=lambda r: int(r[0]))
        for col, desc in reversed(sort_priority):
            filtered.sort(key=lambda r, c=col: key_for(c, r), reverse=desc)

        def update_ui():
            # Save selection/focus
            selected_iid = tree.selection()
            
            tree.delete(*tree.get_children()) # Clear all items
            
            for idx, (pid, name, user, cpu, mem) in enumerate(filtered):
                tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
                display_values = [pid, name, user, f"{cpu:.1f}%", f"{mem:.1f} MB"]
                # Insert as flat list
                tree.insert("", "end", iid=pid, values=tuple(display_values), tags=(tag,))
                
            status_var.set(
                f"Processes: {len(filtered)} | Sorted by {[c for c, _ in sort_priority]} | Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            # Restore selection if it still exists
            if selected_iid and tree.exists(selected_iid[0]):
                tree.selection_set(selected_iid[0])

            tree.after(get_refresh_ms(), lambda: update_process_list(tree, status_var, pid_filter_var, columns))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# ---------- Memory tab (unchanged) ----------
def update_memory_tab(tree, status_var):
    def worker():
        mem = memory_module.get_system_memory()
        keep_keys = ["total", "available", "used", "free"]
        rows = [(k, f"{mem[k] / 1024 / 1024:.1f} MB") for k in keep_keys if k in mem]

        def update_ui():
            for row in tree.get_children():
                tree.delete(row)
            for k, v in rows:
                tree.insert("", "end", values=(k, v))
            status_var.set(f"Memory refreshed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            tree.after(max(get_refresh_ms() * 4, 1000), lambda: update_memory_tab(tree, status_var))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# ---------- Users tab (unchanged) ----------
def update_users_tab(tree, status_var):
    def worker():
        users = user_module.get_logged_in_users()

        def update_ui():
            for row in tree.get_children():
                tree.delete(row)
            for u in users:
                tree.insert("", "end", values=(u['name'], u['terminal'], u['host'], u['started'], u['pid']))
            status_var.set(f"Users refreshed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            tree.after(max(get_refresh_ms() * 8, 2000), lambda: update_users_tab(tree, status_var))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


def update_rights_tab(label):
    label.config(text=f"Running as Admin: {'Yes' if rights_module.is_admin() else 'No'}")


# ---------- Network tab with sorting ----------
# We'll keep the network table update similar but apply network_sort_priority
_network_last_rows = []


def update_network_tab(tree, status_var):
    def worker():
        rows = []
        try:
            rows = network_module.get_network_rows()
        except Exception:
            rows = []
        filtered = []
        for pid, l, r, st in rows:
            try:
                if pid and int(pid) == THIS_PID:
                    continue
            except Exception:
                pass
            filtered.append((pid, l, r, st))

        # store last rows for client-side sorting/refetch
        try:
            global _network_last_rows
            _network_last_rows = list(filtered)
        except Exception:
            pass

        def update_ui():
            for row in tree.get_children():
                tree.delete(row)
            # apply network_sort_priority
            rows_to_show = list(filtered)
            def net_key(col: str, rec):
                if col == "PID":
                    try:
                        return int(rec[0]) if rec[0] and rec[0] != "-" else -1
                    except Exception:
                        return -1
                elif col == "Local":
                    return rec[1] or ""
                elif col == "Remote":
                    return rec[2] or ""
                elif col == "Status":
                    return rec[3] or ""
                return ""
            for col, desc in reversed(network_sort_priority):
                rows_to_show.sort(key=lambda r, c=col: net_key(c, r), reverse=desc)
            for r in rows_to_show:
                tree.insert("", "end", values=r)
            status_var.set(f"Connections: {len(rows_to_show)} | Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            tree.after(max(get_refresh_ms() * 4, 1000), lambda: update_network_tab(tree, status_var))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


def update_network_list_sort_and_refresh():
    # helper to reapply sort to current network tree contents without refetching
    try:
        update_network_tab(net_tree, net_status)
    except Exception:
        pass


# ---------- Events helpers (unchanged) ----------
def read_events_for_log(log_name: str, max_records=200):
    if not SETTINGS.get("event_reading_enabled", True):
        return [{
            "time": "",
            "source": "",
            "event_id": "",
            "category": "",
            "msg": "(event reading disabled)",
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
    if not HAS_EVENTLOG or not eventlog_module:
        return [{
            "time": "",
            "source": "",
            "event_id": "",
            "category": "",
            "msg": "(event log reading not available — pywin32 missing)",
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
    try:
        return eventlog_module.read_events(log_name=log_name, max_records=max_records)
    except Exception as e:
        return [{
            "time": "",
            "source": "",
            "event_id": "",
            "category": "",
            "msg": f"(failed to read {log_name}: {e})",
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


def read_administrative_events(max_per_log=50):
    logs = ["Application", "Security", "System"]
    combined = []
    for l in logs:
        evs = read_events_for_log(l, max_records=max_per_log)
        for ev in evs:
            ev_copy = dict(ev)
            ev_copy["_origin_log"] = l
            combined.append(ev_copy)
    try:
        combined.sort(key=lambda e: e.get("time", ""), reverse=True)
    except Exception:
        pass
    return combined


def update_events_list(tree, status_var, events, details_text):
    def ui():
        for row in tree.get_children():
            tree.delete(row)
        if not events:
            tree.insert("", "end", values=("No events", "", "", "", ""))
            tree._last_filtered = []
            status_var.set(f"Events: 0 | Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            details_text.config(state="normal")
            details_text.delete("1.0", "end")
            details_text.insert("1.0", "Click on any event for details")
            details_text.config(state="disabled")
            return

        for ev in events:
            msg = ev.get("msg", "") or ""
            short = msg if len(msg) <= 200 else (msg[:197] + "...")
            time = ev.get("time", "")
            src = ev.get("source", "") or ev.get("_origin_log", "")
            eid = ev.get("event_id", "")
            cat_text = get_friendly_category(ev)
            tree.insert("", "end", values=(time, src, eid, cat_text, short))
        tree._last_filtered = events
        status_var.set(f"Events: {len(events)} | Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if events and isinstance(events[0], dict) and events[0].get("error"):
            err_msg = events[0].get("msg", "Unable to read events.")
            details_text.config(state="normal")
            details_text.delete("1.0", "end")
            details_text.insert("1.0", f"{err_msg}\n\nTip: run Intrusense with Administrator privileges to view restricted logs (e.g. Security).")
            details_text.config(state="disabled")
        else:
            details_text.config(state="normal")
            details_text.delete("1.0", "end")
            details_text.insert("1.0", "Click on any event for details")
            details_text.config(state="disabled")

    tree.after(0, ui)


def update_events_tab_for_log(tree, status_var, details_text, log_name, event_id_filter=None, source_substr=None, text_filter=None, max_records=200):
    def worker():
        if log_name == "Administrative Events":
            evs = read_administrative_events(max_per_log=80)
        else:
            evs = read_events_for_log(log_name, max_records=max_records)

        out = []
        eid = None
        if event_id_filter:
            try:
                eid = int(event_id_filter)
            except Exception:
                eid = None
        ssub = (source_substr or "").strip().lower() if source_substr else None
        tfilter = (text_filter or "").strip().lower() if text_filter else None

        for ev in evs:
            try:
                if ev.get("error"):
                    out.append(ev)
                    continue
                if eid is not None:
                    try:
                        if int(ev.get("event_id", -1)) != eid:
                            continue
                    except Exception:
                        continue
                if ssub:
                    if ssub not in (ev.get("source", "") or "").lower():
                        continue
                if tfilter:
                    msg = (ev.get("msg", "") or "").lower()
                    src = (ev.get("source", "") or "").lower()
                    if tfilter not in msg and tfilter not in src and tfilter not in str(ev.get("event_id", "")).lower():
                        continue
                out.append(ev)
            except Exception:
                continue

        update_events_list(tree, status_var, out, details_text)

    threading.Thread(target=worker, daemon=True).start()


def _build_event_details_text(ev: Dict[str, Any]) -> str:
    if not ev:
        return "<no event>"

    time = ev.get("time", None)
    eid = ev.get("event_id", None)
    level = ev.get("level", None)
    user = ev.get("user", None)
    opcode = ev.get("opcode", None)
    logged = time
    task = ev.get("task", None)
    keywords = ev.get("keywords", None)
    computer = ev.get("computer", None)
    record_no = ev.get("record_number", None)
    source = ev.get("source", None)
    origin = ev.get("_origin_log", None)

    if HAS_EVENTLOG and eventlog_module:
        full_msg = eventlog_module.get_full_message(ev)
    else:
        full_msg = ev.get("msg", "") or "<no message>"

    lines = []
    if origin:
        lines.append(f"Log Name: {origin}")
    if source:
        lines.append(f"Source: {source}")

    eid_str = str(eid) if eid is not None else None
    level_str = str(level) if level is not None else None
    if eid_str or level_str:
        parts = []
        if eid_str:
            parts.append(f"Event ID: {eid_str}")
        if level_str:
            parts.append(f"Level: {level_str}")
        lines.append("    ".join(parts))

    if user and user != "Unavailable":
        lines.append(f"User: {user}")
    if opcode and opcode != "Unavailable":
        lines.append(f"OpCode: {opcode}")
    if logged:
        lines.append(f"Logged: {logged}")
    friendly_cat = get_friendly_category(ev)
    if friendly_cat:
        lines.append(f"Task Category: {friendly_cat}")
    elif task and task != "Unavailable":
        lines.append(f"Task Category: {task}")
    if keywords and keywords != "Unavailable":
        lines.append(f"Keywords: {keywords}")
    if computer and computer != "Unavailable":
        lines.append(f"Computer: {computer}")
    if record_no and record_no != "Unavailable":
        lines.append(f"Record Number: {record_no}")

    lines.append("")  # spacer
    lines.append("General:")
    lines.append(full_msg or "<no message>")
    lines.append("")
    lines.append("----")
    lines.append("Note: Event descriptions are resolved by the Windows Event Log API")
    lines.append("using localized message resource DLLs. If the resource isn't available")
    lines.append("or can't be read (missing DLL, permissions, mismatch), the API may")
    lines.append("be unable to format localized text. Intrusense will show insertion")
    lines.append("strings or a best-effort message assembled from available data.")
    return "\n".join(lines)


def on_event_row_click(event, tree, details_text):
    try:
        iid = tree.identify_row(event.y)
        if not iid:
            return
        children = list(tree.get_children())
        if iid not in children:
            return
        idx = children.index(iid)
        evs = getattr(tree, "_last_filtered", []) or []
        if idx < 0 or idx >= len(evs):
            return
        ev = evs[idx]
        details = _build_event_details_text(ev)
        details_text.config(state="normal")
        details_text.delete("1.0", "end")
        details_text.insert("1.0", details)
        details_text.config(state="disabled")
    except Exception:
        return


def on_event_row_double_click(event, tree):
    try:
        iid = tree.identify_row(event.y)
        if not iid:
            return
        children = list(tree.get_children())
        if iid not in children:
            return
        idx = children.index(iid)
        evs = getattr(tree, "_last_filtered", []) or []
        if idx < 0 or idx >= len(evs):
            return
        ev = evs[idx]
        details = _build_event_details_text(ev)
        dlg = tk.Toplevel()
        dlg.title("Event details")
        dlg.geometry("900x700")
        text = tk.Text(dlg, wrap="word")
        text.insert("1.0", details)
        text.config(state="disabled")
        text.pack(fill=tk.BOTH, expand=True)
        ttk.Button(dlg, text="Close", command=dlg.destroy).pack(pady=6)
    except Exception:
        return


# ---------- Export current processes ----------
def export_processes(tree):
    # Gather current rows and export
    rows = []
    for iid in tree.get_children():
        vals = tree.item(iid, "values")
        rows.append(vals)
    if not rows:
        messagebox.showinfo("Export processes", "No processes to export.")
        return

    home = os.path.expanduser("~")
    desk = os.path.join(home, "Desktop")
    default = os.path.join(desk, f"intrusense_processes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    fname = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=os.path.basename(default),
                                         filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if not fname:
        return

    def worker():
        try:
            with open(fname, "w", newline='', encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["PID", "Name", "User", "CPU%", "MemoryMB"])
                for r in rows:
                    # values in tree are strings; strip the '│' separators if present
                    clean = [str(x).lstrip("│") for x in r]
                    w.writerow(clean)
            messagebox.showinfo("Export processes", f"Exported {len(rows)} processes to:\n{fname}")
        except Exception as e:
            messagebox.showerror("Export processes", f"Failed to export: {e}")

    threading.Thread(target=worker, daemon=True).start()


# ---------- Process action helpers (run in thread) ----------
def _get_selected_proc_from_tree(tree):
    sel = tree.selection()
    if not sel:
        return None
    iid = sel[0]
    vals = tree.item(iid, "values") or ()
    if not vals:
        return None
    pid = vals[0]
    try:
        pid_int = int(pid)
        return pid_int, vals[1] if len(vals) > 1 else ""
    except Exception:
        return None


def _perform_proc_action(action: str, pid: int, root):
    # Run privileged action safely in a background thread
    def worker():
        try:
            p = psutil.Process(pid)
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Process action", f"Process {pid} not found: {e}"))
            return

        try:
            if action == "terminate":
                p.terminate()
                root.after(0, lambda: messagebox.showinfo("Terminate", f"Sent terminate to PID {pid}"))
            elif action == "suspend":
                try:
                    p.suspend()
                    root.after(0, lambda: messagebox.showinfo("Suspend", f"Suspended PID {pid}"))
                except Exception as ex:
                    root.after(0, lambda: messagebox.showerror("Suspend", f"Failed to suspend PID {pid}: {ex}"))
            elif action == "resume":
                try:
                    p.resume()
                    root.after(0, lambda: messagebox.showinfo("Resume", f"Resumed PID {pid}"))
                except Exception as ex:
                    root.after(0, lambda: messagebox.showerror("Resume", f"Failed to resume PID {pid}: {ex}"))
            elif action == "open_location":
                try:
                    exe = p.exe()
                    if exe:
                        folder = os.path.dirname(exe)
                        if os.path.exists(folder):
                            try:
                                os.startfile(folder)
                                root.after(0, lambda: None)
                            except Exception as ex:
                                root.after(0, lambda: messagebox.showerror("Open location", f"Failed to open folder: {ex}"))
                        else:
                            root.after(0, lambda: messagebox.showerror("Open location", "Folder not found"))
                    else:
                        root.after(0, lambda: messagebox.showerror("Open location", "Executable path not available"))
                except (psutil.AccessDenied, psutil.NoSuchProcess) as ex:
                    root.after(0, lambda: messagebox.showerror("Open location", f"Access denied or process gone: {ex}"))
                except Exception as ex:
                    root.after(0, lambda: messagebox.showerror("Open location", f"Failed: {ex}"))
        finally:
            # after action, refresh process list
            try:
                root.after(200, lambda: update_process_list(proc_tree, proc_status, pid_filter_var, ("PID", "Name", "User", "CPU %", "Memory")))
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()


# ---------- Context menu for process tree (UNCHANGED logic, menu text is the same) ----------
def _on_proc_right_click(event):
    # Show context menu on right-click row
    try:
        iid = proc_tree.identify_row(event.y)
        if not iid:
            return
        proc_tree.selection_set(iid)
        sel = _get_selected_proc_from_tree(proc_tree)
        if not sel:
            return
        pid, pname = sel

        menu = tk.Menu(proc_tree, tearoff=0)
        menu.add_command(label=f"Copy PID ({pid})", command=lambda: (root.clipboard_clear(), root.clipboard_append(str(pid))))
        menu.add_command(label=f"Copy Name ({pname})", command=lambda: (root.clipboard_clear(), root.clipboard_append(str(pname))))
        menu.add_separator()
        menu.add_command(label="Open file location", command=lambda: _perform_proc_action("open_location", pid, root))
        menu.add_separator()
        menu.add_command(label="End Task (terminate)", command=lambda: _confirm_and_run("terminate", pid))
        menu.add_command(label="Kill (force)", command=lambda: _confirm_and_run("kill", pid))
        menu.add_command(label="Kill Process & Children (force)", command=lambda: _confirm_and_run("kill_tree", pid)) # NEW
        menu.add_separator()
        menu.add_command(label="Suspend", command=lambda: _confirm_and_run("suspend", pid))
        menu.add_command(label="Resume", command=lambda: _confirm_and_run("resume", pid))
        menu.tk_popup(event.x_root, event.y_root)
    except Exception:
        return

# ---------- CONFIRMATION DIALOG TEXT (UPDATED) ----------
def _confirm_and_run(action, pid):
    # Confirmation dialog then run action (UPDATED)
    try:
        if action == "terminate":
            if not messagebox.askyesno("Confirm terminate", f"Send terminate to PID {pid}?"):
                return
            _perform_proc_action(action, pid, root)
            
        elif action == "kill":
            # --- UPDATED TEXT ---
            if not messagebox.askyesno("Confirm kill", f"Force kill process {pid}?\n\nThis may cause data loss."):
                return
            kill_with_powershell(pid, root, _on_kill_done)
            
        elif action == "kill_tree":
            # --- UPDATED TEXT ---
            if not messagebox.askyesno("Confirm kill tree", f"Force kill process {pid} and all its children?\n\nThis will cause data loss."):
                return
            kill_tree_with_fallback(pid, root, _on_kill_done)
            
        elif action in ("suspend", "resume"):
            if not messagebox.askyesno("Confirm", f"{action.title()} PID {pid}?"):
                return
            _perform_proc_action(action, pid, root)
            
    except Exception:
        return


# ---------- Export events (unchanged) ----------
def export_current_events(events_tree):
    evs = getattr(events_tree, "_last_filtered", []) or []
    if not evs:
        messagebox.showinfo("Export events", "No events to export.")
        return
    home = os.path.expanduser("~")
    desk = os.path.join(home, "Desktop")
    default = os.path.join(desk, f"intrusense_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    fname = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=os.path.basename(default),
                                         filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if not fname:
        return

    def worker():
        try:
            with open(fname, "w", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["time", "source", "event_id", "category", "message", "computer", "level", "user", "record_number"])
                for ev in evs:
                    writer.writerow([
                        ev.get("time", ""),
                        ev.get("source", ""),
                        ev.get("event_id", ""),
                        ev.get("category", ""),
                        (ev.get("msg", "") or "").replace("\n", " ").strip(),
                        ev.get("computer", ""),
                        ev.get("level", ""),
                        ev.get("user", ""),
                        ev.get("record_number", "")
                    ])
            messagebox.showinfo("Export events", f"Exported {len(evs)} events to:\n{fname}")
        except Exception as e:
            messagebox.showerror("Export events", f"Failed to export events: {e}")

    threading.Thread(target=worker, daemon=True).start()


# ---------- Settings dialog (unchanged) ----------
def open_settings_dialog(root):
    dlg = tk.Toplevel(root)
    dlg.title("Settings")
    dlg.geometry("420x220")
    dlg.transient(root)

    ttk.Label(dlg, text="Refresh interval (ms):").pack(anchor="w", padx=10, pady=(10,0))
    rvar = tk.IntVar(value=int(SETTINGS.get("refresh_ms", 500)))
    rentry = ttk.Entry(dlg, textvariable=rvar, width=12)
    rentry.pack(anchor="w", padx=10, pady=(0,6))

    sp_var = tk.BooleanVar(value=SETTINGS.get("show_python_procs", False))
    ttk.Checkbutton(dlg, text="Show python processes", variable=sp_var).pack(anchor="w", padx=10, pady=4)

    er_var = tk.BooleanVar(value=SETTINGS.get("event_reading_enabled", True))
    ttk.Checkbutton(dlg, text="Enable event reading (pywin32)", variable=er_var).pack(anchor="w", padx=10, pady=4)

    def _save():
        try:
            new_r = int(rvar.get())
            if new_r < 100:
                new_r = 100
            set_setting("refresh_ms", new_r)
            set_setting("show_python_procs", bool(sp_var.get()))
            set_setting("event_reading_enabled", bool(er_var.get()))
            dlg.destroy()
        except Exception:
            dlg.destroy()

    ttk.Button(dlg, text="Save", command=_save).pack(side=tk.RIGHT, padx=10, pady=12)
    ttk.Button(dlg, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT, padx=(0,6), pady=12)


# ---------- Main UI (UPDATED for name search) ----------
def main():
    global proc_tree, proc_status, pid_filter_var, root, net_tree, net_status

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    root = tk.Tk()
    root.title("Intrusense - Phase 1")
    try:
        w = int(SETTINGS.get("window_width", 1300))
        h = int(SETTINGS.get("window_height", 750))
        root.geometry(f"{w}x{h}")
    except Exception:
        root.geometry("1300x750")

    style = ttk.Style()
    try:
        style.theme_use('vista')
    except tk.TclError:
        style.theme_use('clam')
    style.configure('Treeview', rowheight=22)
    style.configure('Treeview.Heading', font=(None, 10, 'bold'))

    # warm up CPU counters
    try:
        for p in psutil.process_iter(['pid']):
            try:
                p.cpu_percent(None)
            except Exception:
                pass
        try:
            psutil.cpu_percent(None)
        except Exception:
            pass
    except Exception:
        pass

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)
    main_state.notebook = notebook

    # topbar with settings and process export
    topbar = ttk.Frame(root)
    topbar.pack(fill=tk.X, side=tk.TOP)
    ttk.Button(topbar, text="Settings", command=lambda: open_settings_dialog(root)).pack(side=tk.RIGHT, padx=8, pady=6)
    ttk.Button(topbar, text="Export processes", command=lambda: export_processes(proc_tree)).pack(side=tk.RIGHT, padx=8, pady=6)

    # Processes tab
    process_frame = ttk.Frame(notebook)
    notebook.add(process_frame, text="Processes")
    search_frame = ttk.Frame(process_frame)
    search_frame.pack(fill=tk.X, padx=5, pady=3)
    pid_filter_var = tk.StringVar()
    
    # --- UPDATED: Changed label text ---
    ttk.Label(search_frame, text="Search (PID or Name):").pack(side=tk.LEFT, padx=(0, 5))
    # --- END UPDATE ---
    
    pid_entry = ttk.Entry(search_frame, textvariable=pid_filter_var, width=20)
    pid_entry.pack(side=tk.LEFT)
    ttk.Button(search_frame, text="Clear", command=lambda: pid_filter_var.set("")).pack(side=tk.LEFT, padx=(5, 0))

    proc_columns = ("PID", "Name", "User", "CPU %", "Memory")
    proc_table_frame = ttk.Frame(process_frame)
    proc_table_frame.pack(fill=tk.BOTH, expand=True)
    proc_tree = ttk.Treeview(proc_table_frame, columns=proc_columns, show="headings", selectmode="browse")
    for col in proc_columns:
        anchor = "e" if col in ("PID", "CPU %", "Memory") else "w"
        proc_tree.heading(col, text=header_text(col, net=False), anchor=anchor)
        proc_tree.column(col, anchor=anchor, width=120)
    ysb_proc = ttk.Scrollbar(proc_table_frame, orient="vertical", command=proc_tree.yview)
    proc_tree.configure(yscrollcommand=ysb_proc.set)
    proc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_proc.pack(side=tk.RIGHT, fill=tk.Y)
    proc_status = tk.StringVar(value="Loading...")
    ttk.Label(process_frame, textvariable=proc_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    refresh_headers(proc_tree, proc_columns)
    proc_tree.after(get_refresh_ms(), lambda: update_process_list(proc_tree, proc_status, pid_filter_var, proc_columns))

    # header click sorting for processes
    def on_proc_tree_click(event):
        region = proc_tree.identify("region", event.x, event.y)
        if region != "heading":
            return
        col_id = proc_tree.identify_column(event.x)
        try:
            idx = int(col_id.replace("#", "")) - 1
            if 0 <= idx < len(proc_columns):
                additive = (getattr(event, "state", 0) & 0x0001) != 0
                set_sort(proc_columns[idx], additive)
        except Exception:
            pass

    proc_tree.bind("<Button-1>", on_proc_tree_click, add="+")
    proc_tree.bind("<Button-3>", _on_proc_right_click, add="+")  # right-click menu

    # Memory tab
    mem_frame = ttk.Frame(notebook)
    notebook.add(mem_frame, text="Memory")
    mem_table_frame = ttk.Frame(mem_frame)
    mem_table_frame.pack(fill=tk.BOTH, expand=True)
    mem_tree = ttk.Treeview(mem_table_frame, columns=("Key", "Value"), show="headings")
    for col in ("Key", "Value"):
        mem_tree.heading(col, text=col, anchor="w")
        mem_tree.column(col, anchor="w", width=250)
    ysb_mem = ttk.Scrollbar(mem_table_frame, orient="vertical", command=mem_tree.yview)
    mem_tree.configure(yscrollcommand=ysb_mem.set)
    mem_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_mem.pack(side=tk.RIGHT, fill=tk.Y)
    mem_status = tk.StringVar(value="Loading...")
    ttk.Label(mem_frame, textvariable=mem_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    mem_tree.after(0, lambda: update_memory_tab(mem_tree, mem_status))

    # Users tab
    user_frame = ttk.Frame(notebook)
    notebook.add(user_frame, text="Users")
    user_table_frame = ttk.Frame(user_frame)
    user_table_frame.pack(fill=tk.BOTH, expand=True)
    user_tree = ttk.Treeview(user_table_frame, columns=("Name", "Terminal", "Host", "Started", "PID"), show="headings")
    for col in ("Name", "Terminal", "Host", "Started", "PID"):
        anchor = "e" if col == "PID" else "w"
        user_tree.heading(col, text=col, anchor=anchor)
        user_tree.column(col, anchor=anchor, width=180)
    ysb_user = ttk.Scrollbar(user_table_frame, orient="vertical", command=user_tree.yview)
    user_tree.configure(yscrollcommand=ysb_user.set)
    user_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_user.pack(side=tk.RIGHT, fill=tk.Y)
    user_status = tk.StringVar(value="Loading...")
    ttk.Label(user_frame, textvariable=user_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    user_tree.after(0, lambda: update_users_tab(user_tree, user_status))

    # Rights tab
    rights_frame = ttk.Frame(notebook)
    notebook.add(rights_frame, text="Rights")
    rights_label = ttk.Label(rights_frame, text="Checking...")
    rights_label.pack(anchor="w", padx=10, pady=10)
    update_rights_tab(rights_label)

    # Network tab (with sorting)
    net_frame = ttk.Frame(notebook)
    notebook.add(net_frame, text="Network")
    net_table_frame = ttk.Frame(net_frame)
    net_table_frame.pack(fill=tk.BOTH, expand=True)
    net_cols = ("PID", "Local", "Remote", "Status")
    net_tree = ttk.Treeview(net_table_frame, columns=net_cols, show="headings", selectmode="browse")
    for col in net_cols:
        anchor = "e" if col == "PID" else "w"
        net_tree.heading(col, text=header_text(col, net=True), anchor=anchor)
        net_tree.column(col, anchor=anchor, width=220)
    ysb_net = ttk.Scrollbar(net_table_frame, orient="vertical", command=net_tree.yview)
    net_tree.configure(yscrollcommand=ysb_net.set)
    net_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_net.pack(side=tk.RIGHT, fill=tk.Y)
    net_status = tk.StringVar(value="Loading...")
    ttk.Label(net_frame, textvariable=net_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    net_tree.after(0, lambda: update_network_tab(net_tree, net_status))

    # header click sorting for network
    def on_net_tree_click(event):
        region = net_tree.identify("region", event.x, event.y)
        if region != "heading":
            return
        col_id = net_tree.identify_column(event.x)
        try:
            idx = int(col_id.replace("#", "")) - 1
            if 0 <= idx < len(net_cols):
                additive = (getattr(event, "state", 0) & 0x0001) != 0
                set_network_sort(net_cols[idx], additive)
        except Exception:
            pass

    net_tree.bind("<Button-1>", on_net_tree_click, add="+")

    # Events tab (left: logs, middle: events, right: details)
    events_frame = ttk.Frame(notebook)
    notebook.add(events_frame, text="Events")
    main_state.events_tab_index = notebook.index(events_frame)
    events_panes = ttk.PanedWindow(events_frame, orient=tk.HORIZONTAL)
    events_panes.pack(fill=tk.BOTH, expand=True)

    # Left: logs hierarchy
    logs_frame = ttk.Frame(events_panes)
    events_panes.add(logs_frame, weight=1)
    ttk.Label(logs_frame, text="Log categories:", anchor="w").pack(fill=tk.X, padx=6, pady=(6, 0))
    logs_tree = ttk.Treeview(logs_frame, columns=("col",), show="tree")
    logs_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    if HAS_EVENTLOG and eventlog_module:
        logs_hierarchy = eventlog_module.list_known_logs()
    else:
        logs_hierarchy = {
            "Administrative Views": ["Administrative Events"],
            "Windows Logs": ["Application", "Security", "Setup", "System"]
        }

    root_custom = logs_tree.insert("", "end", text="Administrative Views", open=True)
    for item in logs_hierarchy.get("Administrative Views", []):
        logs_tree.insert(root_custom, "end", text=item, values=(item,))

    root_win = logs_tree.insert("", "end", text="Windows Logs", open=True)
    for item in logs_hierarchy.get("Windows Logs", []):
        logs_tree.insert(root_win, "end", text=item, values=(item,))

    # Middle: events list with compact filter and export
    events_list_frame = ttk.Frame(events_panes)
    events_panes.add(events_list_frame, weight=3)
    filter_frame = ttk.Frame(events_list_frame)
    filter_frame.pack(fill=tk.X, padx=6, pady=(6,4))
    ttk.Label(filter_frame, text="Filter (source/message/ID):").pack(side=tk.LEFT, padx=(0,6))
    event_filter_var = tk.StringVar()
    event_filter_entry = ttk.Entry(filter_frame, textvariable=event_filter_var, width=36)
    event_filter_entry.pack(side=tk.LEFT)
    current_log_name = tk.StringVar(value="Administrative Events")
    ttk.Button(filter_frame, text="Apply", command=lambda: update_events_tab_for_log(events_tree, events_status, details_text, current_log_name.get(), text_filter=event_filter_var.get(), max_records=200)).pack(side=tk.LEFT, padx=6)
    ttk.Button(filter_frame, text="Clear", command=lambda: (event_filter_var.set(""), update_events_tab_for_log(events_tree, events_status, details_text, current_log_name.get(), max_records=200))).pack(side=tk.LEFT)
    ttk.Button(filter_frame, text="Export events", command=lambda: export_current_events(events_tree)).pack(side=tk.RIGHT, padx=(0,6))

    events_cols = ("Time", "Source", "EventID", "Category", "Message")
    events_tree = ttk.Treeview(events_list_frame, columns=events_cols, show="headings")
    for col in events_cols:
        anchor = "w" if col in ("Source", "Message") else "e"
        events_tree.heading(col, text=col, anchor=anchor)
        width = 420 if col == "Message" else 140
        events_tree.column(col, anchor=anchor, width=width)
    events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_events = ttk.Scrollbar(events_list_frame, orient="vertical", command=events_tree.yview)
    events_tree.configure(yscrollcommand=ysb_events.set)
    ysb_events.pack(side=tk.RIGHT, fill=tk.Y)

    # Right: details pane
    details_frame = ttk.Frame(events_panes)
    events_panes.add(details_frame, weight=2)
    ttk.Label(details_frame, text="Event details:", anchor="w").pack(fill=tk.X, padx=6, pady=(6, 0))
    details_text = tk.Text(details_frame, wrap="word", state="disabled", width=60)
    details_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
    events_status = tk.StringVar(value="Loading...")
    ttk.Label(events_frame, textvariable=events_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)

    def on_logs_tree_select(event):
        sel = logs_tree.selection()
        if not sel:
            return
        node = sel[0]
        val = logs_tree.item(node, "text")
        if val in ("Administrative Views", "Windows Logs"):
            return
        log_name = val
        current_log_name.set(log_name)
        details_text.config(state="normal")
        details_text.delete("1.0", "end")
        details_text.insert("1.0", "Click on any event for details")
        details_text.config(state="disabled")
        update_events_tab_for_log(events_tree, events_status, details_text, log_name, max_records=200, text_filter=event_filter_var.get())

    logs_tree.bind("<<TreeviewSelect>>", on_logs_tree_select)
    events_tree.bind("<Button-1>", lambda e: on_event_row_click(e, events_tree, details_text))
    events_tree.bind("<Double-1>", lambda e: on_event_row_double_click(e, events_tree))

    # Auto-select Administrative Events if present
    try:
        for iid in logs_tree.get_children(root_custom):
            if logs_tree.item(iid, "text") == "Administrative Events":
                logs_tree.selection_set(iid)
                logs_tree.see(iid)
                update_events_tab_for_log(events_tree, events_status, details_text, "Administrative Events", max_records=200)
                current_log_name.set("Administrative Events")
                break
    except Exception:
        pass

    # Save window size and settings on close
    def _on_close():
        try:
            geom = root.geometry().split('+')[0]
            if 'x' in geom:
                w, h = geom.split('x')
                set_setting("window_width", int(w))
                set_setting("window_height", int(h))
        except Exception:
            pass
        try:
            if settings_helper:
                settings_helper.save_settings(SETTINGS)
        except Exception:
            pass
        try:
            root.destroy()
        except Exception:
            os._exit(0)

    root.protocol("WM_DELETE_WINDOW", _on_close)
    root.mainloop()



# killing processes using background powershell script
def _run_command(cmd: list, timeout: int = 8) -> dict:
    """Run a command list, return dict with returncode, stdout, stderr."""
    try:
        # Prevent console window from flashing
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, shell=False, startupinfo=startupinfo)
        return {"rc": proc.returncode, "out": proc.stdout or "", "err": proc.stderr or ""}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "out": "", "err": "timeout"}
    except Exception as e:
        return {"rc": -1, "out": "", "err": str(e)}

def kill_with_powershell(pid: int, root, on_done=None):
    """
    Try to kill PID using PowerShell Stop-Process (force). Runs in background.
    """
    def worker():
        result = {"method": "powershell", "rc": -1, "out": "", "err": ""}

        if platform.system().lower() != "windows":
            result["err"] = "Not running on Windows"
            if on_done:
                root.after(0, lambda: on_done(result))
            return

        try:
            pid_i = int(pid)
            if pid_i <= 0:
                raise ValueError("invalid pid")
        except Exception as e:
            result["err"] = f"Invalid PID: {e}"
            if on_done:
                root.after(0, lambda: on_done(result))
            return

        ps_cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            f"Try {{ Stop-Process -Id {pid_i} -Force -ErrorAction Stop; Write-Output 'OK' }} Catch {{ Write-Error $_.Exception.Message; exit 1 }}"
        ]
        r = _run_command(ps_cmd, timeout=10)
        result.update({"rc": r["rc"], "out": r["out"], "err": r["err"]})
        if r["rc"] == 0:
            if on_done:
                root.after(0, lambda: on_done(result))
            return

        # Fallback: taskkill
        task_cmd = ["taskkill", "/PID", str(pid_i), "/F"]
        r2 = _run_command(task_cmd, timeout=8)
        result.update({"method": "taskkill", "rc": r2["rc"], "out": r2["out"], "err": r2["err"]})
        if on_done:
            root.after(0, lambda: on_done(result))

    threading.Thread(target=worker, daemon=True).start()

def kill_tree_with_fallback(pid: int, root, on_done=None):
    """
    Try to kill PID AND ITS CHILDREN using taskkill /T /F.
    """
    def worker():
        result = {"method": "taskkill_tree", "rc": -1, "out": "", "err": ""}

        if platform.system().lower() != "windows":
            result["err"] = "Not running on Windows"
            if on_done:
                root.after(0, lambda: on_done(result))
            return
        
        try:
            pid_i = int(pid)
        except Exception:
            result["err"] = f"Invalid PID: {pid}"
            if on_done:
                root.after(0, lambda: on_done(result))
            return

        # Use taskkill /T (tree) /F (force)
        task_cmd = ["taskkill", "/PID", str(pid_i), "/T", "/F"]
        r = _run_command(task_cmd, timeout=10)
        
        result.update({"rc": r["rc"], "out": r["out"], "err": r["err"]})
        
        if r["rc"] != 0 and "child process" not in (r["err"] or "").lower():
            # If taskkill /T fails, try to get children with psutil
            try:
                parent = psutil.Process(pid_i)
                children = parent.children(recursive=True)
                for child in reversed(children):
                    child.kill()
                parent.kill()
                result.update({"method": "psutil_fallback", "rc": 0, "out": "Killed process tree."})
            except Exception as e:
                result["err"] = f"taskkill failed and psutil fallback also failed: {e}"
        
        if on_done:
            root.after(0, lambda: on_done(result))

    threading.Thread(target=worker, daemon=True).start()


# ---------- RESULT DIALOG TEXT (UPDATED) ----------
def _on_kill_done(result):
    """Show message after process kill attempt and refresh process list."""
    rc = result.get("rc", -1)
    err = result.get("err", "").strip()

    if rc == 0:
        # --- UPDATED TEXT ---
        messagebox.showinfo("End process", "The process was successfully terminated.")
    else:
        # Specific error for "access denied"
        if "Access is denied" in err or "Operation could not be completed" in err or "rc=1" in err or "rc=5" in err:
             # --- UPDATED TEXT ---
             messagebox.showerror("End process failed", "Access is denied.\n\Try running Intrusense as Administrator.")
        else:
            # --- UPDATED TEXT ---
            messagebox.showerror("End process failed", f"Failed to terminate process.\n\nError: {err}")

    # refresh the process list afterward
    try:
        update_process_list(proc_tree, proc_status, pid_filter_var, ("PID","Name","User","CPU %","Memory"))
    except Exception:
        pass

if __name__ == "__main__":
    main()