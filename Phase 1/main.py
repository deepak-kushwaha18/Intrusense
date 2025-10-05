import os
import tkinter as tk
from tkinter import ttk
import psutil
from datetime import datetime
import logging
import threading
from typing import Dict, Any, Optional

import process_module
import memory_module
import user_module
import rights_module
import network_module

# Windows event helper: try to load it, but the app works fine without it.
try:
    import eventlog_module
    HAS_EVENTLOG = True
except Exception:
    eventlog_module = None
    HAS_EVENTLOG = False

# UI refresh interval (ms). Kept at 500ms to avoid CPU spikes.
REFRESH_MS = 500

# Default sorting: primary key is CPU percent.
sort_priority = [("CPU %", True)]
ALLOWED_SORT_COLUMNS = {"PID", "CPU %", "Memory"}

# Skip showing the Python process and similar processes because they often dominate CPU.
IGNORE_PROCESS_NAMES = {"python.exe", "pythonw.exe"}
THIS_PID = os.getpid()


def default_desc(col: str) -> bool:
    # Numeric columns default to descending sort.
    return col in ("PID", "CPU %", "Memory")


def header_text(col: str) -> str:
    # Show arrow + order index for sortable columns.
    if col not in ALLOWED_SORT_COLUMNS:
        return col
    for idx, (c, desc) in enumerate(sort_priority):
        if c == col:
            order = f"[{idx + 1}]"
            return f"{col} {'▼' if desc else '▲'}{order}"
    return col


def set_sort(col: str, additive: bool = False):
    # Update sort keys. Click = primary toggle, shift+click = add/toggle multi-sort.
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
    # Refresh headers and process list (best-effort).
    try:
        refresh_headers(proc_tree, ("PID", "Name", "User", "CPU %", "Memory"))
        update_process_list(proc_tree, proc_status, pid_filter_var, ("PID", "Name", "User", "CPU %", "Memory"))
    except Exception:
        pass


# Small mapping from known source names to readable category labels.
_SOURCE_CATEGORY_HINTS = {
    "Kernel-Power": "Kernel-Power",
    "Kernel-General": "Kernel",
    "W32Time": "Time-Service",
    "Time-Service": "Time-Service",
    "Service Control Manager": "Service Control Manager",
    "ServiceControlManager": "Service Control Manager",
    "Application Error": "Application Error",
    "Application": "Application",
    "Microsoft-Windows-TaskScheduler": "Task Scheduler",
    "TaskScheduler": "Task Scheduler",
    "Task Scheduler": "Task Scheduler",
    "Microsoft-Windows-Windows Defender": "Windows Defender",
    "Security": "Security",
    "Microsoft-Windows-Security-Auditing": "Security (Auditing)",
}


def get_friendly_category(ev: Dict[str, Any]) -> str:
    # Return a friendly category: prefer task text, then source hints, then numeric fallback.
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


# -------- Processes tab --------
def refresh_headers(tree, columns):
    # Update headers to show current sort state.
    for idx, c in enumerate(columns):
        text = header_text(c)
        tree.heading(c, text=text)


def update_process_list(tree, status_var, pid_filter_var, columns):
    # Fetch process rows in a background thread, then update UI.
    def worker():
        digits_only = ''.join(ch for ch in pid_filter_var.get().strip() if ch.isdigit())
        proc_rows = process_module.get_process_rows(digits_only)
        filtered = []
        for (pid, name, user, cpu, mem) in proc_rows:
            try:
                if int(pid) == THIS_PID:
                    continue
            except Exception:
                pass
            if (name or "").lower() in IGNORE_PROCESS_NAMES:
                continue
            filtered.append((pid, name, user, cpu, mem))

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

        # Stable sorting: PID first, then apply sort_priority from last to first.
        filtered.sort(key=lambda r: int(r[0]))
        for col, desc in reversed(sort_priority):
            filtered.sort(key=lambda r, c=col: key_for(c, r), reverse=desc)

        def update_ui():
            # Replace tree contents with fresh rows.
            for row in tree.get_children():
                tree.delete(row)
            for idx, (pid, name, user, cpu, mem) in enumerate(filtered):
                tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
                display_values = [pid, name, user, f"{cpu:.1f}%", f"{mem:.1f} MB"]
                tree.insert("", "end", values=tuple(display_values), tags=(tag,))
            status_var.set(
                f"Processes: {len(filtered)} | Sorted by {[c for c, _ in sort_priority]} | Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            # Schedule next refresh.
            tree.after(REFRESH_MS, lambda: update_process_list(tree, status_var, pid_filter_var, columns))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# -------- Memory tab --------
def update_memory_tab(tree, status_var):
    # Read memory stats in background and update key/value view.
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
            tree.after(max(REFRESH_MS * 4, 1000), lambda: update_memory_tab(tree, status_var))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# -------- Users tab --------
def update_users_tab(tree, status_var):
    # Show logged-in user sessions; updated less frequently.
    def worker():
        users = user_module.get_logged_in_users()

        def update_ui():
            for row in tree.get_children():
                tree.delete(row)
            for u in users:
                tree.insert("", "end", values=(u['name'], u['terminal'], u['host'], u['started'], u['pid']))
            status_var.set(f"Users refreshed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            tree.after(max(REFRESH_MS * 8, 2000), lambda: update_users_tab(tree, status_var))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# -------- Rights tab --------
def update_rights_tab(label):
    # Simple admin rights indicator.
    admin = rights_module.is_admin()
    label.config(text=f"Running as Admin: {'Yes' if admin else 'No'}")


# -------- Network tab --------
def update_network_tab(tree, status_var):
    # Show active connections and owning PID if available.
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

        def update_ui():
            for row in tree.get_children():
                tree.delete(row)
            for r in filtered:
                tree.insert("", "end", values=r)
            status_var.set(f"Connections: {len(filtered)} | Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            tree.after(max(REFRESH_MS * 4, 1000), lambda: update_network_tab(tree, status_var))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# -------- Events helpers --------
def read_events_for_log(log_name: str, max_records=200):
    # Use eventlog_module if available; return an error entry otherwise.
    if not HAS_EVENTLOG or not eventlog_module:
        return [{
            "time": "",
            "source": "",
            "event_id": "",
            "category": "",
            "msg": "(event log reading not available — pywin32 not installed or missing)",
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
    # Build the unified Administrative Events view from App/Security/System.
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
    # Populate the middle events list; set instruction or error in details pane.
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
        # Show error tip when event reading failed (e.g. missing permissions).
        if events and isinstance(events[0], dict) and events[0].get("error"):
            err_msg = events[0].get("msg", "Unable to read events.")
            details_text.config(state="normal")
            details_text.delete("1.0", "end")
            details_text.insert("1.0", f"{err_msg}\n\nTip: run Intrusense as Administrator to view restricted logs (e.g. Security).")
            details_text.config(state="disabled")
        else:
            details_text.config(state="normal")
            details_text.delete("1.0", "end")
            details_text.insert("1.0", "Click on any event for details")
            details_text.config(state="disabled")

    tree.after(0, ui)


def update_events_tab_for_log(tree, status_var, details_text, log_name, event_id_filter=None, source_substr=None, max_records=200):
    # Load events for a chosen log in background, then update the list.
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
                out.append(ev)
            except Exception:
                continue

        update_events_list(tree, status_var, out, details_text)

    threading.Thread(target=worker, daemon=True).start()


def _build_event_details_text(ev: Dict[str, Any]) -> str:
    # Build a clean, Event Viewer-like details block and omit empty fields.
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

    # Try to get a formatted message, otherwise fall back to raw msg.
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
        lines.append("     ".join(parts))

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
    # Short technical note about why some event descriptions may be unformatted.
    lines.append("Note: Event descriptions are resolved by the Windows Event Log API using")
    lines.append("localized message resource DLLs. If a matching resource isn't available")
    lines.append("or can't be read (missing DLL, permissions, localization mismatch), the")
    lines.append("API may be unable to format the localized text. Intrusense will then")
    lines.append("show insertion strings or a best-effort message from available data.")
    return "\n".join(lines)


def on_event_row_click(event, tree, details_text):
    # Show details for the clicked event (no popup).
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
    # Open a popup with full event details on double-click.
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


# -------- Main UI ----------
def main():
    global proc_tree, proc_status, pid_filter_var

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    root = tk.Tk()
    root.title("Intrusense - Phase 1")
    root.geometry("1300x750")

    style = ttk.Style()
    try:
        style.theme_use('vista')
    except tk.TclError:
        style.theme_use('clam')
    style.configure('Treeview', rowheight=22)
    style.configure('Treeview.Heading', font=(None, 10, 'bold'))

    # Main tabbed view
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    # ----- Processes tab -----
    process_frame = ttk.Frame(notebook)
    notebook.add(process_frame, text="Processes")

    # Search bar for PID substring filter
    search_frame = ttk.Frame(process_frame)
    search_frame.pack(fill=tk.X, padx=5, pady=3)
    pid_filter_var = tk.StringVar()
    ttk.Label(search_frame, text="Search PID:").pack(side=tk.LEFT, padx=(0, 5))
    pid_entry = ttk.Entry(search_frame, textvariable=pid_filter_var, width=20)
    pid_entry.pack(side=tk.LEFT)
    ttk.Button(search_frame, text="Clear", command=lambda: pid_filter_var.set("")).pack(side=tk.LEFT, padx=(5, 0))

    proc_columns = ("PID", "Name", "User", "CPU %", "Memory")
    proc_table_frame = ttk.Frame(process_frame)
    proc_table_frame.pack(fill=tk.BOTH, expand=True)
    proc_tree = ttk.Treeview(proc_table_frame, columns=proc_columns, show="headings")
    for col in proc_columns:
        anchor = "e" if col in ("PID", "CPU %", "Memory") else "w"
        proc_tree.heading(col, text=header_text(col), anchor=anchor)
        proc_tree.column(col, anchor=anchor, width=120)
    # Vertical scrollbar
    ysb_proc = ttk.Scrollbar(proc_table_frame, orient="vertical", command=proc_tree.yview)
    proc_tree.configure(yscrollcommand=ysb_proc.set)
    proc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_proc.pack(side=tk.RIGHT, fill=tk.Y)
    proc_status = tk.StringVar(value="Loading...")
    ttk.Label(process_frame, textvariable=proc_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    refresh_headers(proc_tree, proc_columns)
    proc_tree.after(REFRESH_MS, lambda: update_process_list(proc_tree, proc_status, pid_filter_var, proc_columns))

    # Header click sorting; shift+click for multi-sort.
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

    # ----- Memory tab -----
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

    # ----- Users tab -----
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

    # ----- Rights tab -----
    rights_frame = ttk.Frame(notebook)
    notebook.add(rights_frame, text="Rights")
    rights_label = ttk.Label(rights_frame, text="Checking...")
    rights_label.pack(anchor="w", padx=10, pady=10)
    update_rights_tab(rights_label)

    # ----- Network tab -----
    net_frame = ttk.Frame(notebook)
    notebook.add(net_frame, text="Network")
    net_table_frame = ttk.Frame(net_frame)
    net_table_frame.pack(fill=tk.BOTH, expand=True)
    net_tree = ttk.Treeview(net_table_frame, columns=("PID", "Local", "Remote", "Status"), show="headings")
    for col in ("PID", "Local", "Remote", "Status"):
        anchor = "e" if col == "PID" else "w"
        net_tree.heading(col, text=col, anchor=anchor)
        net_tree.column(col, anchor=anchor, width=220)
    ysb_net = ttk.Scrollbar(net_table_frame, orient="vertical", command=net_tree.yview)
    net_tree.configure(yscrollcommand=ysb_net.set)
    net_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_net.pack(side=tk.RIGHT, fill=tk.Y)
    net_status = tk.StringVar(value="Loading...")
    ttk.Label(net_frame, textvariable=net_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    net_tree.after(0, lambda: update_network_tab(net_tree, net_status))

    # ----- Events tab (left: logs, middle: events, right: details) -----
    events_frame = ttk.Frame(notebook)
    notebook.add(events_frame, text="Events")
    events_panes = ttk.PanedWindow(events_frame, orient=tk.HORIZONTAL)
    events_panes.pack(fill=tk.BOTH, expand=True)

    # Left: logs hierarchy
    logs_frame = ttk.Frame(events_panes)
    events_panes.add(logs_frame, weight=1)
    ttk.Label(logs_frame, text="Log categories:", anchor="w").pack(fill=tk.X, padx=6, pady=(6, 0))
    logs_tree = ttk.Treeview(logs_frame, columns=("col",), show="tree")
    logs_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    # Try to get a live list of logs; otherwise use defaults.
    if HAS_EVENTLOG and eventlog_module:
        logs_hierarchy = eventlog_module.list_known_logs()
    else:
        logs_hierarchy = {
            "Administrative Views": ["Administrative Events"],
            "Windows Logs": ["Application", "Security", "Setup", "System"],
            "Applications and Services Logs": ["(cannot enumerate; pywin32 or registry access missing)"]
        }

    root_custom = logs_tree.insert("", "end", text="Administrative Views", open=True)
    for item in logs_hierarchy.get("Administrative Views", []):
        logs_tree.insert(root_custom, "end", text=item, values=(item,))

    root_win = logs_tree.insert("", "end", text="Windows Logs", open=True)
    for item in logs_hierarchy.get("Windows Logs", []):
        logs_tree.insert(root_win, "end", text=item, values=(item,))

    root_apps = logs_tree.insert("", "end", text="Applications and Services Logs", open=False)
    for item in logs_hierarchy.get("Applications and Services Logs", []):
        logs_tree.insert(root_apps, "end", text=item, values=(item,))

    # Middle: events list
    events_list_frame = ttk.Frame(events_panes)
    events_panes.add(events_list_frame, weight=3)
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

    # When a log is selected, load its events.
    def on_logs_tree_select(event):
        sel = logs_tree.selection()
        if not sel:
            return
        node = sel[0]
        val = logs_tree.item(node, "text")
        if val in ("Administrative Views", "Windows Logs", "Applications and Services Logs"):
            return
        log_name = val
        details_text.config(state="normal")
        details_text.delete("1.0", "end")
        details_text.insert("1.0", "Click on any event for details")
        details_text.config(state="disabled")
        update_events_tab_for_log(events_tree, events_status, details_text, log_name, event_id_filter=None, source_substr=None, max_records=200)

    logs_tree.bind("<<TreeviewSelect>>", on_logs_tree_select)

    # Event selection handlers (click = details pane, double-click = popup).
    events_tree.bind("<Button-1>", lambda e: on_event_row_click(e, events_tree, details_text))
    events_tree.bind("<Double-1>", lambda e: on_event_row_double_click(e, events_tree))

    # Auto-select Administrative Events on startup if present.
    try:
        for iid in logs_tree.get_children(root_custom):
            if logs_tree.item(iid, "text") == "Administrative Events":
                logs_tree.selection_set(iid)
                logs_tree.see(iid)
                update_events_tab_for_log(events_tree, events_status, details_text, "Administrative Events", max_records=200)
                break
    except Exception:
        pass

    root.mainloop()

if __name__ == "__main__":
    main()
