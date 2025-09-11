import tkinter as tk
from tkinter import ttk
import psutil
from datetime import datetime
from typing import List, Tuple
import logging
import time

# Refresh interval (ms)
REFRESH_MS = 500

# Global sort state: list of (column, desc). Primary sort is first item.
sort_priority: List[Tuple[str, bool]] = [("CPU %", True)]

# Only allow sorting on these columns (disable sorting for others like User/Name)
ALLOWED_SORT_COLUMNS = {"PID", "CPU %", "Memory"}

# Sanitize default sort priority to allowed columns
sort_priority = [item for item in sort_priority if item[0] in ALLOWED_SORT_COLUMNS] or [("CPU %", True)]

# Cache CPU count to avoid recomputing every refresh
TOTAL_CPUS = psutil.cpu_count(logical=True) or 1


def default_desc(col: str) -> bool:
    """Default sort direction per column: numeric desc, text asc."""
    return col in ("PID", "CPU %", "Memory")


def header_text(col: str) -> str:
    # Show arrow and order index only for allowed sort columns
    if col not in ALLOWED_SORT_COLUMNS:
        return col
    for idx, (c, desc) in enumerate(sort_priority):
        if c == col:
            order = f"[{idx + 1}]"
            return f"{col} {'▼' if desc else '▲'}{order}"
    return col


def refresh_headers():
    for idx, c in enumerate(columns):
        text = header_text(c)
        if idx > 0:
            text = f"│{text}"
        tree.heading(c, text=text)


def set_sort(col: str, additive: bool = False):
    """Update sort priority.
    - If additive is False: make `col` the only sort key (toggle direction if already primary).
    - If additive is True: add/toggle `col` while keeping existing priority (Shift-click behavior).
    """
    global sort_priority
    # Ignore sorting for disallowed columns (e.g., User, Name)
    if col not in ALLOWED_SORT_COLUMNS:
        return
    # Current mapping
    existing = {c: i for i, (c, _) in enumerate(sort_priority)}

    if not additive:
        # Single-column sort
        if sort_priority and sort_priority[0][0] == col:
            # toggle primary direction
            sort_priority[0] = (col, not sort_priority[0][1])
        else:
            sort_priority = [(col, default_desc(col))]
    else:
        # Multi-column adjustment
        if col in existing:
            i = existing[col]
            # toggle that column's direction
            c, d = sort_priority[i]
            sort_priority[i] = (c, not d)
        else:
            sort_priority.append((col, default_desc(col)))

    refresh_headers()
    update_process_list()


def update_process_list():
    # Prevent overlapping heavy updates; ensure only one runs at a time
    global is_updating, refresh_job_id
    if is_updating:
        return
    is_updating = True
    try:
        for row in tree.get_children():
            tree.delete(row)

        # Determine PID filter (digits only). If empty -> no filtering.
        try:
            filter_text = pid_filter_var.get().strip()
        except Exception:
            filter_text = ""
        digits_only = ''.join(ch for ch in filter_text if ch.isdigit())

        proc_rows = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
            try:
                name = proc.info.get('name') or "-"
                if name == "System Idle Process":
                    continue  # Hide idle process

                pid = proc.info['pid']
                # Apply PID substring filter if provided
                if digits_only and digits_only not in str(pid):
                    continue

                user = proc.info.get('username') or "-"
                cpu = (proc.info.get('cpu_percent') or 0.0) / TOTAL_CPUS  # Normalize like Task Manager
                mem = (proc.info['memory_info'].rss if proc.info.get('memory_info') else 0) / (1024 * 1024)  # MB

                proc_rows.append((pid, name, user, cpu, mem))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Build a sort key based on multi-column priority
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

        # Stable multi-key sort: start with base key (PID asc), then apply each sort level in reverse order.
        proc_rows.sort(key=lambda r: int(r[0]))
        for col, desc in reversed(sort_priority):
            proc_rows.sort(key=lambda r, c=col: key_for(c, r), reverse=desc)

        for idx, (pid, name, user, cpu, mem) in enumerate(proc_rows):
            tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
            display_values = [pid, name, user, f"{cpu:.1f}%", f"{mem:.1f} MB"]
            for i in range(1, len(display_values)):
                display_values[i] = f"│{display_values[i]}"
            tree.insert("", "end", values=tuple(display_values), tags=(tag,))

        if sort_priority:
            parts = [f"{c} {'desc' if d else 'asc'}" for c, d in sort_priority if c in ALLOWED_SORT_COLUMNS]
            sort_desc_text = ' | '.join(parts) if parts else 'None'
        else:
            sort_desc_text = 'None'
        filter_note = f" | PID filter: {digits_only}" if digits_only else ""
        status_var.set(f"Processes: {len(proc_rows)} | Sorted by {sort_desc_text}{filter_note} | Updated: {datetime.now().strftime('%H:%M:%S')}")
    finally:
        # Ensure we only have one scheduled refresh pending
        try:
            if refresh_job_id:
                root.after_cancel(refresh_job_id)
        except Exception:
            pass
        refresh_job_id = root.after(REFRESH_MS, update_process_list)
        is_updating = False


def main():
    # Expose UI-related objects so helper functions can access them
    global root, style, columns, container, tree, ysb, COL_WEIGHTS, MIN_WIDTHS, status_var, status_bar, pid_filter_var, refresh_job_id, is_updating, pid_debounce_id

    # Basic logging setup for the app
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    root = tk.Tk()
    root.title("Process Manager")
    root.geometry("900x500")

    style = ttk.Style()
    try:
        style.theme_use('vista')
    except tk.TclError:
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass
    style.configure('Treeview', rowheight=22)
    style.configure('Treeview.Heading', font=(None, 10, 'bold'))

    # Top bar with centered PID search
    topbar = ttk.Frame(root, padding=(8, 8, 8, 4))
    topbar.pack(fill=tk.X, side=tk.TOP)
    topbar.columnconfigure(0, weight=1)
    topbar.columnconfigure(2, weight=1)

    pid_filter_var = tk.StringVar()

    refresh_job_id = None
    is_updating = False
    pid_debounce_id = None


    def _on_pid_filter_change(*_):
        # Debounce to avoid heavy refresh on every keystroke
        global pid_debounce_id
        try:
            if pid_debounce_id:
                root.after_cancel(pid_debounce_id)
        except Exception:
            pass
        pid_debounce_id = root.after(250, update_process_list)

    try:
        pid_filter_var.trace_add('write', _on_pid_filter_change)
    except Exception:
        # Fallback for older Tk versions
        pid_filter_var.trace('w', _on_pid_filter_change)

    search_frame = ttk.Frame(topbar)
    search_frame.grid(row=0, column=1, pady=(0, 4))
    ttk.Label(search_frame, text="Search PID:").pack(side=tk.LEFT, padx=(0, 6))
    pid_entry = ttk.Entry(search_frame, textvariable=pid_filter_var, width=18, justify='center')
    pid_entry.pack(side=tk.LEFT)
    ttk.Button(search_frame, text="Clear", width=6, command=lambda: pid_filter_var.set("")).pack(side=tk.LEFT, padx=(6, 0))

    columns = ("PID", "Name", "User", "CPU %", "Memory")

    container = ttk.Frame(root, padding=(8, 8, 8, 4))
    container.pack(fill=tk.BOTH, expand=True)

    tree = ttk.Treeview(container, columns=columns, show="headings", selectmode="browse")

    for col in columns:
        tree.heading(col, text=header_text(col))

    col_widths = {
        "PID": 80,
        "Name": 180,
        "User": 80,
        "CPU %": 80,
        "Memory": 110,
    }
    for col in columns:
        anchor = "e" if col in ("PID", "CPU %", "Memory") else "w"
        # We'll manage widths ourselves; disable built-in stretching on individual columns
        tree.column(col, anchor=anchor, width=col_widths[col], stretch=False)

    # Scrollbar
    ysb = ttk.Scrollbar(container, orient="vertical", command=tree.yview)

    # Attach scrollbar
    tree.configure(yscrollcommand=ysb.set)

    # Grid layout
    tree.grid(row=0, column=0, sticky="nsew")
    ysb.grid(row=0, column=1, sticky="ns")
    container.rowconfigure(0, weight=1)
    container.columnconfigure(0, weight=1)

    # Responsive column widths: proportional to available tree width
    COL_WEIGHTS = {
        "PID": 1,
        "Name": 2,
        "User": 2,
        "CPU %": 1,
        "Memory": 2,
    }
    MIN_WIDTHS = {
        "PID": 70,
        "Name": 160,
        "User": 120,
        "CPU %": 70,
        "Memory": 100,
    }

    def resize_columns(event=None):
        try:
            total = max(tree.winfo_width(), 200)
        except Exception:
            return
        # Avoid division by zero
        total_weight = sum(COL_WEIGHTS.get(c, 1) for c in columns) or 1
        widths = {}
        remaining_px = total
        # Iteratively assign to respect min widths and ensure exact fill
        for i, c in enumerate(columns):
            weight = COL_WEIGHTS.get(c, 1)
            min_w = MIN_WIDTHS.get(c, 50)
            proposed = max(min_w, int(total * weight / total_weight))
            if i == len(columns) - 1:
                w = max(min_w, remaining_px)
            else:
                min_left = sum(MIN_WIDTHS.get(cc, 50) for cc in columns[i+1:])
                w = max(min_w, min(proposed, max(0, remaining_px - min_left)))
            widths[c] = w
            remaining_px -= w
        for c, w in widths.items():
            tree.column(c, width=w)

    container.bind('<Configure>', resize_columns)
    tree.bind('<Configure>', resize_columns)

    # Zebra striping tags
    try:
        tree.tag_configure('oddrow', background='#f6f8fa')
        tree.tag_configure('evenrow', background='#ffffff')
    except tk.TclError:
        pass

    # Mouse bindings for sorting (support Shift-click on headers)

    def on_tree_click(event):
        # Only respond if clicking on heading region
        region = tree.identify('region', event.x, event.y)
        if region != 'heading':
            return
        col_id = tree.identify_column(event.x)  # e.g., '#1'
        try:
            idx = int(col_id.replace('#', '')) - 1
            if 0 <= idx < len(columns):
                # Check if Shift is held for additive sort
                additive = (getattr(event, 'state', 0) & 0x0001) != 0
                set_sort(columns[idx], additive=additive)
        except ValueError:
            pass

    # Binding
    tree.bind('<Button-1>', on_tree_click, add='+')

    # Status bar
    status_var = tk.StringVar(value="Loading processes…")
    status_bar = ttk.Label(root, textvariable=status_var, anchor="w", padding=(8, 2))
    status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    refresh_headers()


    # Warm up per-process CPU counters so first fast refresh shows non-zero CPU%
    try:
        for p in psutil.process_iter(['pid']):
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        logging.exception("Unexpected error while warming up per-process CPU counters")

    # Schedule first update after a short delay for responsiveness
    refresh_job_id = root.after(REFRESH_MS, update_process_list)
    # Kick an initial resize to fit current window size
    root.after(0, resize_columns)
    root.mainloop()


if __name__ == "__main__":
    main()
