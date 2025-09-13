import tkinter as tk
from tkinter import ttk
import psutil
from datetime import datetime
import logging
import threading

import process_module
import memory_module
import user_module
import rights_module
import network_module

# Refresh interval (ms)
REFRESH_MS = 250

# Sorting state
sort_priority = [("CPU %", True)]
ALLOWED_SORT_COLUMNS = {"PID", "CPU %", "Memory"}


def default_desc(col: str) -> bool:
    return col in ("PID", "CPU %", "Memory")


def header_text(col: str) -> str:
    if col not in ALLOWED_SORT_COLUMNS:
        return col
    for idx, (c, desc) in enumerate(sort_priority):
        if c == col:
            order = f"[{idx + 1}]"
            return f"{col} {'▼' if desc else '▲'}{order}"
    return col


# Sorting logic
def set_sort(col: str, additive: bool = False):
    global sort_priority
    if col not in ALLOWED_SORT_COLUMNS:
        return

    existing = {c: i for i, (c, _) in enumerate(sort_priority)}

    if not additive:
        if sort_priority and sort_priority[0][0] == col:
            sort_priority[0] = (col, not sort_priority[0][1])  # toggle
        else:
            sort_priority = [(col, default_desc(col))]
    else:
        if col in existing:
            i = existing[col]
            c, d = sort_priority[i]
            sort_priority[i] = (c, not d)
        else:
            sort_priority.append((col, default_desc(col)))

    refresh_headers(proc_tree, ("PID", "Name", "User", "CPU %", "Memory"))
    update_process_list(proc_tree, proc_status, pid_filter_var, ("PID", "Name", "User", "CPU %", "Memory"))


# Process Tab
def refresh_headers(tree, columns):
    for idx, c in enumerate(columns):
        text = header_text(c)
        tree.heading(c, text=text)


def update_process_list(tree, status_var, pid_filter_var, columns):
    def worker():
        digits_only = ''.join(ch for ch in pid_filter_var.get().strip() if ch.isdigit())
        proc_rows = process_module.get_process_rows(digits_only)

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

        proc_rows.sort(key=lambda r: int(r[0]))
        for col, desc in reversed(sort_priority):
            proc_rows.sort(key=lambda r, c=col: key_for(c, r), reverse=desc)

        def update_ui():
            for row in tree.get_children():
                tree.delete(row)
            for idx, (pid, name, user, cpu, mem) in enumerate(proc_rows):
                tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
                display_values = [pid, name, user, f"{cpu:.1f}%", f"{mem:.1f} MB"]
                tree.insert("", "end", values=tuple(display_values), tags=(tag,))
            status_var.set(
                f"Processes: {len(proc_rows)} | Sorted by {[c for c, _ in sort_priority]} | Updated: {datetime.now().strftime('%H:%M:%S')}"
            )
            tree.after(REFRESH_MS, lambda: update_process_list(tree, status_var, pid_filter_var, columns))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# Memory Tab
def update_memory_tab(tree, status_var):
    def worker():
        mem = memory_module.get_system_memory()
        keep_keys = ["total", "available", "used", "free"]
        rows = [(k, f"{mem[k]/1024/1024:.1f} MB") for k in keep_keys if k in mem]

        def update_ui():
            for row in tree.get_children():
                tree.delete(row)
            for k, v in rows:
                tree.insert("", "end", values=(k, v))
            status_var.set(f"Memory refreshed at {datetime.now().strftime('%H:%M:%S')}")
            tree.after(REFRESH_MS * 2, lambda: update_memory_tab(tree, status_var))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# Users Tab
def update_users_tab(tree, status_var):
    def worker():
        users = user_module.get_logged_in_users()

        def update_ui():
            for row in tree.get_children():
                tree.delete(row)
            for u in users:
                tree.insert("", "end", values=(u['name'], u['terminal'], u['host'], u['started'], u['pid']))
            status_var.set(f"Users refreshed at {datetime.now().strftime('%H:%M:%S')}")
            tree.after(REFRESH_MS * 5, lambda: update_users_tab(tree, status_var))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# Rights Tab
def update_rights_tab(label):
    admin = rights_module.is_admin()
    label.config(text=f"Running as Admin: {'Yes' if admin else 'No'}")


# Network Tab
def update_network_tab(tree, status_var):
    def worker():
        rows = network_module.get_network_rows()

        def update_ui():
            for row in tree.get_children():
                tree.delete(row)
            for r in rows:
                tree.insert("", "end", values=r)
            status_var.set(f"Connections: {len(rows)} | Updated: {datetime.now().strftime('%H:%M:%S')}")
            tree.after(REFRESH_MS * 2, lambda: update_network_tab(tree, status_var))

        tree.after(0, update_ui)

    threading.Thread(target=worker, daemon=True).start()


# main method
def main():
    global proc_tree, proc_status, pid_filter_var

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    root = tk.Tk()
    root.title("Intrusense - Phase 1")
    root.geometry("1100x650")

    style = ttk.Style()
    try:
        style.theme_use('vista')
    except tk.TclError:
        style.theme_use('clam')
    style.configure('Treeview', rowheight=22)
    style.configure('Treeview.Heading', font=(None, 10, 'bold'))

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    # Process Tab using tkinter Treeview widget
    process_frame = ttk.Frame(notebook)
    notebook.add(process_frame, text="Processes")

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

    ysb_proc = ttk.Scrollbar(proc_table_frame, orient="vertical", command=proc_tree.yview)
    proc_tree.configure(yscrollcommand=ysb_proc.set)
    proc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_proc.pack(side=tk.RIGHT, fill=tk.Y)

    proc_status = tk.StringVar(value="Loading...")
    ttk.Label(process_frame, textvariable=proc_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    refresh_headers(proc_tree, proc_columns)
    proc_tree.after(REFRESH_MS, lambda: update_process_list(proc_tree, proc_status, pid_filter_var, proc_columns))

    # Enable column header click sorting
    def on_proc_tree_click(event):
        region = proc_tree.identify("region", event.x, event.y)
        if region != "heading":
            return
        col_id = proc_tree.identify_column(event.x)  # "#1"
        try:
            idx = int(col_id.replace("#", "")) - 1
            if 0 <= idx < len(proc_columns):
                additive = (getattr(event, "state", 0) & 0x0001) != 0  # Shift pressed?
                set_sort(proc_columns[idx], additive)
        except ValueError:
            pass

    proc_tree.bind("<Button-1>", on_proc_tree_click, add="+")

    # Memory Tab using tkinter Treeview widget
    mem_frame = ttk.Frame(notebook)
    notebook.add(mem_frame, text="Memory")

    mem_table_frame = ttk.Frame(mem_frame)
    mem_table_frame.pack(fill=tk.BOTH, expand=True)

    mem_tree = ttk.Treeview(mem_table_frame, columns=("Key", "Value"), show="headings")
    for col in ("Key", "Value"):
        mem_tree.heading(col, text=col, anchor="w")
        mem_tree.column(col, anchor="w", width=200)

    ysb_mem = ttk.Scrollbar(mem_table_frame, orient="vertical", command=mem_tree.yview)
    mem_tree.configure(yscrollcommand=ysb_mem.set)
    mem_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_mem.pack(side=tk.RIGHT, fill=tk.Y)

    mem_status = tk.StringVar(value="Loading...")
    ttk.Label(mem_frame, textvariable=mem_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    mem_tree.after(0, lambda: update_memory_tab(mem_tree, mem_status))

    # Users Tab using tkinter Treeview widget
    user_frame = ttk.Frame(notebook)
    notebook.add(user_frame, text="Users")

    user_table_frame = ttk.Frame(user_frame)
    user_table_frame.pack(fill=tk.BOTH, expand=True)

    user_tree = ttk.Treeview(user_table_frame, columns=("Name", "Terminal", "Host", "Started", "PID"), show="headings")
    for col in ("Name", "Terminal", "Host", "Started", "PID"):
        anchor = "e" if col == "PID" else "w"
        user_tree.heading(col, text=col, anchor=anchor)
        user_tree.column(col, anchor=anchor, width=150)

    ysb_user = ttk.Scrollbar(user_table_frame, orient="vertical", command=user_tree.yview)
    user_tree.configure(yscrollcommand=ysb_user.set)
    user_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_user.pack(side=tk.RIGHT, fill=tk.Y)

    user_status = tk.StringVar(value="Loading...")
    ttk.Label(user_frame, textvariable=user_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    user_tree.after(0, lambda: update_users_tab(user_tree, user_status))

    # Rights Tab using tkinter Label widget
    rights_frame = ttk.Frame(notebook)
    notebook.add(rights_frame, text="Rights")
    rights_label = ttk.Label(rights_frame, text="Checking...")
    rights_label.pack(anchor="w", padx=10, pady=10)
    update_rights_tab(rights_label)

    # Network Tab uisng tkinter Treeview widget
    net_frame = ttk.Frame(notebook)
    notebook.add(net_frame, text="Network")

    net_table_frame = ttk.Frame(net_frame)
    net_table_frame.pack(fill=tk.BOTH, expand=True)

    net_tree = ttk.Treeview(net_table_frame, columns=("PID", "Local", "Remote", "Status"), show="headings")
    for col in ("PID", "Local", "Remote", "Status"):
        anchor = "e" if col == "PID" else "w"
        net_tree.heading(col, text=col, anchor=anchor)
        net_tree.column(col, anchor=anchor, width=180)

    ysb_net = ttk.Scrollbar(net_table_frame, orient="vertical", command=net_tree.yview)
    net_tree.configure(yscrollcommand=ysb_net.set)
    net_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ysb_net.pack(side=tk.RIGHT, fill=tk.Y)

    net_status = tk.StringVar(value="Loading...")
    ttk.Label(net_frame, textvariable=net_status, anchor="w").pack(fill=tk.X, side=tk.BOTTOM)
    net_tree.after(0, lambda: update_network_tab(net_tree, net_status))

    root.mainloop()

if __name__ == "__main__":
    main()
