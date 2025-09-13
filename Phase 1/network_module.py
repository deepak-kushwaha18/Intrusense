from typing import List, Tuple
import psutil

Row = Tuple[str, str, str, str]  # (pid, local, remote, status)


def get_network_rows() -> List[Row]:
    rows: List[Row] = []
    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            try:
                pid = str(c.pid) if c.pid is not None else "-"
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                status = c.status
                rows.append((pid, laddr, raddr, status))
            except Exception:
                continue
    except Exception:
        pass
    return rows

