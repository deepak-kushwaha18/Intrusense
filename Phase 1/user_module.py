from typing import List, Dict, Any
import psutil

def get_logged_in_users() -> List[Dict[str, Any]]:
    # List logged-in user sessions (name, terminal, host, started, pid)
    users = []
    for u in psutil.users():
        users.append({
            'name': getattr(u, 'name', None),
            'terminal': getattr(u, 'terminal', None),
            'host': getattr(u, 'host', None),
            'started': getattr(u, 'started', None),
            'pid': getattr(u, 'pid', None),
        })
    return users
