# Simple settings persistence (JSON).

import json
import os
from typing import Dict, Any

DEFAULTS: Dict[str, Any] = {
    "refresh_ms": 500,
    "show_python_procs": False,
    "event_reading_enabled": True,
    "window_width": 1300,
    "window_height": 750
}

def _settings_path() -> str:
    home = os.path.expanduser("~")
    return os.path.join(home, ".intrusense_settings.json")

def load_settings() -> Dict[str, Any]:
    p = _settings_path()
    if not os.path.exists(p):
        return dict(DEFAULTS)
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = dict(DEFAULTS)
        if isinstance(data, dict):
            out.update(data)
        return out
    except Exception:
        return dict(DEFAULTS)

def save_settings(s: Dict[str, Any]) -> None:
    p = _settings_path()
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
    except Exception:
        # best-effort save; ignore errors
        pass
