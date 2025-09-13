from typing import Dict, Any
import psutil

def get_system_memory() -> Dict[str, Any]:
    # Return basic system memory stats
    vm = psutil.virtual_memory()
    return {
        'total': vm.total,
        'available': vm.available,
        'used': vm.used,
        'percent': vm.percent,
        'free': vm.free,
    }
