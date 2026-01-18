from datetime import datetime

def is_time_allowed(unlock_str: str) -> bool:
    
    unlock_str = unlock_str.replace("T", " ")
    unlock_time = datetime.strptime(unlock_str, "%Y-%m-%d %H:%M")
    now = datetime.now()
    return now >= unlock_time
