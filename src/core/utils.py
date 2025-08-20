from datetime import datetime, timezone

def fmt_time(epoch: float) -> str:
    # devuelve YYYY-MM-DD HH:MM:SS.mmm (local time)
    dt = datetime.fromtimestamp(epoch)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{int(dt.microsecond/1000):03d}"
