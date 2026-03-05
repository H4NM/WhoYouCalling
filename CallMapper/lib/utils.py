import sys
from datetime import datetime, timezone

from lib.static.static import MINIMUM_PYTHON_VERSION

def convert_unix_epoch_to_standard_datetime(unix_epoch:str) -> str:
    return datetime.fromtimestamp(int(unix_epoch), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

def get_current_timestamp() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def sort_unique_values(unique_values) -> dict:
    sorted_unique_values = {}

    for key, values in unique_values.items():
        if isinstance(values, list):
            sorted_unique_values[key] = sorted(values, key=str.lower) 
        else:
            sorted_unique_values[key] = values

    return sorted_unique_values

def requests_is_installed() -> bool:
    try:
        import requests
        return True
    except ImportError:
        return False
    
def has_prerequisites() -> bool:
    versions = MINIMUM_PYTHON_VERSION.split(".")
    major_version = int(versions[0])
    minor_version = int(versions[1])
    if sys.version_info >= (major_version, minor_version):
        return True
    else:
        return False    
    
def datetime_is_in_range_by_seconds(reference_time: datetime, range_time: datetime, max_second_range: int) -> bool:
    if abs((reference_time - range_time).total_seconds()) <= max_second_range:
        return True
    else:
        return False
    
def convert_to_datetime_object(date_str: str) -> datetime:
    if '.' in date_str:
        base, fraction = date_str.split('.', 1)
        if '+' in fraction or 'Z' in fraction:
            fraction, offset = fraction.split('+', 1) if '+' in fraction else fraction.split('Z', 1)
            fraction = fraction[:6] 
            date_str = f"{base}.{fraction}+{offset}" if '+' in date_str else f"{base}.{fraction}Z"
        else:
            fraction = fraction[:6] 
            date_str = f"{base}.{fraction}"
    return datetime.fromisoformat(date_str)


def get_comma_separated_results_files(csv:str) -> list:
    return csv.split(',')

def normalize_windows_path(path:str) -> str:
    if not path:
        return path
    path = path.strip().replace('/', '\\')

    is_unc = path.startswith('\\\\')
    if is_unc:
        path = path[2:]

    normalized = []
    prev_was_slash = False

    for ch in path:
        if ch == '\\':
            if not prev_was_slash:
                normalized.append(ch)
            prev_was_slash = True
        else:
            normalized.append(ch)
            prev_was_slash = False

    path = ''.join(normalized)

    if is_unc:
        path = '\\\\' + path

    return path