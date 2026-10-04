"""Validation for additional recurring schedule windows (one shared timezone)."""
import json
import re
from datetime import time

MAX_SCHEDULE_WINDOWS = 32


def extra_schedule_windows(value):
    if not value:
        return []
    if not isinstance(value, str) or len(value) > 16384:
        raise ValueError('Invalid schedule windows')
    try:
        windows = json.loads(value)
    except (ValueError, TypeError) as exc:
        raise ValueError('Invalid schedule windows') from exc
    if not isinstance(windows, list) or len(windows) >= MAX_SCHEDULE_WINDOWS:
        raise ValueError(f'Use at most {MAX_SCHEDULE_WINDOWS} schedule windows')
    for window in windows:
        if not isinstance(window, dict) or set(window) != {'days', 'start', 'end'}:
            raise ValueError('Each schedule window needs days, start, and end')
        days = window['days']
        if not isinstance(days, list) or not days or len(days) > 7 or any(type(day) is not int or day not in range(7) for day in days):
            raise ValueError('Select at least one valid day for each window')
        window['days'] = sorted(set(days))
        for key in ('start', 'end'):
            text = window[key]
            if not isinstance(text, str) or not re.fullmatch(r'[0-2][0-9]:[0-5][0-9]', text):
                raise ValueError('Schedule start and end must use HH:MM local times without seconds or offsets')
            try:
                time.fromisoformat(text)
            except ValueError as exc:
                raise ValueError('Schedule start and end must be valid HH:MM times') from exc
    return windows
