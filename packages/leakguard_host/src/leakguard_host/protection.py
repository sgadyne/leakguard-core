"""Validated recurring protection preferences and civil-time scheduling."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from .errors import HostError


def system_timezone():
    try:
        return str(Path('/etc/localtime').resolve()).split('/zoneinfo/',1)[1]
    except (OSError,IndexError):
        return 'UTC'


def defaults():
    return {'version':1,'automatic_this_mac':True,'paused':False,
            'schedule':{'mode':'interval','interval_seconds':3600,'daily_time':'09:00','timezone':system_timezone()},
            'new_content':'inspect','notify_new_findings':False,'exclusions':[]}


def validate_schedule(schedule):
    return validate({'schedule':schedule})['schedule']


def validate(value):
    try:
        result = {**defaults(), **value}
        if type(value) is not dict or set(result) != set(defaults()) or result['version'] != 1:
            raise ValueError()
        for name in ('automatic_this_mac','paused','notify_new_findings'):
            if type(result[name]) is not bool: raise ValueError()
        if result['new_content'] not in {'inspect','inventory'}: raise ValueError()
        schedule=result['schedule']
        if type(schedule) is not dict or set(schedule) != {'mode','interval_seconds','daily_time','timezone'}: raise ValueError()
        if schedule['mode'] not in {'interval','daily'} or type(schedule['interval_seconds']) is not int or not 60 <= schedule['interval_seconds'] <= 31_536_000: raise ValueError()
        if type(schedule['daily_time']) is not str or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]',schedule['daily_time']): raise ValueError()
        ZoneInfo(schedule['timezone'])
        excluded=result['exclusions']
        if type(excluded) is not list or len(excluded)>100 or not all(type(p) is str and 0<len(p)<=4096 and Path(p).is_absolute() and '\x00' not in p for p in excluded): raise ValueError()
        return result
    except (ValueError,TypeError,KeyError,ZoneInfoNotFoundError):
        raise HostError('settings-invalid') from None


def next_run(schedule, now):
    """One catch-up, then a future run; no replay storm after downtime.

    Daily times use the saved IANA zone, first occurrence on a repeated hour;
    nonexistent spring times advance to the first valid minute that day.
    """
    if schedule['mode']=='interval': return now+schedule['interval_seconds']
    zone=ZoneInfo(schedule['timezone']);local=datetime.fromtimestamp(now,zone)
    hour,minute=map(int,schedule['daily_time'].split(':'))
    for days in range(3):
        target=(local+timedelta(days=days)).replace(hour=hour,minute=minute,second=0,microsecond=0,fold=0)
        for _ in range(181):
            roundtrip=datetime.fromtimestamp(target.timestamp(),zone)
            if roundtrip.replace(tzinfo=None)==target.replace(tzinfo=None): break
            target+=timedelta(minutes=1)
        if target.timestamp()>now:return target.timestamp()
    raise HostError('schedule-invalid')
