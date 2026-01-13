import datetime as _dt


def now(tz: _dt.timezone = _dt.timezone.utc) -> _dt.datetime:
    return _dt.datetime.now(tz)


def start_of_day(dt: _dt.datetime) -> _dt.datetime:
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def start_of_today(tz: _dt.timezone = _dt.timezone.utc) -> _dt.datetime:
    return start_of_day(now(tz))


def sub_days(dt: _dt.datetime, days: int) -> _dt.datetime:
    return dt - _dt.timedelta(days=days)
