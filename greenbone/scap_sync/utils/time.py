# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import datetime as _dt


def now(tz: _dt.timezone = _dt.timezone.utc) -> _dt.datetime:
    return _dt.datetime.now(tz)


def sub_days(dt: _dt.datetime, days: int) -> _dt.datetime:
    return dt - _dt.timedelta(days=days)
