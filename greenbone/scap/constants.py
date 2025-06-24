# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
from json import JSONDecodeError

from httpx import HTTPError

# Exceptions on API access to catch in order to retry these calls
STAMINA_API_RETRY_EXCEPTIONS = (JSONDecodeError, HTTPError)
