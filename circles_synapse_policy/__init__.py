# Circles Synapse policy module
# Copyright (C) 2026 inrCircle GmbH
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this
# program. If not, see <https://www.gnu.org/licenses/>.
"""Invite rules of Circles (spec D3) for an unmodified Synapse.

Every invite, including those made while creating a room, goes through Synapse's
``user_may_invite`` callback. The module asks the Circles services whether it is allowed
(Chat API 0.1.0, rules 1 to 5); the services also record the first contact as a chat request.
The decision lives in the services, so the module holds no data and no rules of its own.

If the services can't be reached, invites are refused (fail closed): an invite that slipped
through can't be taken back, a refused one can be sent again.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Literal, Union

logger = logging.getLogger(__name__)

__version__ = "0.1.0"

NOT_SPAM: Literal["NOT_SPAM"] = "NOT_SPAM"

try:  # Synapse is there at run time; the tests run without it.
    from synapse.api.errors import Codes

    FORBIDDEN: Any = Codes.FORBIDDEN
except ImportError:  # pragma: no cover - only without Synapse
    FORBIDDEN = "M_FORBIDDEN"


@dataclass(frozen=True)
class Config:
    #: e.g. http://api:3000/internal/chat/v1/invite-check (internal network only)
    check_url: str
    #: shared secret, sent as a bearer token
    token: str


class CirclesPolicy:
    def __init__(self, config: Config, api: Any) -> None:
        self._config = config
        self._api = api
        api.register_spam_checker_callbacks(user_may_invite=self.user_may_invite)

    @staticmethod
    def parse_config(raw: dict[str, Any]) -> Config:
        url = raw.get("check_url")
        token = raw.get("token")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ValueError("circles_synapse_policy: check_url must be an http(s) URL")
        if not isinstance(token, str) or len(token) < 32:
            raise ValueError("circles_synapse_policy: token must be at least 32 characters")
        return Config(check_url=url, token=token)

    async def user_may_invite(
        self, inviter: str, invitee: str, room_id: str
    ) -> Union[Literal["NOT_SPAM"], Any]:
        try:
            answer = await self._api.http_client.post_json_get_json(
                self._config.check_url,
                {"inviter": inviter, "invitee": invitee, "roomId": room_id},
                headers={"Authorization": [f"Bearer {self._config.token}"]},
            )
        except Exception as e:  # noqa: BLE001 - any failure refuses the invite
            logger.warning("Circles invite check failed (%s); invite refused", type(e).__name__)
            return FORBIDDEN
        if isinstance(answer, dict) and answer.get("allow") is True:
            return NOT_SPAM
        return FORBIDDEN
