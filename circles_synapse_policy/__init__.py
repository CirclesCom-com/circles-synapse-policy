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
"""Invite rules of Circles (spec D3) and read-only organisations for an unmodified Synapse.

Every invite, including those made while creating a room, goes through Synapse's
``user_may_invite`` callback. The module asks the Circles services whether it is allowed
(Chat API 0.1.0, rules 1 to 5); the services also record the first contact as a chat request.
The decision lives in the services, so the module holds no data and no rules of its own.

If the services can't be reached, invites are refused (fail closed): an invite that slipped
through can't be taken back, a refused one can be sent again.

Messages (Circles Admin API 0.5.0): while an organisation is read-only because its invoice is
unpaid, its members can't send messages. Synapse's ``check_event_for_spam`` callback asks the
services about the sender (``sender_check_url``) and refuses with ``M_FORBIDDEN`` and
``"circles_code": "tenant_read_only"``. Answers are kept for a minute per sender, so a payment
takes effect within a minute. If the services can't be reached, messages go through (fail
open): a few extra messages from an unpaid organisation do less harm than stopping all chats.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional, Union

logger = logging.getLogger(__name__)

__version__ = "0.2.0"

#: Event types that count as sending a message.
MESSAGE_TYPES = frozenset(
    {"m.room.message", "m.room.encrypted", "m.sticker", "m.reaction", "m.poll.start"}
)
#: How long an answer about a sender is kept, in seconds.
SENDER_TTL = 60.0

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
    #: e.g. http://api:3000/internal/chat/v1/sender-check; without it, messages aren't checked
    sender_check_url: Optional[str] = None


class CirclesPolicy:
    def __init__(self, config: Config, api: Any, clock: Callable[[], float] = time.monotonic) -> None:
        self._config = config
        self._api = api
        self._clock = clock
        self._senders: dict[str, tuple[float, bool]] = {}
        callbacks: dict[str, Any] = {"user_may_invite": self.user_may_invite}
        if config.sender_check_url:
            callbacks["check_event_for_spam"] = self.check_event_for_spam
        api.register_spam_checker_callbacks(**callbacks)

    @staticmethod
    def parse_config(raw: dict[str, Any]) -> Config:
        url = raw.get("check_url")
        token = raw.get("token")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ValueError("circles_synapse_policy: check_url must be an http(s) URL")
        if not isinstance(token, str) or len(token) < 32:
            raise ValueError("circles_synapse_policy: token must be at least 32 characters")
        sender_url = raw.get("sender_check_url")
        if sender_url is not None and (
            not isinstance(sender_url, str) or not sender_url.startswith(("http://", "https://"))
        ):
            raise ValueError("circles_synapse_policy: sender_check_url must be an http(s) URL")
        return Config(check_url=url, token=token, sender_check_url=sender_url)

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

    async def check_event_for_spam(self, event: Any) -> Union[Literal["NOT_SPAM"], Any]:
        if event.type not in MESSAGE_TYPES or getattr(event, "is_state", lambda: False)():
            return NOT_SPAM
        if await self._sender_allowed(event.sender):
            return NOT_SPAM
        return (FORBIDDEN, {"circles_code": "tenant_read_only"})

    async def _sender_allowed(self, sender: str) -> bool:
        now = self._clock()
        cached = self._senders.get(sender)
        if cached and cached[0] > now:
            return cached[1]
        try:
            answer = await self._api.http_client.post_json_get_json(
                self._config.sender_check_url,
                {"sender": sender},
                headers={"Authorization": [f"Bearer {self._config.token}"]},
            )
        except Exception as e:  # noqa: BLE001 - fail open, see the module's docstring
            logger.warning("Circles sender check failed (%s); message let through", type(e).__name__)
            return True
        allowed = not (isinstance(answer, dict) and answer.get("allow") is False)
        if len(self._senders) > 10000:
            self._senders = {k: v for k, v in self._senders.items() if v[0] > now}
        self._senders[sender] = (now + SENDER_TTL, allowed)
        return allowed
