# Circles Synapse policy module
# Copyright (c) 2026 The Circles authors
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

Calls (Circles Chat API 0.5.0): call memberships are unencrypted MatrixRTC state events. After
one is stored, Synapse's ``on_new_event`` callback reports it to the services
(``call_member_url``): room, user, whether that user and, in a 1on1, the other person are in the
call, the time and, for a join, the call's intent (``audio`` or ``video``, from ``m.call.intent``);
nothing else of the event's content. The services then ring the other person or tell
them about a missed call. A 1on1 is a room whose create event names exactly one additional
creator and whose joined members are those two people. Reports that fail are dropped: the
phone's own ring still works.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional, Union

logger = logging.getLogger(__name__)

__version__ = "0.3.1"

#: Event types that count as sending a message.
MESSAGE_TYPES = frozenset(
    {"m.room.message", "m.room.encrypted", "m.sticker", "m.reaction", "m.poll.start"}
)
#: How long an answer about a sender is kept, in seconds.
SENDER_TTL = 60.0
#: MatrixRTC call membership state events (MSC3401/MSC4143 and the stable name).
CALL_MEMBER_TYPES = frozenset({"org.matrix.msc3401.call.member", "m.call.member"})
#: The only values of ``m.call.intent`` that are passed on.
CALL_INTENTS = frozenset({"audio", "video"})

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
    #: e.g. http://api:3000/internal/chat/v1/call-member; without it, calls aren't reported
    call_member_url: Optional[str] = None


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
        if config.call_member_url:
            api.register_third_party_rules_callbacks(on_new_event=self.on_new_event)

    @staticmethod
    def parse_config(raw: dict[str, Any]) -> Config:
        url = raw.get("check_url")
        token = raw.get("token")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ValueError("circles_synapse_policy: check_url must be an http(s) URL")
        if not isinstance(token, str) or len(token) < 32:
            raise ValueError("circles_synapse_policy: token must be at least 32 characters")
        optional: dict[str, Optional[str]] = {}
        for key in ("sender_check_url", "call_member_url"):
            value = raw.get(key)
            if value is not None and (
                not isinstance(value, str) or not value.startswith(("http://", "https://"))
            ):
                raise ValueError(f"circles_synapse_policy: {key} must be an http(s) URL")
            optional[key] = value
        return Config(check_url=url, token=token, **optional)

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

    async def on_new_event(self, event: Any, state_events: Any) -> None:
        """Reports a call membership change (Chat API 0.5.0); see the module's docstring."""
        if event.type not in CALL_MEMBER_TYPES or getattr(event, "state_key", None) is None:
            return
        try:
            report = call_report(event, state_events)
        except Exception as e:  # noqa: BLE001 - a malformed room never stops Synapse
            logger.warning("Circles call report skipped (%s)", type(e).__name__)
            return
        try:
            await self._api.http_client.post_json_get_json(
                self._config.call_member_url,
                report,
                headers={"Authorization": [f"Bearer {self._config.token}"]},
            )
        except Exception as e:  # noqa: BLE001 - dropped, see the module's docstring
            logger.warning("Circles call report failed (%s)", type(e).__name__)


def _alive(entry: dict[str, Any], sent_ts: Any, now_ts: Any) -> bool:
    """Whether a membership hasn't expired: ``expires`` (ms) counts from ``created_ts``, or from
    when the state event was sent. Without ``expires`` it counts as alive."""
    expires = entry.get("expires")
    if not isinstance(expires, (int, float)) or not isinstance(now_ts, (int, float)):
        return True
    start = entry.get("created_ts")
    if not isinstance(start, (int, float)):
        start = sent_ts
    if not isinstance(start, (int, float)):
        return True
    return start + expires > now_ts


def _in_call(ev: Any, now_ts: Any) -> bool:
    """Whether a call membership event means "in a call" now: not empty (a leave) and not expired.

    A member whose app quit without leaving keeps a non-empty membership in the room state until
    it expires; until then it would look like someone already in the call.
    """
    content = ev.content
    if not isinstance(content, dict) or not content:
        return False
    sent = getattr(ev, "origin_server_ts", None)
    if content.get("application") == "m.call":
        return _alive(content, sent, now_ts)
    memberships = content.get("memberships")  # the older, per-user form
    return isinstance(memberships, list) and any(
        isinstance(m, dict) and _alive(m, sent, now_ts) for m in memberships
    )


def call_report(event: Any, state_events: Any) -> dict[str, Any]:
    """The report for one call membership event, from the room state around it.

    The event itself counts as stored, whether or not ``state_events`` already includes it.
    """
    entries = dict(state_events.items()) if state_events else {}
    entries[(event.type, event.state_key)] = event
    in_call: set[str] = set()
    joined: set[str] = set()
    for (kind, key), ev in entries.items():
        if kind in CALL_MEMBER_TYPES and _in_call(ev, event.origin_server_ts):
            in_call.add(ev.sender)
        elif kind == "m.room.member" and ev.content.get("membership") == "join":
            joined.add(key)
    peer: Optional[str] = None
    create = entries.get(("m.room.create", ""))
    if create is not None:
        extra = create.content.get("additional_creators")
        if isinstance(extra, list) and len(extra) == 1 and isinstance(extra[0], str):
            pair = {create.sender, extra[0]}
            if len(pair) == 2 and joined == pair and event.sender in pair:
                peer = next(u for u in pair if u != event.sender)
    intent = event.content.get("m.call.intent") if isinstance(event.content, dict) else None
    report: dict[str, Any] = {
        "roomId": event.room_id,
        "userId": event.sender,
        "inCall": event.sender in in_call,
        "peer": peer,
        "peerInCall": peer is not None and peer in in_call,
        "ts": event.origin_server_ts,
    }
    if intent in CALL_INTENTS and _in_call(event, event.origin_server_ts):
        report["intent"] = intent
    return report
