import asyncio
import unittest
from collections.abc import Mapping

from circles_synapse_policy import FORBIDDEN, NOT_SPAM, SENDER_TTL, CirclesPolicy, call_report


class FakeHttp:
    def __init__(self, answer=None, error=None):
        self.answer, self.error, self.calls = answer, error, []

    async def post_json_get_json(self, uri, body, headers=None):
        self.calls.append((uri, body, headers))
        if self.error:
            raise self.error
        return self.answer


class Event:
    def __init__(self, type="m.room.message", sender="@a:circlescom.com", state=False):
        self.type, self.sender, self._state = type, sender, state

    def is_state(self):
        return self._state


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class FakeApi:
    def __init__(self, http):
        self.http_client = http
        self.callbacks = {}

    def register_spam_checker_callbacks(self, **callbacks):
        self.callbacks.update(callbacks)

    def register_third_party_rules_callbacks(self, **callbacks):
        self.callbacks.update(callbacks)


class Frozen(Mapping):
    """Like Synapse's event content since 1.164: an immutable mapping (its Rust JsonObject), not a
    dict, with JSON arrays as tuples."""

    def __init__(self, content):
        self._d = {
            k: Frozen(v) if isinstance(v, dict) else tuple(v) if isinstance(v, list) else v
            for k, v in content.items()
        }

    def __getitem__(self, key):
        return self._d[key]

    def __iter__(self):
        return iter(self._d)

    def __len__(self):
        return len(self._d)


class StateEvent:
    def __init__(self, type, state_key, sender, content, room_id="!room", ts=1700000000000):
        self.type, self.state_key, self.sender = type, state_key, sender
        self.content = Frozen(content)
        self.room_id, self.origin_server_ts = room_id, ts


A, B, C = "@a:circlescom.com", "@b:circlescom.com", "@c:circlescom.com"
CALL = "org.matrix.msc3401.call.member"
JOINED = {"application": "m.call", "call_id": "", "scope": "m.room", "device_id": "D"}


def room(creator=A, additional=(B,), members=(A, B), calls=()):
    """A room's state: create event, joined members, and call memberships (sender, device)."""
    state = {
        ("m.room.create", ""): StateEvent(
            "m.room.create", "", creator, {"room_version": "12", "additional_creators": list(additional)}
        )
    }
    for m in members:
        state[("m.room.member", m)] = StateEvent("m.room.member", m, m, {"membership": "join"})
    for sender, device in calls:
        key = f"_{sender}_{device}_m.call"
        state[(CALL, key)] = StateEvent(CALL, key, sender, JOINED)
    return state


def call_event(sender, device, joined=True, ts=1700000001000):
    return StateEvent(CALL, f"_{sender}_{device}_m.call", sender, JOINED if joined else {}, ts=ts)


RAW = {"check_url": "http://api:3000/internal/chat/v1/invite-check", "token": "x" * 40}
SENDER_URL = "http://api:3000/internal/chat/v1/sender-check"


def run(policy):
    return asyncio.run(policy.user_may_invite("@a:circlescom.com", "@b:circlescom.com", "!r:c"))


class PolicyTest(unittest.TestCase):
    def make(self, **http):
        api = FakeApi(FakeHttp(**http))
        return CirclesPolicy(CirclesPolicy.parse_config(RAW), api), api

    def test_registers_the_invite_callback(self):
        policy, api = self.make(answer={"allow": True})
        self.assertEqual(api.callbacks, {"user_may_invite": policy.user_may_invite})

    def test_registers_the_message_callback_with_a_sender_check_url(self):
        policy, api = self.with_sender_check(answer={"allow": True})
        self.assertEqual(
            api.callbacks,
            {
                "user_may_invite": policy.user_may_invite,
                "check_event_for_spam": policy.check_event_for_spam,
            },
        )

    def test_allows_what_the_services_allow(self):
        policy, api = self.make(answer={"allow": True})
        self.assertEqual(run(policy), NOT_SPAM)
        uri, body, headers = api.http_client.calls[0]
        self.assertEqual(uri, RAW["check_url"])
        self.assertEqual(
            body, {"inviter": "@a:circlescom.com", "invitee": "@b:circlescom.com", "roomId": "!r:c"}
        )
        self.assertEqual(headers, {"Authorization": ["Bearer " + "x" * 40]})

    def test_refuses_everything_else(self):
        for answer in ({"allow": False}, {}, None, {"allow": "yes"}):
            policy, _ = self.make(answer=answer)
            self.assertEqual(run(policy), FORBIDDEN)

    def test_fails_closed(self):
        policy, _ = self.make(error=TimeoutError())
        self.assertEqual(run(policy), FORBIDDEN)

    def with_sender_check(self, clock=None, **http):
        api = FakeApi(FakeHttp(**http))
        config = CirclesPolicy.parse_config({**RAW, "sender_check_url": SENDER_URL})
        return CirclesPolicy(config, api, **({"clock": clock} if clock else {})), api

    def test_refuses_messages_of_read_only_organisations(self):
        policy, api = self.with_sender_check(answer={"allow": False})
        result = asyncio.run(policy.check_event_for_spam(Event()))
        self.assertEqual(result, (FORBIDDEN, {"circles_code": "tenant_read_only"}))
        uri, body, headers = api.http_client.calls[0]
        self.assertEqual((uri, body), (SENDER_URL, {"sender": "@a:circlescom.com"}))
        self.assertEqual(headers, {"Authorization": ["Bearer " + "x" * 40]})
        for kind in ("m.room.encrypted", "m.sticker", "m.reaction"):
            self.assertNotEqual(asyncio.run(policy.check_event_for_spam(Event(kind))), NOT_SPAM)

    def test_lets_other_events_and_allowed_senders_through(self):
        policy, api = self.with_sender_check(answer={"allow": False})
        for event in (Event("m.room.member"), Event("m.room.message", state=True)):
            self.assertEqual(asyncio.run(policy.check_event_for_spam(event)), NOT_SPAM)
        self.assertEqual(api.http_client.calls, [])
        for answer in ({"allow": True}, {}, None):
            policy, _ = self.with_sender_check(answer=answer)
            self.assertEqual(asyncio.run(policy.check_event_for_spam(Event())), NOT_SPAM)

    def test_keeps_an_answer_for_a_minute(self):
        clock = Clock()
        policy, api = self.with_sender_check(clock=clock, answer={"allow": False})
        for _ in range(3):
            asyncio.run(policy.check_event_for_spam(Event()))
        self.assertEqual(len(api.http_client.calls), 1)
        api.http_client.answer = {"allow": True}
        clock.now += SENDER_TTL + 1
        self.assertEqual(asyncio.run(policy.check_event_for_spam(Event())), NOT_SPAM)
        self.assertEqual(len(api.http_client.calls), 2)

    def test_messages_fail_open(self):
        policy, _ = self.with_sender_check(error=TimeoutError())
        self.assertEqual(asyncio.run(policy.check_event_for_spam(Event())), NOT_SPAM)

    def test_checks_its_config(self):
        with self.assertRaises(ValueError):
            CirclesPolicy.parse_config({"check_url": "api:3000", "token": "x" * 40})
        with self.assertRaises(ValueError):
            CirclesPolicy.parse_config({"check_url": RAW["check_url"], "token": "short"})
        with self.assertRaises(ValueError):
            CirclesPolicy.parse_config({**RAW, "sender_check_url": "api:3000/sender-check"})


if __name__ == "__main__":
    unittest.main()


CALL_URL = "http://api:3000/internal/chat/v1/call-member"


class CallReportTest(unittest.TestCase):
    def test_a_caller_joining_a_1on1(self):
        report = call_report(call_event(A, "D1"), room())
        self.assertEqual(
            report,
            {
                "roomId": "!room",
                "userId": A,
                "inCall": True,
                "peer": B,
                "peerInCall": False,
                "ts": 1700000001000,
            },
        )

    def test_reads_synapse_s_immutable_content(self):
        # Synapse 1.164 hands modules content that is a Mapping, not a dict.
        event = call_event(A, "D1")
        self.assertNotIsInstance(event.content, dict)
        report = call_report(event, room())
        self.assertTrue(report["inCall"])
        self.assertEqual(report["peer"], B)

    def test_passes_on_only_a_known_intent(self):
        video = StateEvent(CALL, "_a_D_m.call", A, {**JOINED, "m.call.intent": "video"})
        self.assertEqual(call_report(video, room())["intent"], "video")
        odd = StateEvent(CALL, "_a_D_m.call", A, {**JOINED, "m.call.intent": "<script>"})
        self.assertNotIn("intent", call_report(odd, room()))
        self.assertNotIn("intent", call_report(call_event(A, "D"), room()))

    def test_the_callee_answering_and_the_last_device_leaving(self):
        state = room(calls=[(A, "D1")])
        self.assertEqual(call_report(call_event(B, "P"), state)["peerInCall"], True)
        state = room(calls=[(A, "D1"), (A, "D2")])
        self.assertTrue(call_report(call_event(A, "D1", joined=False), state)["inCall"])
        state = room(calls=[(A, "D1")])
        self.assertFalse(call_report(call_event(A, "D1", joined=False), state)["inCall"])

    def test_an_expired_membership_is_not_in_the_call(self):
        # B's app quit 5 hours ago without leaving: its membership expired after 4 hours.
        stale = StateEvent(
            CALL,
            "_b_P_m.call",
            B,
            {**JOINED, "expires": 4 * 3600 * 1000},
            ts=1700000001000 - 5 * 3600 * 1000,
        )
        state = room()
        state[(CALL, "_b_P_m.call")] = stale
        self.assertFalse(call_report(call_event(A, "D1"), state)["peerInCall"])
        fresh = StateEvent(CALL, "_b_P_m.call", B, {**JOINED, "expires": 4 * 3600 * 1000})
        state[(CALL, "_b_P_m.call")] = fresh
        self.assertTrue(call_report(call_event(A, "D1"), state)["peerInCall"])
        # created_ts counts when present; the older per-user form too.
        made = StateEvent(
            CALL, "_b_P_m.call", B, {**JOINED, "expires": 1000, "created_ts": 1700000000500}
        )
        state[(CALL, "_b_P_m.call")] = made
        self.assertTrue(call_report(call_event(A, "D1"), state)["peerInCall"])
        legacy = StateEvent(
            CALL, B, B, {"memberships": [{"expires": 1000, "created_ts": 1}]}
        )
        state[(CALL, "_b_P_m.call")] = legacy
        self.assertFalse(call_report(call_event(A, "D1"), state)["peerInCall"])

    def test_teams_and_other_rooms_have_no_peer(self):
        self.assertIsNone(call_report(call_event(A, "D"), room(additional=()))["peer"])
        self.assertIsNone(
            call_report(call_event(A, "D"), room(members=(A, B, C)))["peer"]
        )
        self.assertIsNone(call_report(call_event(A, "D"), room(additional=(B, C)))["peer"])
        self.assertIsNone(call_report(call_event(C, "D"), room(members=(A, C)))["peer"])

    def test_reports_only_call_memberships_and_never_their_content(self):
        api = FakeApi(FakeHttp(answer={}))
        policy = CirclesPolicy(
            CirclesPolicy.parse_config({**RAW, "call_member_url": CALL_URL}), api
        )
        self.assertEqual(api.callbacks["on_new_event"], policy.on_new_event)
        asyncio.run(policy.on_new_event(Event(), room()))
        asyncio.run(policy.on_new_event(call_event(A, "D1"), room()))
        self.assertEqual(len(api.http_client.calls), 1)
        uri, body, headers = api.http_client.calls[0]
        self.assertEqual(uri, CALL_URL)
        self.assertEqual(headers, {"Authorization": [f"Bearer {'x' * 40}"]})
        self.assertNotIn("D1", str(body))

    def test_a_failed_report_is_dropped(self):
        api = FakeApi(FakeHttp(error=RuntimeError("down")))
        policy = CirclesPolicy(
            CirclesPolicy.parse_config({**RAW, "call_member_url": CALL_URL}), api
        )
        asyncio.run(policy.on_new_event(call_event(A, "D1"), room()))
        self.assertEqual(len(api.http_client.calls), 1)

    def test_without_the_url_nothing_is_registered(self):
        _, api = PolicyTest.make(PolicyTest(), answer={})
        self.assertNotIn("on_new_event", api.callbacks)

    def test_refuses_a_bad_url(self):
        with self.assertRaises(ValueError):
            CirclesPolicy.parse_config({**RAW, "call_member_url": "api:3000"})

