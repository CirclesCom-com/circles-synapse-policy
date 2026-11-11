import asyncio
import unittest

from circles_synapse_policy import FORBIDDEN, NOT_SPAM, SENDER_TTL, CirclesPolicy


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
