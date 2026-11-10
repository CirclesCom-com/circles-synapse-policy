import asyncio
import unittest

from circles_synapse_policy import FORBIDDEN, NOT_SPAM, CirclesPolicy


class FakeHttp:
    def __init__(self, answer=None, error=None):
        self.answer, self.error, self.calls = answer, error, []

    async def post_json_get_json(self, uri, body, headers=None):
        self.calls.append((uri, body, headers))
        if self.error:
            raise self.error
        return self.answer


class FakeApi:
    def __init__(self, http):
        self.http_client = http
        self.callbacks = {}

    def register_spam_checker_callbacks(self, **callbacks):
        self.callbacks.update(callbacks)


RAW = {"check_url": "http://api:3000/internal/chat/v1/invite-check", "token": "x" * 40}


def run(policy):
    return asyncio.run(policy.user_may_invite("@a:circlescom.com", "@b:circlescom.com", "!r:c"))


class PolicyTest(unittest.TestCase):
    def make(self, **http):
        api = FakeApi(FakeHttp(**http))
        return CirclesPolicy(CirclesPolicy.parse_config(RAW), api), api

    def test_registers_the_invite_callback(self):
        policy, api = self.make(answer={"allow": True})
        self.assertEqual(api.callbacks, {"user_may_invite": policy.user_may_invite})

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

    def test_checks_its_config(self):
        with self.assertRaises(ValueError):
            CirclesPolicy.parse_config({"check_url": "api:3000", "token": "x" * 40})
        with self.assertRaises(ValueError):
            CirclesPolicy.parse_config({"check_url": RAW["check_url"], "token": "short"})


if __name__ == "__main__":
    unittest.main()
