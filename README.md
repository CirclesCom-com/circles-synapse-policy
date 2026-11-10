# circles-synapse-policy

The invite rules of [Circles](https://circlescom.com) as a module for an unmodified
[Synapse](https://github.com/element-hq/synapse): cross-company chats, chat requests, and external
invitations switched off by an organisation (Circles spec, D3).

Every invite, including those made while creating a room, goes through Synapse's
`user_may_invite` callback. The module asks the Circles services whether the invite is allowed;
the services decide and record first contacts as chat requests. If the services can't be reached,
the invite is refused.

## Configuration (homeserver.yaml)

```yaml
modules:
  - module: circles_synapse_policy.CirclesPolicy
    config:
      check_url: http://api:3000/internal/chat/v1/invite-check
      token: <shared secret, at least 32 characters>
```

## Tests

```sh
python3 -m unittest discover -s tests -t .
```

## Licence

GNU Affero General Public License v3.0 or later.
