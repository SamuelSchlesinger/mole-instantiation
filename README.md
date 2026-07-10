# MoLE Instantiation

The first end-to-end instantiation of the MoLE (Moderation of unLinkable
Endorsements) architecture, implementing:

- [draft-jms-mole-architecture](../internet-drafts/draft-jms-mole-architecture.md) — roles and flows
- [draft-jms-mole-http-transport](../internet-drafts/draft-jms-mole-http-transport.md) — the `Mole` HTTP authentication scheme
- [draft-jms-mole-protocols](../internet-drafts/draft-jms-mole-protocols.md) — the IHAT endorsement protocol (type 0x0002) and the ACT credential protocol (type 0x0001)

using the [ihat-rs](https://github.com/Moderation-of-unLinkable-Endorsements/ihat-rs)
and [anonymous-credit-tokens](https://github.com/SamuelSchlesinger/anonymous-credit-tokens)
cryptographic implementations.

> **Warning:** Experimental, unaudited code built to validate the drafts.
> Not for production use.

## Layout

| Crate | Role |
|---|---|
| `mole-core` | Wire encoding (TLS presentation language), `Mole` HTTP header handling, configuration formats, protocol glue shared by all roles |
| `mole-anchor` | The Anchor: grants IHAT Endorsements over the two-exchange grant flow |
| `mole-moderator` | The Moderator: challenges, Redeem & Issue, Presentation + Update, nullifier stores |
| `mole-client` | The Client: library + CLI driving the full flow |
| `mole-e2e` | End-to-end tests over localhost HTTP |

## Running

```sh
# Terminal 1: the Anchor
cargo run --bin mole-anchor -- --port 8081

# Terminal 2: the Moderator, trusting that Anchor
cargo run --bin mole-moderator -- --port 8080 --anchor http://127.0.0.1:8081

# Terminal 3: a Client fetching the protected resource
cargo run --bin mole-client -- --anchor http://127.0.0.1:8081 \
    fetch http://127.0.0.1:8080/resource
```

## Tests

```sh
cargo test
```

The end-to-end tests boot both servers on ephemeral localhost ports and run
the whole flow — endorsement grant, redeem & issue, presentation, update,
double-spend rejection — over real HTTP.

## Relationship to the drafts

Decisions this implementation had to make that the drafts leave open are
collected on the `practicalities` branch of the
[internet-drafts](https://github.com/Moderation-of-unLinkable-Endorsements/internet-drafts)
repository.
