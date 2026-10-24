# A2A Contracted Agent Service

<!-- 561-group-standards:badges:start -->
[![Red Cup Engineering](https://img.shields.io/badge/561%20Group-Red%20Cup%20Engineering-c0392b)](https://github.com/red-cup-engineering)
[![License: MIT](https://img.shields.io/badge/license-MIT-c0392b)](LICENSE)
[![Indigenous data: CARE](https://img.shields.io/badge/Indigenous%20data-CARE-4b6f44)](https://github.com/red-cup-engineering/.github/blob/main/GOVERNANCE.md)
[![Tips welcome](https://img.shields.io/badge/tips-welcome-d4a017)](https://github.com/561-group/.github/blob/main/TIPS.md)
<!-- 561-group-standards:badges:end -->

**Make one contracted task executor available through the Agent-to-Agent
(A2A) 1.0 protocol.** This Node.js provider exposes an Agent Card, JSON-RPC
and HTTP+JSON task interfaces, and a bounded child-process execution seam.
It is a component for an admitted agent host—not a general chatbot,
a directory of agents, or a turnkey public server.

Unlike the
[Agent Card discovery library](https://github.com/red-cup-engineering/a2a-agent-card-discovery-service),
which *reads* remote cards, this package implements the **provider** that
publishes a card and receives task requests.

## Where to begin

The package exports [`serveContractedAgent(options)`](src/serve-contracted-agent.mjs)
from its root. It also declares the `serve-contracted-a2a-agent` binary,
but **running the binary alone is not a complete installation**: the
function deliberately refuses to start without storage and coordination
sources supplied by the owning host or membrane.

The minimum integration responsibilities are:

- A membrane-supplied `taskSource` (or `taskStore`) **and**
  `coordinationSource` for durable task state and callbacks; the
  production server has no in-process persistence fallback.
- An A2A Agent Card JSON template (`agentCard`) advertising supported
  version `1.0` interfaces rooted at its configured `baseUrl`.
- An executable command (`executor`, and optional `executorArgs`) that
  consumes an A2A Message on standard input and returns an A2A agent
  Message with the required RMN part on standard output.
- A matching Agent Card signing private key, public JWKS and key identifier,
  or an explicitly supplied signed-card generator, public JWKS and separate
  dependency callback key.
- Optional bearer credentials **only when the card declares bearer
  authentication**. The card remains discoverable; protected task routes
  require the configured bearer token.

The [provider implementation](src/serve-contracted-agent.mjs) is the
authority on option names and validation.
[The integration tests](test/a2a-provider.test.mjs) show membrane-supplied
in-memory *test doubles* and an end-to-end signed-card/task exchange.
Those doubles do not authorize a production installation.

## Interfaces and code map

| Source | Responsibility |
| --- | --- |
| [Provider entry](src/serve-contracted-agent.mjs) | Signed card, A2A JSON-RPC and REST endpoints, authentication, executor and cancellation |
| [Signed-card helper](src/signed-agent-card.mjs) | Load a card template and configured private/public key material |
| [Durable task store](src/durable-task-store.mjs) | Task persistence through the provided storage source |
| [Durable push notifications](src/durable-push-notifications.mjs) | Outbox and dependency callback coordination |

The provider serves its Agent Card at
`/.well-known/agent-card.json` and its verification keys at
`/.well-known/jwks.json`. The package exports each of the modules above
as a named subpath. Current tests also exercise interrupted-task recovery,
bearer access, callback coordination, and cancellation.

## Hosting and security boundaries

A directly opened listener is restricted to the local loopback interface.
The server can instead receive **exactly one** already-inherited systemd
socket-activated listener named `a2a`; in that case its public `baseUrl`
must be supplied explicitly. This library does not provision the
socket, a public gateway, the required task/coordination sources,
or a hosting account.

The separate
[Agent Card Key Service](https://github.com/red-cup-engineering/a2a-agent-card-key-service)
provisions a private signing key and public JWKS. Neither a valid signature
nor a successful local test proves independent receiving, authorization,
contract settlement, or live availability.

## Status and verification

The manifest declares package version `2.0.9` and the
`npm run verify` script for syntax and test checks. Run it in a workspace
where the declared dependencies resolve; production readiness still depends
on the host's provisioned sources, credentials, networking boundaries,
and independent operational verification.
