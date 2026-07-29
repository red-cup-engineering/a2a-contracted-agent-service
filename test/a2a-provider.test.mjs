import assert from "node:assert/strict";
import { createServer } from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { AgentCard, Message, Role, Task, TaskState, canonicalizeAgentCard, generateAgentCardSignature } from "@a2a-js/sdk";
import { exportJWK } from "jose";
import { inheritedSystemdListener, replayInterruptedTasks, serveContractedAgent as serveNetworkContractedAgent } from "../src/serve-contracted-agent.mjs";
import { cancelRmnTask, discoverValidatedAgentCard, resumeRmnTask, sendRmnTask, submitRmnTask } from "@red-cup-engineering/a2a-rmn-task-client-service";
import { discoverAgentCard } from "@red-cup-engineering/a2a-agent-card-discovery-service";
import { extractRmnPart, rmnPart, userRmnMessage } from "@red-cup-engineering/a2a-rmn-part-service";
import { DurableA2aTaskStore } from "../src/durable-task-store.mjs";
import { DurableDependencyEventInbox } from "../src/durable-push-notifications.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
function memoryTaskSource() {
  const records = new Map();
  const key = (taskId, tenant = "") => `${tenant}\u0000${taskId}`;
  return Object.freeze({
    async put(record) { records.set(key(record.taskId, record.tenant), structuredClone(record)); return structuredClone(record); },
    async get({ taskId, tenant = "" }) { const record = records.get(key(taskId, tenant)); return record === undefined ? null : structuredClone(record); },
    async list({ tenant = "" } = {}) { return [...records.values()].filter((record) => record.tenant === tenant).map((record) => structuredClone(record)); },
  });
}
function memoryCoordinationSource() {
  const records = new Map(), coordinate = ({ namespace, tenant = "", key }) => `${namespace}\u0000${tenant}\u0000${key}`;
  return Object.freeze({
    async put(record) { const stored = { ...structuredClone(record), contentSha256: "memory", etag: randomUUID() }; records.set(coordinate(record), stored); return structuredClone(stored); },
    async get(record) { const stored = records.get(coordinate(record)); return stored === undefined ? null : structuredClone(stored); },
    async list({ namespace, tenant = "" }) { return [...records.values()].filter((record) => record.namespace === namespace && record.tenant === tenant).map((record) => structuredClone(record)); },
    async remove(record) { return records.delete(coordinate(record)); },
  });
}
function serveContractedAgent(options) {
  return serveNetworkContractedAgent({ taskSource: options.taskSource ?? memoryTaskSource(), coordinationSource: options.coordinationSource ?? memoryCoordinationSource(), ...options });
}
async function freePort() {
  const server = createServer(); await new Promise((accept) => server.listen(0, "127.0.0.1", accept));
  const port = server.address().port; await new Promise((accept) => server.close(accept)); return port;
}
async function eventually(assertion) {
  for (;;) {
    try { return assertion(); }
    catch {}
    await new Promise((accept) => setImmediate(accept));
  }
}

async function signing(baseUrl, capture) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519"), kid = "test-a2a-card-ed25519";
  const key = { ...(await exportJWK(publicKey)), kid, alg: "EdDSA", use: "sig" };
  const generate = generateAgentCardSignature(privateKey, { alg: "EdDSA", kid, typ: "JOSE", jku: `${baseUrl}/.well-known/jwks.json` });
  return { agentCardSignatureGenerator: async (card) => { capture?.(structuredClone(card)); return generate(card); }, agentCardJwks: { keys: [key] }, dependencyCallbackKey: randomBytes(32) };
}

test("socket activation admits exactly one colony-supplied listener named a2a", () => {
  assert.equal(inheritedSystemdListener({}, 41), null);
  assert.deepEqual(
    inheritedSystemdListener({ LISTEN_PID: "41", LISTEN_FDS: "1", LISTEN_FDNAMES: "a2a" }, 41),
    { fd: 3, name: "a2a", source: "systemd-socket-activation" },
  );
  assert.throws(() => inheritedSystemdListener({ LISTEN_PID: "41" }, 41), /requires both/u);
  assert.throws(() => inheritedSystemdListener({ LISTEN_PID: "042", LISTEN_FDS: "1" }, 42), /canonical positive/u);
  assert.throws(() => inheritedSystemdListener({ LISTEN_PID: "40", LISTEN_FDS: "1" }, 41), /does not identify/u);
  assert.throws(() => inheritedSystemdListener({ LISTEN_PID: "41", LISTEN_FDS: "2" }, 41), /exactly one/u);
  assert.throws(() => inheritedSystemdListener({ LISTEN_PID: "41", LISTEN_FDS: "1", LISTEN_FDNAMES: "http" }, 41), /named "a2a"/u);
});

test("socket activation refuses to invent the inherited listener's public address", async () => {
  await assert.rejects(
    serveContractedAgent({
      environment: { LISTEN_PID: "41", LISTEN_FDS: "1", LISTEN_FDNAMES: "a2a" },
      processId: 41,
    }),
    /requires an explicit public/u,
  );
});
function securedFixture() {
  const root = mkdtempSync(join(tmpdir(), "union-a2a-bearer-"));
  const card = JSON.parse(readFileSync(join(ROOT, "test/fixtures/agent-card.json"), "utf8"));
  const requirement = [{ schemes: { bearerAuth: { list: [] } } }];
  card.securitySchemes = { bearerAuth: { httpAuthSecurityScheme: { description: "Contracted A2A caller", scheme: "Bearer", bearerFormat: "opaque" } } };
  card.securityRequirements = requirement;
  for (const skill of card.skills) skill.securityRequirements = requirement;
  const cardPath = join(root, "agent-card.json"), tokenPath = join(root, "bearer.token"), wrongTokenPath = join(root, "wrong.token");
  writeFileSync(cardPath, `${JSON.stringify(card)}\n`, "utf8");
  writeFileSync(tokenPath, "correct-contract-token\n", { encoding: "utf8", mode: 0o600 });
  writeFileSync(wrongTokenPath, "wrong-contract-token\n", { encoding: "utf8", mode: 0o600 });
  return { root, cardPath, tokenPath, wrongTokenPath };
}

test("a contracted provider cannot energize without a signed Agent Card identity", async () => {
  const port = await freePort(), baseUrl = `http://127.0.0.1:${port}`;
  await assert.rejects(
    serveContractedAgent({
      port, host: "127.0.0.1", baseUrl,
      agentCard: join(ROOT, "test/fixtures/agent-card.json"),
      executor: process.execPath, executorArgs: [join(ROOT, "test/fixtures/echo-rmn.mjs")],
    }),
    /require an Agent Card signing key, public JWKS, and kid/u,
  );
});

test("signed Agent Card discovery performs one observation without inventing retry timing", async () => {
  let attempts = 0;
  await assert.rejects(discoverValidatedAgentCard("http://127.0.0.1:1/.well-known/agent-card.json", {
    requireSignature: true,
    discover: async () => { attempts += 1; throw Object.assign(new Error("socket reset"), { code: "ECONNRESET" }); },
  }), /socket reset/u);
  assert.equal(attempts, 1);
});

test("official A2A 1.0 Agent Card and JSON-RPC binding round-trip canonical RMN bytes", async () => {
  const port = await freePort(), baseUrl = `http://127.0.0.1:${port}`;
  let signatureCount = 0;
  const running = await serveContractedAgent({
    port, host: "127.0.0.1", baseUrl,
    agentCard: join(ROOT, "test/fixtures/agent-card.json"),
    executor: process.execPath, executorArgs: [join(ROOT, "test/fixtures/echo-rmn.mjs")],
    ...(await signing(baseUrl, () => { signatureCount += 1; })),
  });
  try {
    const cardResponse = await fetch(`${baseUrl}/.well-known/agent-card.json`, { headers: { "A2A-Version": "1.0" } });
    assert.equal(cardResponse.status, 200);
    const card = await cardResponse.json();
    assert.deepEqual(card.supportedInterfaces.map((face) => [face.protocolBinding, face.protocolVersion]), [["JSONRPC", "1.0"], ["HTTP+JSON", "1.0"]]);
    const discovered = await discoverAgentCard({ agentUrl: `${baseUrl}/.well-known/agent-card.json`, requireSignature: true });
    assert.equal(discovered.version, "1.0.0");
    assert.equal(discovered.signatures.length, 1);
    const bytes = Buffer.from([0x82, 0x64, 0x6d, 0x61, 0x72, 0x6b, 0x61, 0x78]);
    const message = userRmnMessage(bytes, "operation.rmn.cbor", "00000000-0000-4000-8000-000000000000");
    const result = await sendRmnTask({ agentUrl: `${baseUrl}/.well-known/agent-card.json`, message, requireSignature: true });
    assert.equal(result.inputNi, result.outputNi);
    assert.deepEqual(result.extensions, ["ni:///sha-256;wzh-zYeFQCsh4zAzGS34uacNV4qJeIEmCKIUUWyRZ-M"]);
    assert.equal(result.agentCard.signatures.length, 1);
    assert.equal(result.result.status.state, TaskState.TASK_STATE_COMPLETED);
    assert.equal(result.result.status.message.parts.length, 1);
    assert.equal(signatureCount, 1);
  } finally { await new Promise((accept) => running.server.close(accept)); }
});

test("declared HTTP Bearer security keeps discovery public and protects A2A task interfaces", async () => {
  const fixture = securedFixture();
  const port = await freePort(), baseUrl = `http://127.0.0.1:${port}`;
  let signedPayload;
  const common = {
    port, host: "127.0.0.1", baseUrl, agentCard: fixture.cardPath,
    executor: process.execPath, executorArgs: [join(ROOT, "test/fixtures/echo-rmn.mjs")],
    bearerUser: "contracted-test-caller",
    ...(await signing(baseUrl, (card) => { signedPayload = card; })),
  };
  await assert.rejects(serveContractedAgent(common), /require a Bearer token file/u);
  const running = await serveContractedAgent({ ...common, bearerTokenFile: fixture.tokenPath });
  try {
    const cardResponse = await fetch(`${baseUrl}/.well-known/agent-card.json`, { headers: { "A2A-Version": "1.0" } });
    assert.equal(cardResponse.status, 200);
    const publicCard = await cardResponse.json();
    assert.equal(publicCard.securitySchemes.bearerAuth.httpAuthSecurityScheme.scheme, "Bearer");
    const verifiedPayload = AgentCard.toJSON(AgentCard.fromJSON(publicCard));
    delete verifiedPayload.signatures;
    assert.equal(canonicalizeAgentCard(signedPayload), canonicalizeAgentCard(verifiedPayload));

    const unauthorized = await fetch(`${baseUrl}/a2a/jsonrpc`, {
      method: "POST", headers: { "content-type": "application/json", "A2A-Version": "1.0" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "unauthorized", method: "SendMessage", params: {} }),
    });
    assert.equal(unauthorized.status, 401);
    assert.equal(unauthorized.headers.get("www-authenticate"), 'Bearer realm="A2A"');

    const message = userRmnMessage(Buffer.from([0x82, 0x64, 0x6d, 0x61, 0x72, 0x6b, 0x61, 0x78]), "operation.rmn.cbor", "00000000-0000-4000-8000-000000000020");
    await assert.rejects(sendRmnTask({
      agentUrl: `${baseUrl}/.well-known/agent-card.json`, message, requireSignature: true,
      bearerTokenFile: fixture.wrongTokenPath,
    }), /401|authentication required|HTTP error/u);
    const result = await sendRmnTask({
      agentUrl: `${baseUrl}/.well-known/agent-card.json`, message, requireSignature: true,
      bearerTokenFile: fixture.tokenPath,
    });
    assert.equal(result.inputNi, result.outputNi);
    assert.equal(result.result.status.state, TaskState.TASK_STATE_COMPLETED);
  } finally {
    await new Promise((accept) => running.server.close(accept));
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("provider-owned long labor may complete through the persisted task lifecycle without a host temporal ceiling", async () => {
  const port = await freePort(), baseUrl = `http://127.0.0.1:${port}`;
  const running = await serveContractedAgent({
    port, host: "127.0.0.1", baseUrl,
    agentCard: join(ROOT, "test/fixtures/agent-card.json"),
    executor: process.execPath, executorArgs: [join(ROOT, "test/fixtures/slow-echo-rmn.mjs")],
    ...(await signing(baseUrl)),
  });
  try {
    const bytes = Buffer.from([0x82, 0x64, 0x6d, 0x61, 0x72, 0x6b, 0x61, 0x78]);
    const result = await sendRmnTask({
      agentUrl: `${baseUrl}/.well-known/agent-card.json`,
      message: userRmnMessage(bytes, "operation.rmn.cbor", "00000000-0000-4000-8000-000000000010"),
      requireSignature: true,
      pollIntervalMs: 20,
    });
    assert.equal(result.result.status.state, TaskState.TASK_STATE_COMPLETED);
    assert.equal(result.result.history.length, 0);
    assert.equal(result.inputNi, result.outputNi);
  } finally { await new Promise((accept) => running.server.close(accept)); }
});

test("customer A2A cancellation terminates the identified task's execution group and returns a wall-time receipt", async () => {
  const root = mkdtempSync(join(tmpdir(), "union-a2a-cancel-"));
  const childPidPath = join(root, "grandchild.pid");
  const priorChildPidPath = process.env.A2A_TEST_CHILD_PID_FILE;
  process.env.A2A_TEST_CHILD_PID_FILE = childPidPath;
  const port = await freePort(), baseUrl = `http://127.0.0.1:${port}`;
  const running = await serveContractedAgent({
    port, host: "127.0.0.1", baseUrl,
    agentCard: join(ROOT, "test/fixtures/agent-card.json"),
    executor: process.execPath, executorArgs: [join(ROOT, "test/fixtures/slow-child-rmn.mjs")],
    ...(await signing(baseUrl)),
  });
  let taskId;
  try {
    const bytes = Buffer.from([0x82, 0x64, 0x6d, 0x61, 0x72, 0x6b, 0x61, 0x78]);
    const submitted = await submitRmnTask({
      agentUrl: `${baseUrl}/.well-known/agent-card.json`,
      message: userRmnMessage(bytes, "operation.rmn.cbor", "00000000-0000-4000-8000-000000000012"),
      requireSignature: false,
    });
    taskId = submitted.taskId;
    await eventually(() => assert.ok(existsSync(childPidPath)));
    await cancelRmnTask({
      agentUrl: `${baseUrl}/.well-known/agent-card.json`, taskId,
      requireSignature: false,
    });
    const grandchildPid = Number(readFileSync(childPidPath, "utf8"));
    await eventually(() => assert.throws(() => process.kill(grandchildPid, 0), /ESRCH/u));
    await assert.rejects(
      resumeRmnTask({ agentUrl: `${baseUrl}/.well-known/agent-card.json`, taskId, inputNi: "ni:///sha-256;placeholder", requireSignature: false }),
      (error) => {
        assert.equal(error.result.status.state, TaskState.TASK_STATE_CANCELED);
        assert.equal(error.result.status.message.metadata.disposition, "cancelled");
        assert.equal(error.result.status.message.metadata.providerExecution.measure, "wall-time-milliseconds");
        assert.equal(typeof error.result.status.message.metadata.providerExecution.wallTimeMilliseconds, "number");
        return true;
      },
    );
  } finally {
    priorChildPidPath === undefined ? delete process.env.A2A_TEST_CHILD_PID_FILE : process.env.A2A_TEST_CHILD_PID_FILE = priorChildPidPath;
    await new Promise((accept) => running.server.close(accept));
    if (existsSync(childPidPath)) {
      try { process.kill(Number(readFileSync(childPidPath, "utf8")), "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; }
    }
    rmSync(root, { recursive: true, force: true });
  }
});

test("cancellation waits for the executor's actual acknowledgement before its terminal receipt", async () => {
  const root = mkdtempSync(join(tmpdir(), "union-a2a-cancellation-grace-"));
  const acknowledgement = join(root, "downstream-cancelled"), started = join(root, "downstream-started");
  const priorAcknowledgement = process.env.A2A_TEST_CANCELLATION_ACK_FILE;
  const priorStarted = process.env.A2A_TEST_CANCELLATION_STARTED_FILE;
  process.env.A2A_TEST_CANCELLATION_ACK_FILE = acknowledgement;
  process.env.A2A_TEST_CANCELLATION_STARTED_FILE = started;
  const port = await freePort(), baseUrl = `http://127.0.0.1:${port}`;
  const running = await serveContractedAgent({
    port, host: "127.0.0.1", baseUrl,
    agentCard: join(ROOT, "test/fixtures/agent-card.json"),
    executor: process.execPath, executorArgs: [join(ROOT, "test/fixtures/graceful-cancellation-rmn.mjs")],
    ...(await signing(baseUrl)),
  });
  try {
    const submitted = await submitRmnTask({
      agentUrl: `${baseUrl}/.well-known/agent-card.json`,
      message: userRmnMessage(Buffer.from([0x82, 0x64, 0x6d, 0x61, 0x72, 0x6b, 0x61, 0x78]), "operation.rmn.cbor", "00000000-0000-4000-8000-000000000013"),
      requireSignature: false,
    });
    await eventually(() => assert.equal(existsSync(started), true));
    const taskId = submitted.taskId;
    await cancelRmnTask({
      agentUrl: `${baseUrl}/.well-known/agent-card.json`, taskId,
      requireSignature: false,
    });
    assert.equal(existsSync(acknowledgement), true, "terminal cancellation follows the executor's downstream acknowledgement");
  } finally {
    priorAcknowledgement === undefined ? delete process.env.A2A_TEST_CANCELLATION_ACK_FILE : process.env.A2A_TEST_CANCELLATION_ACK_FILE = priorAcknowledgement;
    priorStarted === undefined ? delete process.env.A2A_TEST_CANCELLATION_STARTED_FILE : process.env.A2A_TEST_CANCELLATION_STARTED_FILE = priorStarted;
    await new Promise((accept) => running.server.close(accept));
    rmSync(root, { recursive: true, force: true });
  }
});

test("a2a-durable-resumption: a caller retains the standard task id and resumes after provider restart", async () => {
  const port = await freePort(), baseUrl = `http://127.0.0.1:${port}`;
  const taskSource = memoryTaskSource();
  const options = {
    port, host: "127.0.0.1", baseUrl, taskSource,
    agentCard: join(ROOT, "test/fixtures/agent-card.json"),
    executor: process.execPath, executorArgs: [join(ROOT, "test/fixtures/slow-echo-rmn.mjs")],
    ...(await signing(baseUrl)),
  };
  let running = await serveContractedAgent(options);
  try {
    const bytes = Buffer.from([0x82, 0x64, 0x6d, 0x61, 0x72, 0x6b, 0x61, 0x78]);
    const observations = [];
    const first = await sendRmnTask({
      agentUrl: `${baseUrl}/.well-known/agent-card.json`,
      message: userRmnMessage(bytes, "operation.rmn.cbor", "00000000-0000-4000-8000-000000000011"),
      requireSignature: true,
      pollIntervalMs: 20,
      onTaskObservation: async (task) => observations.push(task),
    });
    assert.ok(observations.length >= 1);
    assert.equal(observations[0].id, first.result.id);
    assert.equal(observations.at(-1).status.state, "TASK_STATE_COMPLETED");
    await new Promise((accept) => running.server.close(accept));
    running = await serveContractedAgent(options);
    const resumed = await resumeRmnTask({
      agentUrl: `${baseUrl}/.well-known/agent-card.json`, taskId: first.result.id, inputNi: first.inputNi,
      requireSignature: true,
    });
    assert.equal(resumed.result.status.state, TaskState.TASK_STATE_COMPLETED);
    assert.equal(resumed.outputNi, first.outputNi);
  } finally {
    await new Promise((accept) => running.server.close(accept));
  }
});

test("an interrupted task retains its durable intent and is projected into an exact semantic replay", async () => {
  const taskSource = memoryTaskSource();
  const customer = userRmnMessage(Buffer.from([0x82, 0x64, 0x6d, 0x61, 0x72, 0x6b, 0x61, 0x78]), "operation.rmn.cbor", "00000000-0000-4000-8000-000000000021");
  const task = Task.fromJSON({
    id: "urn:a2a:task:interrupted", contextId: "urn:a2a:context:one",
    status: { state: "TASK_STATE_WORKING", timestamp: "2026-07-22T00:00:00.000Z" },
    artifacts: [], history: [{ ...customer, taskId: "urn:a2a:task:interrupted", contextId: "urn:a2a:context:one" }], metadata: {},
  });
  try {
    const original = new DurableA2aTaskStore(taskSource);
    await original.save(task, {});
    const restarted = new DurableA2aTaskStore(taskSource);
    const recovered = await restarted.load(task.id, {});
    assert.equal(recovered.status.state, TaskState.TASK_STATE_WORKING);
    assert.deepEqual((await restarted.interrupted({})).map((value) => value.id), [task.id]);
    const calls = [];
    const outcomes = await replayInterruptedTasks({ sendMessage: async (...args) => { calls.push(args); return task; } }, restarted);
    assert.equal(outcomes[0].replayed, true);
    assert.equal(calls[0][0].message.taskId, task.id);
    assert.equal(calls[0][0].message.contextId, task.contextId);
    assert.equal(calls[0][0].message.metadata.replayOfMessageId, customer.messageId);
    assert.notEqual(calls[0][0].message.messageId, customer.messageId);
    assert.deepEqual(extractRmnPart(calls[0][0].message.parts), extractRmnPart(Message.fromJSON(customer).parts));
  } finally { /* the fake network source is process-local and disposable */ }
});

test("terminal settlement is absorbing and poisoned dependency events are quarantined without erasure", async () => {
  const root = mkdtempSync(join(tmpdir(), "union-a2a-monotone-"));
  const working = Task.fromJSON({
    id: "urn:a2a:task:monotone", contextId: "urn:a2a:context:monotone",
    status: { state: "TASK_STATE_WORKING", timestamp: "2026-07-25T00:00:00.000Z" },
    artifacts: [], history: [], metadata: {},
  });
  try {
    const store = new DurableA2aTaskStore(memoryTaskSource());
    await store.save(working, {});
    const canceled = await store.cancel(working.id, {}, "trajectory dissociated after replay storm");
    assert.equal(canceled.status.state, TaskState.TASK_STATE_CANCELED);
    await store.save({ ...working, status: { ...working.status, timestamp: "2026-07-26T00:00:00.000Z" } }, {});
    assert.equal((await store.load(working.id, {})).status.state, TaskState.TASK_STATE_CANCELED);
    assert.deepEqual(await store.interrupted({}), []);

    const inbox = new DurableDependencyEventInbox(memoryCoordinationSource());
    const body = { task: { id: "urn:a2a:child", contextId: "urn:a2a:child-context", status: { state: "TASK_STATE_COMPLETED" }, artifacts: [], history: [], metadata: {} } };
    await inbox.accept(working.id, body);
    const result = await inbox.quarantine(working.id, "parent trajectory settled");
    assert.equal(result.quarantined, 1);
    assert.equal((await inbox.pending(working.id)).length, 0);
    await inbox.accept(working.id, { ...body, task: { ...body.task, id: "urn:a2a:child:later" } });
    assert.equal((await inbox.pending(working.id)).length, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("interrupted-task replay declares every extension required by the provider card", async () => {
  const task = Task.fromJSON({
    id: "urn:a2a:task:required-extension-replay", contextId: "urn:a2a:context:required-extension-replay",
    status: { state: "TASK_STATE_WORKING", timestamp: "2026-07-22T00:00:00.000Z" },
    artifacts: [], history: [userRmnMessage(Buffer.from([0x82, 0x64, 0x6d, 0x61, 0x72, 0x6b, 0x61, 0x78]), "operation.rmn.cbor", "00000000-0000-4000-8000-000000000022")], metadata: {},
  });
  let observedContext;
  const handler = {
    getAgentCard: async () => ({ capabilities: { extensions: [{ uri: "urn:extension:required", required: true }, { uri: "urn:extension:optional", required: false }] } }),
    sendMessage: async (_request, context) => { observedContext = context; return task; },
  };
  const store = { interrupted: async () => [task] };
  const outcomes = await replayInterruptedTasks(handler, store);
  assert.equal(outcomes[0].replayed, true);
  assert.deepEqual(observedContext.requestedExtensions, ["urn:extension:required"]);
  assert.equal(observedContext.requestedVersion, "1.0");
});

test("ephemeral bearer capabilities are refused from durable task storage", async () => {
  const task = Task.fromJSON({
    id: "urn:a2a:task:ephemeral", contextId: "urn:a2a:context:ephemeral",
    status: { state: "TASK_STATE_COMPLETED", timestamp: "2026-07-22T00:00:00.000Z" },
    artifacts: [], history: [], metadata: { capability: { type: "EphemeralBucketObjectReadCapability", url: "https://example.invalid/signed", durable: false, mustNotBeRecorded: true } },
  });
  await assert.rejects(new DurableA2aTaskStore(memoryTaskSource()).save(task, {}), /ephemeral bearer capability/u);
});

test("a transient JWKS read retries silently and returns the signed provider face", async () => {
  const port = await freePort(), baseUrl = `http://127.0.0.1:${port}`;
  const running = await serveContractedAgent({
    port, host: "127.0.0.1", baseUrl,
    agentCard: join(ROOT, "test/fixtures/agent-card.json"),
    executor: process.execPath, executorArgs: [join(ROOT, "test/fixtures/echo-rmn.mjs")],
    ...(await signing(baseUrl)),
  });
  let jwksReads = 0, debugWrites = 0;
  const originalDebug = console.debug;
  console.debug = () => { debugWrites += 1; };
  try {
    const fetchCard = async (url, options) => {
      if (new URL(url).pathname === "/.well-known/jwks.json" && ++jwksReads === 1) throw Object.assign(new Error("transient reset"), { code: "ECONNRESET" });
      return fetch(url, options);
    };
    const card = await discoverAgentCard({ agentUrl: `${baseUrl}/.well-known/agent-card.json`, fetch: fetchCard, requireSignature: true });
    assert.equal(card.signatures.length, 1);
    assert.equal(jwksReads, 2);
    assert.equal(debugWrites, 0);
  } finally {
    console.debug = originalDebug;
    await new Promise((accept) => running.server.close(accept));
  }
});

test("server refuses a raw part whose claimed RMN identity does not match its bytes", async () => {
  assert.throws(() => extractRmnPart([{ content: { $case: "raw", value: Buffer.from("x") }, metadata: { ni: "ni:///sha-256;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, filename: "x.cbor", mediaType: "application/rmn+cbor" }]), /do not match/);
});

test("an executor that refuses before reading reports its refusal instead of crashing the A2A seam", async () => {
  const port = await freePort(), baseUrl = `http://127.0.0.1:${port}`;
  const running = await serveContractedAgent({
    port, host: "127.0.0.1", baseUrl,
    agentCard: join(ROOT, "test/fixtures/agent-card.json"),
    executor: process.execPath, executorArgs: [join(ROOT, "test/fixtures/refuse-before-read.mjs")],
    ...(await signing(baseUrl)),
  });
  try {
    const bytes = Buffer.alloc(512 * 1024, 0x61);
    const message = Message.toJSON({
      messageId: "00000000-0000-4000-8000-000000000001", contextId: "", taskId: "", role: Role.ROLE_USER,
      parts: [rmnPart(bytes)], metadata: {}, extensions: [], referenceTaskIds: [],
    });
    await assert.rejects(
      sendRmnTask({ agentUrl: `${baseUrl}/.well-known/agent-card.json`, message, requireSignature: true }),
      /deliberate executor refusal before request read/u,
    );
  } finally { await new Promise((accept) => running.server.close(accept)); }
});
