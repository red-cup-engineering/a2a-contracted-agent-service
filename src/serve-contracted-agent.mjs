#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import express from "express";
import { AGENT_CARD_PATH, AgentCard, Message, Role, StreamResponse, TaskState, generateAgentCardSignature } from "@a2a-js/sdk";
import { importPKCS8 } from "jose";
import { AgentEvent, DefaultExecutionEventBusManager, DefaultRequestHandler, ServerCallContext } from "@a2a-js/sdk/server";
import { UserBuilder, agentCardHandler, jsonRpcHandler, restHandler } from "@a2a-js/sdk/server/express";
import { extractRmnPart } from "@red-cup-engineering/a2a-rmn-part-service";
import { DurableA2aTaskStore } from "./durable-task-store.mjs";
import { DurableDependencyEventInbox, DurablePushNotificationSender, DurablePushNotificationStore } from "./durable-push-notifications.mjs";

function values(flag) {
  const result = [];
  for (let index = 0; index < process.argv.length; index += 1) if (process.argv[index] === flag) result.push(process.argv[index + 1]);
  return result;
}
function value(flag, fallback) { const found = values(flag); return found.length === 0 ? fallback : found.at(-1); }
function boundedInteger(flag, fallback, minimum, maximum) {
  const parsed = Number(value(flag, fallback));
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`${flag} must be an integer from ${minimum} through ${maximum}`);
  return parsed;
}
function canonicalPositiveInteger(raw, label) {
  if (!/^[1-9][0-9]*$/u.test(raw ?? "")) throw new Error(`${label} must be one canonical positive decimal integer`);
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${label} exceeds the safe integer range`);
  return parsed;
}
export function inheritedSystemdListener(environment = process.env, processId = process.pid) {
  const hasPid = environment.LISTEN_PID !== undefined;
  const hasFds = environment.LISTEN_FDS !== undefined;
  const hasNames = environment.LISTEN_FDNAMES !== undefined;
  if (!hasPid && !hasFds && !hasNames) return null;
  if (!hasPid || !hasFds) throw new Error("socket activation requires both LISTEN_PID and LISTEN_FDS");
  if (canonicalPositiveInteger(environment.LISTEN_PID, "LISTEN_PID") !== processId) {
    throw new Error("socket activation LISTEN_PID does not identify this provider process");
  }
  if (canonicalPositiveInteger(environment.LISTEN_FDS, "LISTEN_FDS") !== 1) {
    throw new Error("contracted A2A providers require exactly one inherited listener");
  }
  const names = hasNames ? environment.LISTEN_FDNAMES.split(":") : [];
  if (hasNames && (names.length !== 1 || names[0] !== "a2a")) {
    throw new Error('the inherited contracted A2A listener must be named "a2a"');
  }
  return Object.freeze({ fd: 3, name: "a2a", source: "systemd-socket-activation" });
}
function sameSecurityRequirement(left, right) {
  return JSON.stringify(left ?? []) === JSON.stringify(right ?? []);
}
function declaredHttpBearer(card) {
  const requirements = card.securityRequirements ?? [];
  const schemes = card.securitySchemes ?? {};
  if (requirements.length === 0) {
    if (Object.keys(schemes).length !== 0) throw new Error("an A2A Agent Card cannot declare unused security schemes");
    for (const skill of card.skills ?? []) {
      if ((skill.securityRequirements ?? []).length !== 0) throw new Error("an A2A skill cannot require security absent from its Agent Card");
    }
    return null;
  }
  if (requirements.length !== 1) throw new Error("contracted A2A providers support exactly one global security requirement");
  const names = Object.keys(requirements[0]?.schemes ?? {});
  if (names.length !== 1 || Object.keys(schemes).length !== 1 || !Object.hasOwn(schemes, names[0])) {
    throw new Error("contracted A2A providers require exactly one referenced security scheme");
  }
  const declared = schemes[names[0]]?.httpAuthSecurityScheme;
  if (!declared || String(declared.scheme).toLowerCase() !== "bearer") {
    throw new Error("contracted A2A providers currently admit only standard HTTP Bearer security");
  }
  for (const skill of card.skills ?? []) {
    if (!sameSecurityRequirement(skill.securityRequirements, requirements)) {
      throw new Error("every A2A skill must carry the Agent Card's global security requirement");
    }
  }
  return { name: names[0], requirement: requirements };
}
function readBearerToken(path) {
  const bytes = readFileSync(resolve(path));
  if (bytes.length === 0 || bytes.length > 4096) throw new Error("A2A Bearer token must contain 1 through 4096 bytes");
  const token = bytes.toString("utf8").replace(/\r?\n$/u, "");
  if (!/^[A-Za-z0-9\-._~+/]+=*$/u.test(token)) throw new Error("A2A Bearer token file must contain one RFC 6750 bearer token");
  return Buffer.from(token, "utf8");
}
function bearerAuthenticator(expected, userName) {
  const authenticate = (request) => {
    const supplied = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/u.exec(request.get("authorization") ?? "")?.[1];
    const candidate = supplied === undefined ? Buffer.alloc(0) : Buffer.from(supplied, "utf8");
    return candidate.length === expected.length && timingSafeEqual(candidate, expected);
  };
  return {
    middleware(request, response, next) {
      if (!authenticate(request)) {
        response.set("WWW-Authenticate", 'Bearer realm="A2A"');
        return response.status(401).json({ error: "A2A Bearer authentication required" });
      }
      next();
    },
    userBuilder: async (request) => {
      if (!authenticate(request)) throw new Error("A2A Bearer authentication invariant failed");
      return { get isAuthenticated() { return true; }, get userName() { return userName; } };
    },
  };
}
function loadAgentCard(path, baseUrl) {
  const source = readFileSync(resolve(path), "utf8").replaceAll("${BASE_URL}", baseUrl);
  const card = JSON.parse(source);
  const controllerAccount = process.env.CONTROLLER_ACCOUNT;
  if (controllerAccount !== undefined) {
    if (!/^eip155:[1-9][0-9]*:0x[0-9a-fA-F]{40}$/u.test(controllerAccount)) {
      throw new Error("CONTROLLER_ACCOUNT must be one EIP-155 CAIP-10 account");
    }
    for (const extension of card.capabilities?.extensions ?? []) {
      if (extension?.params?.profile === "org.emsenn.rmn.sovereign-circuit-interface.v1") {
        extension.params.account = controllerAccount;
      }
    }
  }
  card.capabilities = { ...(card.capabilities ?? {}), pushNotifications: true };
  if (!Array.isArray(card.supportedInterfaces) || card.supportedInterfaces.length === 0) throw new Error("Agent Card requires supportedInterfaces");
  for (const endpoint of card.supportedInterfaces) {
    if (endpoint.protocolVersion !== "1.0") throw new Error("only A2A 1.0 interfaces are admitted");
    if (!["JSONRPC", "HTTP+JSON"].includes(endpoint.protocolBinding)) throw new Error(`unsupported A2A binding ${endpoint.protocolBinding}`);
    if (!String(endpoint.url).startsWith(baseUrl)) throw new Error("Agent Card interfaces must be rooted at --base-url");
  }
  return { card: AgentCard.fromJSON(card), bearer: declaredHttpBearer(card) };
}
async function signingConfiguration(options, baseUrl) {
  const normalizeGenerator = (generator) => async (agentCard) => {
    const normalized = AgentCard.toJSON(agentCard);
    const signed = await generator(normalized);
    return { ...agentCard, signatures: signed.signatures };
  };
  if (options.agentCardSignatureGenerator || options.agentCardJwks) {
    if (!options.agentCardSignatureGenerator || !options.agentCardJwks) throw new Error("agentCardSignatureGenerator and agentCardJwks must be supplied together");
    if (!options.dependencyCallbackKey) throw new Error("custom Agent Card signing requires a separate dependencyCallbackKey");
    return { generator: normalizeGenerator(options.agentCardSignatureGenerator), jwks: options.agentCardJwks, callbackKey: Buffer.from(options.dependencyCallbackKey) };
  }
  const privateKeyPath = value("--agent-card-signing-key", process.env.AGENT_CARD_SIGNING_KEY);
  const jwksPath = value("--agent-card-jwks", process.env.AGENT_CARD_JWKS);
  const kid = value("--agent-card-signing-kid", process.env.AGENT_CARD_SIGNING_KID);
  const algorithm = value("--agent-card-signing-alg", process.env.AGENT_CARD_SIGNING_ALG ?? "EdDSA");
  if (!privateKeyPath || !jwksPath || !kid) {
    throw new Error("contracted A2A providers require an Agent Card signing key, public JWKS, and kid");
  }
  const jwks = JSON.parse(readFileSync(resolve(jwksPath), "utf8"));
  const matches = jwks?.keys?.filter((key) => key?.kid === kid && key?.alg === algorithm && !Object.hasOwn(key, "d")) ?? [];
  if (matches.length !== 1) throw new Error("configured Agent Card JWKS must expose exactly one matching public key");
  const privateKeyBytes = readFileSync(resolve(privateKeyPath));
  const privateKey = await importPKCS8(privateKeyBytes.toString("utf8"), algorithm);
  return {
    generator: normalizeGenerator(generateAgentCardSignature(privateKey, { alg: algorithm, kid, typ: "JOSE", jku: `${baseUrl}/.well-known/jwks.json` })),
    jwks,
    callbackKey: createHash("sha256").update("A2A dependency callback\0").update(privateKeyBytes).digest(),
  };
}
class TaskCancelledError extends Error {
  constructor(message = "contracted executor cancelled") {
    super(message);
    this.name = "TaskCancelledError";
  }
}

function signalExecutorGroup(child, signal) {
  if (!child.pid) return;
  try {
    if (process.platform !== "win32") process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

async function terminateExecutor(child) {
  if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
  const close = new Promise((resolve) => child.once("close", resolve));
  signalExecutorGroup(child, "SIGTERM");
  await close;
}

function executorEnvironment(source, grants) {
  const denied = new Set([
    "AGENT_CARD_SIGNING_KEY", "AGENT_CARD_SIGNING_KID", "AGENT_CARD_SIGNING_ALG",
    "A2A_BEARER_TOKEN_FILE", "A2A_BEARER_USER", "A2A_DEPENDENCY_CALLBACK_KEY_FILE",
  ]);
  return {
    ...Object.fromEntries(Object.entries(source).filter(([name]) => !denied.has(name))),
    ...grants,
  };
}

function execute(command, args, input, { taskId, contextId, signal, onCancellation, environment }) {
  return new Promise((accept, reject) => {
    if (signal?.aborted) return reject(signal.reason instanceof Error ? signal.reason : new TaskCancelledError());
    const child = spawn(command, args, {
      cwd: value("--executor-cwd", process.cwd()),
      env: executorEnvironment(process.env, { A2A_TASK_ID: taskId, A2A_CONTEXT_ID: contextId, ...environment }),
      stdio: ["pipe", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    const stdout = [], stderr = [];
    let settled = false, cancellation = null;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", cancel);
      if (error) reject(error); else accept(result);
    };
    const cancel = (reason = signal?.reason instanceof Error ? signal.reason : new TaskCancelledError()) => {
      if (cancellation) return cancellation;
      cancellation = terminateExecutor(child).then(
        () => finish(reason),
        (error) => finish(error),
      );
      onCancellation?.(cancellation);
      return cancellation;
    };
    child.stdout.on("data", (chunk) => { stdout.push(chunk); });
    child.stderr.on("data", (chunk) => { stderr.push(chunk); });
    child.stdin.on("error", (error) => { if (error.code !== "EPIPE") finish(error); });
    child.on("error", (error) => finish(error));
    child.on("close", (code, signal) => {
      if (cancellation) return;
      code === 0
        ? finish(undefined, Buffer.concat(stdout))
        : finish(new Error(`contracted executor refused with code ${code ?? "none"} signal ${signal ?? "none"}: ${Buffer.concat(stderr).toString("utf8")}`));
    });
    signal?.addEventListener("abort", cancel, { once: true });
    child.stdin.end(input);
  });
}

function providerExecution(active, termination) {
  return {
    measure: "wall-time-milliseconds",
    wallTimeMilliseconds: Number((process.hrtime.bigint() - active.startedAtMonotonic) / 1_000_000n),
    startedAt: active.startedAt,
    finishedAt: new Date().toISOString(),
    termination,
  };
}

function callbackToken(key, taskId) {
  return createHmac("sha256", key).update(`a2a-parent-task\n${taskId}`, "utf8").digest("base64url");
}

function suppliedBearer(request) {
  return /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/u.exec(request.get("authorization") ?? "")?.[1];
}

function sameToken(left, right) {
  const one = Buffer.from(left ?? "", "utf8"), two = Buffer.from(right ?? "", "utf8");
  return one.length === two.length && timingSafeEqual(one, two);
}

function terminalPushNotification(source) {
  const event = StreamResponse.fromJSON(source);
  const payload = event.payload;
  const state = payload?.$case === "task"
    ? payload.value.status?.state
    : payload?.$case === "statusUpdate"
      ? payload.value.status?.state
      : undefined;
  return [
    TaskState.TASK_STATE_COMPLETED,
    TaskState.TASK_STATE_FAILED,
    TaskState.TASK_STATE_CANCELED,
    TaskState.TASK_STATE_INPUT_REQUIRED,
    TaskState.TASK_STATE_REJECTED,
    TaskState.TASK_STATE_AUTH_REQUIRED,
  ].includes(state);
}

async function replayTask(handler, task, context, metadata = {}) {
  const prior = [...(task.history ?? [])].reverse().find((message) => message.role === Role.ROLE_USER);
  if (!prior) throw new Error(`durable task ${task.id} has no customer message to replay`);
  const message = {
    ...structuredClone(prior),
    messageId: randomUUID(),
    taskId: task.id,
    contextId: task.contextId,
    metadata: { ...(prior.metadata ?? {}), ...metadata, replayOfMessageId: prior.messageId },
  };
  await handler.sendMessage({ message, configuration: { returnImmediately: true } }, context);
  return { taskId: task.id, replayed: true, replayOfMessageId: prior.messageId, messageId: message.messageId };
}

export async function replayInterruptedTasks(handler, taskStore, context = { tenant: "" }) {
  const interrupted = await taskStore.interrupted(context);
  let replayContext = context;
  if (typeof handler.getAgentCard === "function") {
    const card = await handler.getAgentCard();
    const requiredExtensions = (card.capabilities?.extensions ?? [])
      .filter((extension) => extension.required === true)
      .map((extension) => extension.uri);
    const requestedExtensions = [...new Set([
      ...(context.requestedExtensions ?? []),
      ...requiredExtensions,
    ])];
    replayContext = new ServerCallContext({
      tenant: context.tenant ?? "",
      user: context.user,
      requestedVersion: context.requestedVersion ?? "1.0",
      requestedExtensions,
    });
  }
  const outcomes = [];
  for (const task of interrupted) {
    try { outcomes.push(await replayTask(handler, task, replayContext, { recoveredAfterInterruption: true })); }
    catch (error) { outcomes.push({ taskId: task.id, replayed: false, reason: error.message }); }
  }
  return outcomes;
}

export async function serveContractedAgent(options = {}) {
  const inheritedListener = options.listener ?? inheritedSystemdListener(options.environment ?? process.env, options.processId ?? process.pid);
  const port = inheritedListener ? null : options.port ?? boundedInteger("--port", "8080", 1, 65535);
  const host = inheritedListener ? null : options.host ?? value("--host", "127.0.0.1");
  if (host !== null && !["127.0.0.1", "localhost", "::1"].includes(host)) {
    throw new Error("public A2A listeners are forbidden: carry A2A inside the actor's ActivityPub CloudEvents membrane");
  }
  const configuredBaseUrl = options.baseUrl ?? value("--base-url", process.env.BASE_URL);
  if (inheritedListener && !configuredBaseUrl) {
    throw new Error("an inherited listener requires an explicit public --base-url or BASE_URL");
  }
  const baseUrl = configuredBaseUrl ?? `http://${host}:${port}`;
  const agentCardPath = options.agentCard ?? value("--agent-card");
  const command = options.executor ?? value("--executor");
  const args = options.executorArgs ?? values("--executor-arg");
  const retiredExecutionBounds = [
    ["maxBytes", "--max-bytes"],
    ["requestMaxBytes", "--request-max-bytes"],
  ];
  for (const [option, flag] of retiredExecutionBounds) {
    if (options[option] !== undefined || value(flag) !== undefined) {
      throw new Error(`${option} is retired: contracted tasks remain durable until completion, provider refusal, or explicit A2A customer cancellation`);
    }
  }
  // Thin A2A state is chain-carried. The membrane supplies the on-chain
  // sources; this process deliberately has no R2 state fallback.
  if (!options.taskStore && !options.taskSource) throw new Error("contracted A2A agent requires a membrane-provided on-chain task source");
  if (!options.coordinationSource) throw new Error("contracted A2A agent requires a membrane-provided on-chain coordination source");
  const taskStore = options.taskStore ?? new DurableA2aTaskStore(options.taskSource);
  const coordinationSource = options.coordinationSource;
  const pushNotificationStore = options.pushNotificationStore ?? new DurablePushNotificationStore(coordinationSource);
  const pushNotificationSender = options.pushNotificationSender ?? new DurablePushNotificationSender(pushNotificationStore, coordinationSource);
  const dependencyEventInbox = options.dependencyEventInbox ?? new DurableDependencyEventInbox(coordinationSource);
  if (!agentCardPath || !command) throw new Error("--agent-card and --executor are required");
  const loaded = loadAgentCard(agentCardPath, baseUrl);
  const card = loaded.card;
  const bearerTokenPath = options.bearerTokenFile ?? value("--bearer-token-file", process.env.A2A_BEARER_TOKEN_FILE);
  const bearerUser = options.bearerUser ?? value("--bearer-user", process.env.A2A_BEARER_USER);
  if (loaded.bearer && (!bearerTokenPath || !bearerUser)) throw new Error("secured A2A Agent Cards require a Bearer token file and authenticated user name");
  if (!loaded.bearer && (bearerTokenPath || bearerUser)) throw new Error("A2A Bearer configuration requires a matching Agent Card security declaration");
  const authentication = loaded.bearer ? bearerAuthenticator(readBearerToken(bearerTokenPath), bearerUser) : null;
  const userBuilder = authentication?.userBuilder ?? UserBuilder.noAuthentication;
  const signing = await signingConfiguration(options, baseUrl);
  const activeTasks = new Map();
  const eventBusManager = options.eventBusManager ?? new DefaultExecutionEventBusManager();
  const executor = {
    async execute(requestContext, eventBus) {
      let releaseExecution;
      const active = {
        controller: new AbortController(), eventBus,
        contextId: requestContext.contextId,
        startedAt: new Date().toISOString(), startedAtMonotonic: process.hrtime.bigint(),
        cleanup: Promise.resolve(),
        suspended: false,
        settled: new Promise((resolve) => { releaseExecution = resolve; }),
      };
      activeTasks.set(requestContext.taskId, active);
      eventBus.publish(AgentEvent.task({
        id: requestContext.taskId,
        contextId: requestContext.contextId,
        status: {
          state: TaskState.TASK_STATE_WORKING,
          message: undefined,
          timestamp: new Date().toISOString(),
        },
        artifacts: [],
        history: [],
        metadata: {},
      }));
      try {
        const input = extractRmnPart(requestContext.userMessage.parts);
        const running = execute(command, args, Buffer.from(`${JSON.stringify(Message.toJSON(requestContext.userMessage))}\n`, "utf8"), {
          taskId: requestContext.taskId, contextId: requestContext.contextId, signal: active.controller.signal,
          onCancellation: (cleanup) => { active.cleanup = cleanup; },
          environment: {
            A2A_PARENT_CALLBACK_URL: `${baseUrl}/dependency-events/${encodeURIComponent(requestContext.taskId)}`,
            A2A_PARENT_CALLBACK_TOKEN: callbackToken(signing.callbackKey, requestContext.taskId),
          },
        });
        const output = await running;
        let response;
        try { response = Message.fromJSON(JSON.parse(output.toString("utf8"))); }
        catch (error) { throw new Error(`contracted executor did not return an A2A 1.0 Message: ${error.message}`); }
        if (response.role !== Role.ROLE_AGENT) throw new Error("contracted executor response role must be ROLE_AGENT");
        extractRmnPart(response.parts);
        if (response.metadata?.suspension?.type === "A2aTaskDependency") {
          active.suspended = true;
          eventBus.publish(AgentEvent.statusUpdate({
            taskId: requestContext.taskId,
            contextId: requestContext.contextId,
            status: {
              state: TaskState.TASK_STATE_WORKING,
              message: {
                ...response,
                messageId: response.messageId || randomUUID(),
                contextId: requestContext.contextId,
                taskId: requestContext.taskId,
              },
              timestamp: new Date().toISOString(),
            },
            metadata: { suspension: response.metadata.suspension },
          }));
          return;
        }
        const completed = {
          ...response, messageId: response.messageId || randomUUID(),
          contextId: requestContext.contextId, taskId: requestContext.taskId,
          metadata: { ...(response.metadata ?? {}), inputNi: input.ni, providerExecution: providerExecution(active, "completed") }
        };
        eventBus.publish(AgentEvent.statusUpdate({
          taskId: requestContext.taskId,
          contextId: requestContext.contextId,
          status: {
            state: TaskState.TASK_STATE_COMPLETED,
            message: completed,
            timestamp: new Date().toISOString(),
          },
          metadata: { providerExecution: response.metadata.providerExecution },
        }));
      } catch (error) {
        if (active.controller.signal.aborted || error instanceof TaskCancelledError) return;
        const execution = providerExecution(active, "refused");
        const refused = {
          messageId: randomUUID(), contextId: requestContext.contextId, taskId: requestContext.taskId,
          role: Role.ROLE_AGENT,
          parts: [{ content: { $case: "text", value: String(error.message) }, metadata: {}, filename: "", mediaType: "text/plain" }],
          metadata: { disposition: "refused", providerExecution: execution }, extensions: [], referenceTaskIds: []
        };
        eventBus.publish(AgentEvent.statusUpdate({
          taskId: requestContext.taskId,
          contextId: requestContext.contextId,
          status: {
            state: TaskState.TASK_STATE_FAILED,
            message: refused,
            timestamp: new Date().toISOString(),
          },
          metadata: { providerExecution: execution },
        }));
      } finally {
        activeTasks.delete(requestContext.taskId);
        releaseExecution();
        // DefaultRequestHandler owns its transient event bus lifecycle.  The
        // durable task store, not a reused in-process bus, carries continuity.
      }
    },
    async cancelTask(taskId, eventBus) {
      const active = activeTasks.get(taskId);
      if (active) {
        active.controller.abort(new TaskCancelledError("contracted executor cancelled by its A2A customer"));
        await active.cleanup;
      }
      const execution = active ? providerExecution(active, "cancelled") : undefined;
      eventBus.publish(AgentEvent.statusUpdate({
        taskId,
        contextId: active?.contextId ?? "",
        status: {
          state: TaskState.TASK_STATE_CANCELED,
          message: {
            messageId: randomUUID(), taskId, contextId: active?.contextId ?? "", role: Role.ROLE_AGENT,
            parts: [{ content: { $case: "text", value: "Task cancellation requested by customer." }, metadata: {}, filename: "", mediaType: "text/plain" }],
            metadata: { disposition: "cancelled", ...(execution ? { providerExecution: execution } : {}) }, extensions: [], referenceTaskIds: [],
          },
          timestamp: new Date().toISOString(),
        },
        metadata: execution ? { providerExecution: execution } : {},
      }));
      eventBus.finished();
    }
  };
  let signedCardPromise;
  const signCardOnce = (candidate) => {
    signedCardPromise ??= signing.generator(candidate);
    return signedCardPromise;
  };
  const handler = new DefaultRequestHandler(card, taskStore, executor, eventBusManager, pushNotificationStore, pushNotificationSender, undefined, signCardOnce);
  const recovery = await replayInterruptedTasks(handler, taskStore);
  const advertisedCard = AgentCard.toJSON(await handler.getAgentCard());
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: Number.POSITIVE_INFINITY, strict: false, type: ["application/json", "application/a2a+json"] }));
  const continuationDrains = new Map();
  const drainDependencyEvents = (taskId) => {
    if (continuationDrains.has(taskId)) return continuationDrains.get(taskId);
    const drain = (async () => {
      if (await dependencyEventInbox.isQuarantined(taskId)) {
        await dependencyEventInbox.quarantine(taskId, "task coordination trajectory was explicitly dissociated");
        return;
      }
      for (const event of await dependencyEventInbox.pending(taskId)) {
        const active = activeTasks.get(taskId);
        if (active) await active.settled;
        const context = new ServerCallContext({
          tenant: "",
          requestedVersion: "1.0",
          requestedExtensions: (card.capabilities?.extensions ?? []).filter(({ required }) => required === true).map(({ uri }) => uri),
        });
        const task = await taskStore.load(taskId, context);
        if (!task) throw new Error("parent task not found");
        if (![TaskState.TASK_STATE_COMPLETED, TaskState.TASK_STATE_FAILED, TaskState.TASK_STATE_CANCELED].includes(task.status?.state)) {
          await replayTask(handler, task, context, { dependencyEventAccepted: true });
          const resumed = activeTasks.get(taskId);
          if (resumed) await resumed.settled;
        }
        await dependencyEventInbox.settle(event);
      }
    })().finally(() => {
      if (continuationDrains.get(taskId) === drain) continuationDrains.delete(taskId);
      // A callback can be seated between the final directory read and lock
      // release.  Start another drain from durable state when that happens.
      dependencyEventInbox.pending(taskId).then((pending) => { if (pending.length > 0) drainDependencyEvents(taskId); }).catch((error) => process.stderr.write(`dependency recheck ${taskId} obstructed: ${error.stack ?? error.message}\n`));
    });
    continuationDrains.set(taskId, drain);
    return drain;
  };
  app.post("/dependency-events/:taskId", async (request, response) => {
    const taskId = request.params.taskId;
    const expected = callbackToken(signing.callbackKey, taskId);
    if (!sameToken(suppliedBearer(request), expected)) return response.status(401).json({ error: "task-scoped callback capability required" });
    if (!terminalPushNotification(request.body)) return response.status(202).json({ accepted: true, resumed: false });
    try {
      const receipt = await dependencyEventInbox.accept(taskId, request.body);
      drainDependencyEvents(taskId).catch((error) => process.stderr.write(`dependency drain ${taskId} obstructed: ${error.stack ?? error.message}\n`));
      return response.status(202).json({ accepted: true, seated: true, duplicate: receipt.duplicate });
    }
    catch (error) { return response.status(409).json({ accepted: false, error: error.message }); }
  });
  app.get("/.well-known/jwks.json", (_request, response) => response.type("application/jwk-set+json").send(signing.jwks));
  app.use(`/${AGENT_CARD_PATH}`, agentCardHandler({ agentCardProvider: async () => advertisedCard }));
  if (authentication) app.use(["/a2a/jsonrpc", "/a2a/rest"], authentication.middleware);
  app.use("/a2a/jsonrpc", jsonRpcHandler({ requestHandler: handler, userBuilder }));
  app.use("/a2a/rest", restHandler({ requestHandler: handler, userBuilder }));
  const server = await new Promise((accept, reject) => {
    const target = inheritedListener ? { fd: inheritedListener.fd } : { port, host };
    const listening = app.listen(target, () => accept(listening));
    listening.once("error", reject);
  });
  const recoveredPushDeliveries = await pushNotificationSender.replayPending();
  for (const taskId of [...new Set((await dependencyEventInbox.pending()).map((event) => event.taskId))]) {
    drainDependencyEvents(taskId).catch((error) => process.stderr.write(`dependency recovery ${taskId} obstructed: ${error.stack ?? error.message}\n`));
  }
  return {
    server,
    baseUrl,
    card,
    recovery,
    recoveredPushDeliveries,
    listener: inheritedListener ?? Object.freeze({ host, port, source: "process-bound-listener" }),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) {
  serveContractedAgent().then(({ server, baseUrl }) => {
    process.stdout.write(`${baseUrl}\n`);
    const stop = () => server.close(() => process.exit(0));
    process.once("SIGINT", stop); process.once("SIGTERM", stop);
  }).catch((error) => { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; });
}
