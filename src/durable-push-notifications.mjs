import { createHash, randomUUID } from "node:crypto";
import { StreamResponse } from "@a2a-js/sdk";

function scope(context = {}) { return createHash("sha256").update(`${context.tenant ?? ""}\n${context.user?.userName ?? "anonymous"}`, "utf8").digest("hex"); }
function sourceRequired(source) { if (!source || typeof source.put !== "function" || typeof source.get !== "function" || typeof source.list !== "function" || typeof source.remove !== "function") throw new Error("A2A coordination requires one network custody/index source"); return source; }
function scopedTask(taskId, context) { return `${scope(context)}:${taskId}`; }

export class DurablePushNotificationStore {
  constructor(source) { this.source = sourceRequired(source); }
  async save(taskId, context, config) {
    if (typeof taskId !== "string" || taskId === "") throw new Error("push notification config requires a task id");
    if (typeof config.url !== "string" || !/^https:\/\//u.test(config.url)) throw new Error("push notification callback must use HTTPS");
    config.id ||= randomUUID();
    const coordinate = { namespace: "push-configurations", tenant: context.tenant ?? "", key: scopedTask(taskId, context) };
    const prior = (await this.source.get(coordinate))?.value ?? { taskId, configurations: [] };
    const exact = structuredClone(config);
    await this.source.put({ ...coordinate, value: { taskId, configurations: [...prior.configurations.filter(({ config: item }) => item.id !== exact.id), { config: exact, wireVersion: context.requestedVersion || "1.0" }] } });
  }
  async load(taskId, context) { return (await this.loadWithMetadata(taskId, context)).map(({ config }) => config); }
  async loadWithMetadata(taskId, context) { return (await this.source.get({ namespace: "push-configurations", tenant: context.tenant ?? "", key: scopedTask(taskId, context) }))?.value.configurations ?? []; }
  async delete(taskId, context, configId) {
    const coordinate = { namespace: "push-configurations", tenant: context.tenant ?? "", key: scopedTask(taskId, context) };
    const prior = await this.source.get(coordinate); if (prior === null) return;
    if (!configId) return await this.source.remove(coordinate);
    const configurations = prior.value.configurations.filter(({ config }) => config.id !== configId);
    if (configurations.length === 0) await this.source.remove(coordinate); else await this.source.put({ ...coordinate, value: { taskId, configurations } });
  }
}
function taskIdOf(streamResponse) { const payload = streamResponse?.payload; if (!payload) throw new Error("push notification lacks an A2A payload"); return payload.$case === "task" ? payload.value.id : payload.value.taskId; }
function authorization(config) { if (config.authentication?.scheme && config.authentication?.credentials) return { Authorization: `${config.authentication.scheme} ${config.authentication.credentials}` }; return config.token ? { "X-A2A-Notification-Token": config.token } : {}; }

export class DurablePushNotificationSender {
  constructor(store, source, { fetchImpl = fetch } = {}) { this.store = store; this.source = sourceRequired(source); this.fetchImpl = fetchImpl; }
  async deliver(record) {
    const response = await this.fetchImpl(record.config.url, { method: "POST", headers: { "Content-Type": "application/a2a+json", ...authorization(record.config) }, body: record.body, redirect: "error" });
    if (!response.ok) throw new Error(`push callback refused with HTTP ${response.status}`);
    await this.source.put({ namespace: "push-outbox", tenant: record.tenant, key: record.key, value: { ...record, disposition: "delivered" } });
  }
  async send(streamResponse, context) {
    const taskId = taskIdOf(streamResponse), configurations = await this.store.loadWithMetadata(taskId, context), body = JSON.stringify(StreamResponse.toJSON(streamResponse)), tenant = context.tenant ?? "";
    for (const { config, wireVersion } of configurations) {
      if (wireVersion !== "1.0") throw new Error(`durable push sender does not silently reinterpret A2A ${wireVersion}`);
      const key = createHash("sha256").update(`${taskId}\n${config.id}\n${body}`, "utf8").digest("hex"), coordinate = { namespace: "push-outbox", tenant, key };
      let record = (await this.source.get(coordinate))?.value;
      if (!record) { record = { taskId, config, wireVersion, body, tenant, key, disposition: "pending" }; await this.source.put({ ...coordinate, value: record }); }
      if (record.disposition === "pending") await this.deliver(record);
    }
  }
  async replayPending(tenant = "") {
    const records = (await this.source.list({ namespace: "push-outbox", tenant })).map(({ value }) => value).filter(({ disposition }) => disposition === "pending"), outcomes = [];
    for (const record of records) { try { await this.deliver(record); outcomes.push({ key: record.key, delivered: true }); } catch (error) { outcomes.push({ key: record.key, delivered: false, reason: error.message }); } }
    return outcomes;
  }
}

export class DurableDependencyEventInbox {
  constructor(source) { this.source = sourceRequired(source); }
  async accept(taskId, body) {
    if (typeof taskId !== "string" || taskId === "") throw new Error("dependency event requires a task id");
    const wireBody = JSON.stringify(StreamResponse.toJSON(StreamResponse.fromJSON(body))), key = createHash("sha256").update(`${taskId}\n${wireBody}`, "utf8").digest("hex"), coordinate = { namespace: "dependency-inbox", tenant: "", key };
    const prior = await this.source.get(coordinate); if (!prior) await this.source.put({ ...coordinate, value: { taskId, wireBody, key, disposition: "pending" } });
    if (await this.isQuarantined(taskId)) await this.source.put({ ...coordinate, value: { ...(prior?.value ?? { taskId, wireBody, key }), disposition: "quarantined" } });
    return { taskId, key, duplicate: prior?.value.disposition === "delivered" };
  }
  quarantineKey(taskId) { return `task:${createHash("sha256").update(taskId, "utf8").digest("hex")}`; }
  async isQuarantined(taskId) { return (await this.source.get({ namespace: "dependency-quarantines", tenant: "", key: this.quarantineKey(taskId) })) !== null; }
  async quarantine(taskId, reason) {
    if (typeof taskId !== "string" || taskId === "" || typeof reason !== "string" || reason === "") throw new Error("dependency quarantine requires a task id and reason");
    const records = await this.pending(taskId);
    await this.source.put({ namespace: "dependency-quarantines", tenant: "", key: this.quarantineKey(taskId), value: { taskId, reason, disposition: "quarantined" } });
    await Promise.all(records.map((record) => this.source.put({ namespace: "dependency-inbox", tenant: "", key: record.key, value: { ...record, disposition: "quarantined" } })));
    return { taskId, quarantined: records.length, reason };
  }
  async pending(taskId) { return (await this.source.list({ namespace: "dependency-inbox", tenant: "" })).map(({ value }) => value).filter((record) => record.disposition === "pending" && (taskId === undefined || record.taskId === taskId)); }
  async settle(record) { await this.source.put({ namespace: "dependency-inbox", tenant: "", key: record.key, value: { ...record, disposition: "delivered" } }); }
}
