import { randomUUID } from "node:crypto";
import { Role, Task, TaskState } from "@a2a-js/sdk";
import { a2aTaskStateRecord } from "@red-cup-engineering/a2a-task-state-custody-service";

const TERMINAL = new Set([
  TaskState.TASK_STATE_COMPLETED,
  TaskState.TASK_STATE_FAILED,
  TaskState.TASK_STATE_CANCELED,
  TaskState.TASK_STATE_INPUT_REQUIRED,
  TaskState.TASK_STATE_REJECTED,
  TaskState.TASK_STATE_AUTH_REQUIRED,
]);

function project(task, historyLength, includeArtifacts = true) {
  const copy = structuredClone(task);
  if (historyLength === 0) copy.history = [];
  else if (Number.isInteger(historyLength) && historyLength > 0) copy.history = (copy.history ?? []).slice(-historyLength);
  if (!includeArtifacts) copy.artifacts = [];
  return copy;
}
function containsEphemeralBearer(value, seen = new Set()) {
  if (value === null || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (value.mustNotBeRecorded === true && value.durable === false && typeof value.url === "string") return true;
  return Object.values(value).some((child) => containsEphemeralBearer(child, seen));
}
function taskFromRecord(record, taskId, context = {}) {
  const envelope = record?.envelope;
  if (record === null || record === undefined) return undefined;
  const projection = envelope?.task ?? envelope?.taskIndex;
  if (envelope?.protocol !== "A2A" || envelope.protocolVersion !== "1.0" || envelope.tenant !== (context.tenant ?? "") || projection?.id !== taskId) {
    throw new Error("network task source returned a different A2A task coordinate");
  }
  return Task.fromJSON(projection);
}

/** The official A2A task projection lives at one network custody/index source.
 * This adapter keeps no filesystem authority, enumeration, or dual-write path. */
export class DurableA2aTaskStore {
  constructor(source) {
    if (source === undefined || typeof source.put !== "function" || typeof source.get !== "function" || typeof source.list !== "function") {
      throw new Error("A2A task storage requires one network task-state custody/index source");
    }
    this.source = source;
  }

  async interrupted(context = {}) {
    const records = await this.source.list({ tenant: context.tenant ?? "" });
    if (!Array.isArray(records)) throw new Error("network task source list must return an array");
    return records
      .map((record) => taskFromRecord(record, record?.taskId, context))
      .filter((task) => task !== undefined && !TERMINAL.has(task.status?.state))
      .sort((left, right) => (left.status?.timestamp ?? "").localeCompare(right.status?.timestamp ?? "") || left.id.localeCompare(right.id));
  }

  async save(task, context = {}) {
    const prior = await this.load(task.id, context);
    if (prior && TERMINAL.has(prior.status?.state) && !TERMINAL.has(task.status?.state)) return;
    const envelope = { protocol: "A2A", protocolVersion: "1.0", tenant: context.tenant ?? "", task: Task.toJSON(task) };
    if (containsEphemeralBearer(envelope)) throw new Error("ephemeral bearer capability must not enter durable A2A task storage");
    await this.source.put(a2aTaskStateRecord(envelope));
  }

  /** Explicitly settle an interrupted task without deleting its trajectory. */
  async cancel(taskId, context = {}, reason = "Task cancellation requested by customer.") {
    const task = await this.load(taskId, context);
    if (!task) return undefined;
    if (TERMINAL.has(task.status?.state)) return task;
    const message = {
      messageId: randomUUID(), taskId, contextId: task.contextId, role: Role.ROLE_AGENT,
      parts: [{ content: { $case: "text", value: reason }, metadata: {}, filename: "", mediaType: "text/plain" }],
      metadata: { disposition: "cancelled" }, extensions: [], referenceTaskIds: [],
    };
    const canceled = {
      ...task,
      status: { state: TaskState.TASK_STATE_CANCELED, message, timestamp: new Date().toISOString() },
      history: [...(task.history ?? []), message],
    };
    await this.save(canceled, context);
    return canceled;
  }

  async load(taskId, context = {}) {
    return taskFromRecord(await this.source.get({ taskId, tenant: context.tenant ?? "" }), taskId, context);
  }

  async list(params, context = {}) {
    const records = await this.source.list({ tenant: context.tenant ?? "" });
    if (!Array.isArray(records)) throw new Error("network task source list must return an array");
    let tasks = records.map((record) => taskFromRecord(record, record?.taskId, context)).filter(Boolean);
    if (params.contextId) tasks = tasks.filter((task) => task.contextId === params.contextId);
    if (params.status) tasks = tasks.filter((task) => task.status?.state === params.status);
    if (params.statusTimestampAfter) {
      const after = new Date(params.statusTimestampAfter).getTime();
      tasks = tasks.filter((task) => new Date(task.status?.timestamp ?? 0).getTime() >= after);
    }
    tasks.sort((left, right) => (right.status?.timestamp ?? "").localeCompare(left.status?.timestamp ?? "") || right.id.localeCompare(left.id));
    const totalSize = tasks.length;
    if (params.pageToken) {
      const [timestamp, ...id] = Buffer.from(params.pageToken, "base64").toString("utf8").split("|");
      const cursor = tasks.findIndex((task) => (task.status?.timestamp ?? "") === timestamp && task.id === id.join("|"));
      tasks = cursor < 0 ? [] : tasks.slice(cursor + 1);
    }
    const pageSize = Math.max(1, Math.min(params.pageSize ?? 50, 100));
    const page = tasks.slice(0, pageSize), last = page.at(-1);
    return {
      tasks: page.map((task) => project(task, params.historyLength, params.includeArtifacts === true)),
      nextPageToken: last && tasks.length > page.length ? Buffer.from(`${last.status?.timestamp ?? ""}|${last.id}`).toString("base64") : "",
      pageSize,
      totalSize,
    };
  }
}
