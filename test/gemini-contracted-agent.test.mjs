import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Message, Role, TaskState } from "@a2a-js/sdk";
import { serveContractedAgent } from "../src/serve-contracted-agent.mjs";
import { a2aResultParts, sendRmnTask } from "@red-cup-engineering/a2a-rmn-task-client-service";
import { rmnPart } from "@red-cup-engineering/a2a-rmn-part-service";
import { ephemeralAgentCardSigning } from "@red-cup-engineering/a2a-agent-card-key-service/testing";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const TEAM = resolve(ROOT, "../../../../../model-services-section/services/logical-inference-services-section/services/gemini-inference-team");
const RMN = resolve(ROOT, "../../../../../model-services-section/services/relational-model-services-section/services/relational-model-notation-services-section/services/rmn-conformance-service");
const RWIL = resolve(RMN, "../rwil-rdf-projection-service");
const WIT = resolve(RMN, "../wit-transition-assay");
const { assay, semanticBytes, semanticId } = await import(`${RMN}/src/rmn-core.mjs`);
const { SOVEREIGN_CIRCUIT_INTERFACE_EXTENSION } = await import(`${RMN}/src/hierarchical-circuit.mjs`);
const { startRwilProviderProcess } = await import(`${RWIL}/src/test-provider.mjs`);
const { startWitTransitionAssayProcess } = await import(`${WIT}/src/test-provider.mjs`);
const ACCOUNT = JSON.parse(readFileSync(resolve(TEAM, "content/evm/accounts/eip155-31337.json"), "utf8")).account.caip10;
const CUSTOMER_ACCOUNT = "eip155:31337:0x1111111111111111111111111111111111111111";
const LAW = "ni:///sha-256;h2VIEZwYH__6vRnSgSWYRrFh1AHFcIBFboED8rlsGgo";
const OPERATION_TYPE = ["product", ["mark"], ["product", ["mark"], ["product", ["mark"], ["mark"]]]];
const ni = (label) => `ni:///sha-256;${createHash("sha256").update(label).digest("base64url")}`;

async function freePort() {
  const server = createServer(); await new Promise((accept) => server.listen(0, "127.0.0.1", accept));
  const port = server.address().port; await new Promise((accept) => server.close(accept)); return port;
}
function conform(term, expectedType) {
  const result = assay({ term, expectedType, fuel: 0 });
  return { term: semanticId(result.normalizedTerm), canonicalBytesBase64: semanticBytes(result.normalizedTerm).toString("base64") };
}

test("official A2A 1.0 provider executes the Gemini team's typed RMN dry-run contract", async () => {
  const teamData = mkdtempSync(join(tmpdir(), "a2a-gemini-rwil-"));
  const operation = ["pair", ["mark", "Answer briefly."], ["pair", ["mark", "What is two plus two?"], ["pair", ["mark", "gemini-3.1-flash-lite"], ["mark", "dry-run"]]]];
  const operationReceipt = conform(operation, OPERATION_TYPE);
  const cell = { law: LAW, caller: CUSTOMER_ACCOUNT, provider: ACCOUNT,
    precondition: ni("pre"), operation: operationReceipt.term, postcondition: ni("post"), refusal: ni("refusal"), evidenceRoot: ni("bottom"),
    outcome: { positiveEvidence: false, negativeEvidence: false }, measures: [], parent: null };
  const bundleReceipt = conform(["pair", ["effect", cell], operation], ["product", ["effect"], OPERATION_TYPE]);
  const rmnPort = await freePort(), port = await freePort(), rmnBase = `http://127.0.0.1:${rmnPort}`, baseUrl = `http://127.0.0.1:${port}`;
  const priorProvider = process.env.RMN_CONFORMANCE_AGENT, priorRwil = process.env.RWIL_RDF_AGENT, priorWit = process.env.WIT_TRANSITION_ASSAY_AGENT, priorTeam = process.env.GEMINI_RWIL_ROOT;
  const rwil = await startRwilProviderProcess();
  const wit = await startWitTransitionAssayProcess({ rwilAgentUrl: rwil.agentCardUrl });
  process.env.RMN_CONFORMANCE_AGENT = `${rmnBase}/.well-known/agent-card.json`; process.env.RWIL_RDF_AGENT = rwil.agentCardUrl; process.env.WIT_TRANSITION_ASSAY_AGENT = wit.agentCardUrl; process.env.GEMINI_RWIL_ROOT = teamData;
  const rmnRunning = await serveContractedAgent({ rmnPort, port: rmnPort, host: "127.0.0.1", baseUrl: rmnBase,
    agentCard: join(RMN, "content/agent-cards/rmn-semantic-conformance.json"), executor: process.execPath,
    executorArgs: [join(RMN, "bin/execute-a2a-task.mjs")],
    ...ephemeralAgentCardSigning(rmnBase, "gemini-test-rmn") });
  const running = await serveContractedAgent({ port, host: "127.0.0.1", baseUrl,
    agentCard: join(ROOT, "content/agent-cards/gemini-inference-team.json"), executor: process.execPath,
    executorArgs: [join(TEAM, "src/execute-rmn-inference.mjs")],
    ...ephemeralAgentCardSigning(baseUrl, "gemini-test-team") });
  try {
    const message = Message.toJSON({ messageId: crypto.randomUUID(), contextId: "", taskId: "", role: Role.ROLE_USER,
      parts: [rmnPart(Buffer.from(bundleReceipt.canonicalBytesBase64, "base64"), "proposal.rmn.cbor")], metadata: {}, extensions: [], referenceTaskIds: [] });
    const result = await sendRmnTask({ agentUrl: `${baseUrl}/.well-known/agent-card.json`, extensions: [SOVEREIGN_CIRCUIT_INTERFACE_EXTENSION], requireSignature: true, message, signal: AbortSignal.timeout(10_000) });
    assert.equal(result.result.status.state, TaskState.TASK_STATE_COMPLETED);
    assert.equal(result.result.status.message.metadata.disposition, "completion");
    assert.equal(a2aResultParts(result.result).find((part) => part.mediaType === "text/plain").content.value, "ready");
    assert.match(result.result.status.message.metadata.witnessNi, /^ni:\/\/\/sha-256;/u);
  } finally {
    await new Promise((accept) => running.server.close(accept));
    await new Promise((accept) => rmnRunning.server.close(accept));
    await wit.close();
    await rwil.close();
    if (priorProvider === undefined) delete process.env.RMN_CONFORMANCE_AGENT; else process.env.RMN_CONFORMANCE_AGENT = priorProvider;
    if (priorRwil === undefined) delete process.env.RWIL_RDF_AGENT; else process.env.RWIL_RDF_AGENT = priorRwil;
    if (priorWit === undefined) delete process.env.WIT_TRANSITION_ASSAY_AGENT; else process.env.WIT_TRANSITION_ASSAY_AGENT = priorWit;
    if (priorTeam === undefined) delete process.env.GEMINI_RWIL_ROOT; else process.env.GEMINI_RWIL_ROOT = priorTeam;
  }
});
