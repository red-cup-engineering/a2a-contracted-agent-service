import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { AgentCard, generateAgentCardSignature } from "@a2a-js/sdk";
import { importPKCS8 } from "jose";

function required(value, label) {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(`${label} is required`);
  return value.trim();
}

export async function loadSignedAgentCard({ origin, cardPath, signingKeyPath, jwksPath, kid, algorithm = process.env.AGENT_CARD_SIGNING_ALG ?? "EdDSA" }) {
  const baseUrl = required(origin, "Agent Card origin").replace(/\/$/u, "");
  const privateKeyPath = resolve(signingKeyPath ?? required(process.env.AGENT_CARD_SIGNING_KEY, "AGENT_CARD_SIGNING_KEY"));
  const publicJwksPath = resolve(jwksPath ?? required(process.env.AGENT_CARD_JWKS, "AGENT_CARD_JWKS"));
  const signingKid = kid ?? required(process.env.AGENT_CARD_SIGNING_KID, "AGENT_CARD_SIGNING_KID");
  const jwks = JSON.parse(await readFile(publicJwksPath, "utf8"));
  const matching = jwks?.keys?.filter((key) => key?.kid === signingKid && key?.alg === algorithm && !Object.hasOwn(key, "d")) ?? [];
  if (matching.length !== 1) throw new TypeError("Agent Card JWKS must expose exactly one matching public key");
  const template = await readFile(resolve(required(cardPath, "Agent Card template path")), "utf8");
  const card = AgentCard.toJSON(AgentCard.fromJSON(JSON.parse(template.replaceAll("${BASE_URL}", baseUrl))));
  const privateKey = await importPKCS8(await readFile(privateKeyPath, "utf8"), algorithm);
  const signed = await generateAgentCardSignature(privateKey, { alg: algorithm, kid: signingKid, typ: "JOSE", jku: `${baseUrl}/.well-known/jwks.json` })(card);
  return Object.freeze({ card: Object.freeze(signed), jwks: Object.freeze(jwks) });
}
