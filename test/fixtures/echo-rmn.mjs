let source = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { source += chunk; });
process.stdin.on("end", () => {
  const message = JSON.parse(source);
  process.stdout.write(`${JSON.stringify({
    messageId: "00000000-0000-4000-8000-000000000001",
    role: "ROLE_AGENT",
    parts: message.parts,
    metadata: { executor: "echo-rmn" }
  })}\n`);
});
