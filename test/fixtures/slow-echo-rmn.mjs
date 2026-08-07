let source = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { source += chunk; });
process.stdin.on("end", () => {
  const message = JSON.parse(source);
  setImmediate(() => {
    process.stdout.write(`${JSON.stringify({
      messageId: "00000000-0000-4000-8000-000000000011",
      role: "ROLE_AGENT",
      parts: message.parts,
      metadata: { executor: "slow-echo-rmn" },
    })}\n`);
  });
});
