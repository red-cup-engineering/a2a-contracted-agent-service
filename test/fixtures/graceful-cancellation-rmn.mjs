import { writeFileSync } from "node:fs";

writeFileSync(process.env.A2A_TEST_CANCELLATION_STARTED_FILE, "downstream-started\n", "utf8");
process.on("SIGTERM", () => {
  writeFileSync(process.env.A2A_TEST_CANCELLATION_ACK_FILE, "downstream-cancellation-acknowledged\n", "utf8");
  process.exit(0);
});
const remainRunning = () => setImmediate(remainRunning);
remainRunning();
