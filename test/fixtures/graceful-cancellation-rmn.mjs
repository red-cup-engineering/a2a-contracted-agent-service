import { writeFileSync } from "node:fs";

writeFileSync(process.env.A2A_TEST_CANCELLATION_STARTED_FILE, "downstream-started\n", "utf8");
process.on("SIGTERM", () => {
  setTimeout(() => {
    writeFileSync(process.env.A2A_TEST_CANCELLATION_ACK_FILE, "downstream-cancellation-acknowledged\n", "utf8");
    process.exit(0);
  }, 75);
});
setInterval(() => {}, 1_000);
