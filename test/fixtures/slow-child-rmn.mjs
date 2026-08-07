import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";

const grandchild = spawn(process.execPath, ["-e", "const keepAlive=()=>setImmediate(keepAlive);keepAlive()"], { stdio: "ignore" });
writeFileSync(process.env.A2A_TEST_CHILD_PID_FILE, `${grandchild.pid}\n`, "utf8");
const remainRunning = () => setImmediate(remainRunning);
remainRunning();
