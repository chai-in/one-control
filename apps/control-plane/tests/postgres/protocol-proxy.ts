import { once } from "node:events";
import { createConnection, createServer, type Socket } from "node:net";
import { loadPostgresCustody } from "../postgres-fixture.js";

type Fault = "passthrough" | "lose-committed-ack" | "drop-commit";
export async function openProtocolProxy(mode: Fault) {
  const custody = await loadPostgresCustody();
  const sockets = new Set<Socket>();
  const observations = {
    mode,
    frontendFrames: 0,
    backendFrames: 0,
    frontendTypes: {} as Record<string, number>,
    backendTypes: {} as Record<string, number>,
    commitForwarded: 0,
    commitCommandObserved: 0,
    idleObservedAfterCommit: 0,
    withheldBytes: 0,
    activeSockets: 0,
    closed: false,
  };
  let faultUsed = false;
  const server = createServer((downstream) => {
    const upstream = createConnection({ host: "127.0.0.1", port: custody.port });
    for (const socket of [downstream, upstream]) {
      sockets.add(socket);
      observations.activeSockets = sockets.size;
      socket.on("close", () => {
        sockets.delete(socket);
        observations.activeSockets = sockets.size;
      });
      socket.on("error", () => {
        downstream.destroy();
        upstream.destroy();
      });
    }
    downstream.on("close", () => upstream.destroy());
    upstream.on("close", () => downstream.destroy());
    const deadline = setTimeout(() => {
      downstream.destroy();
      upstream.destroy();
    }, 20_000);
    downstream.on("close", () => clearTimeout(deadline));
    let startup = true;
    let withholding = false;
    let committed = false;
    function parse(socket: Socket, frontend: boolean) {
      let pending = Buffer.alloc(0);
      socket.on("data", (bytes: Buffer) => {
        if (pending.length + bytes.length > 1_048_576) {
          downstream.destroy();
          upstream.destroy();
          return;
        }
        pending = Buffer.concat([pending, bytes]);
        while (pending.length >= (frontend && startup ? 4 : 5)) {
          const initial = frontend && startup;
          const size = initial ? pending.readInt32BE(0) : pending.readInt32BE(1) + 1;
          if (size < (initial ? 8 : 5) || size > 1_048_576) {
            downstream.destroy();
            upstream.destroy();
            return;
          }
          if (pending.length < size) return;
          const frame = pending.subarray(0, size);
          pending = pending.subarray(size);
          const type = initial ? "startup" : String.fromCharCode(frame.readUInt8(0));
          if (frontend) {
            startup = false;
            observations.frontendFrames++;
            observations.frontendTypes[type] = (observations.frontendTypes[type] ?? 0) + 1;
            const commit = type === "Q" && frame.subarray(5).equals(Buffer.from("COMMIT\0"));
            if (commit && mode !== "passthrough" && !faultUsed) {
              faultUsed = true;
              if (mode === "drop-commit") {
                downstream.destroy();
                upstream.destroy();
                return;
              }
              withholding = true;
            }
            if (commit) observations.commitForwarded++;
            upstream.write(frame);
          } else {
            observations.backendFrames++;
            observations.backendTypes[type] = (observations.backendTypes[type] ?? 0) + 1;
            if (withholding) {
              observations.withheldBytes += frame.length;
              if (type === "C" && frame.subarray(5).equals(Buffer.from("COMMIT\0"))) {
                observations.commitCommandObserved++;
                committed = true;
              }
              if (type === "Z" && frame[5] === 73 && committed) {
                observations.idleObservedAfterCommit++;
                downstream.destroy();
                upstream.destroy();
                return;
              }
            } else downstream.write(frame);
          }
        }
      });
    }
    parse(downstream, true);
    parse(upstream, false);
  });
  server.maxConnections = 4;
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Proxy loopback binding failed");
  return {
    endpoint: { host: "127.0.0.1" as const, port: address.port, upstreamPort: custody.port },
    observations,
    disconnect() {
      for (const socket of sockets) socket.destroy();
    },
    async close() {
      const closed = new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      const socketCloses = [...sockets].map(
        (socket) =>
          new Promise<void>((resolve) => {
            socket.once("close", resolve);
            socket.destroy();
          }),
      );
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          Promise.all([closed, ...socketCloses]),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error("Proxy close deadline expired")), 5000);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      observations.closed = !server.listening && sockets.size === 0;
      if (!observations.closed) throw new Error("Proxy sockets did not close");
    },
  };
}
