/**
 * quic-link relay — Cloudflare Workers + Durable Objects implementation.
 *
 * One Durable Object instance per service id. Each DO holds the WebSocket
 * connections of registered servers and brokers the tunnel request/response
 * handshake between clients and servers.
 *
 * Only the signalling traffic (HTTP + WebSocket) touches Cloudflare; the
 * QUIC data plane stays direct between client and server.
 */

const TYPE_SERVICE_REQUEST = 0;
const TYPE_TUNNEL_READY = 1;
const TYPE_TUNNEL_REQUEST = 2;
const TYPE_START_TUNNEL = 3;

export class RelayDO {
  constructor(state, env) {
    this.ctx = state;
    this.env = env;
    this.pending = new Map();
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (request.headers.get("Upgrade") === "websocket") {
      return this.handleServerUpgrade();
    }

    if (url.pathname === "/client") {
      return this.handleClient(request);
    }

    return new Response("not found", { status: 404 });
  }

  handleServerUpgrade() {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    const text = typeof message === "string" ? message : new TextDecoder().decode(message);
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }

    if (msg.type === TYPE_SERVICE_REQUEST) {
      const fingerprint = msg.value?.server_fingerprint ?? "";
      ws.serializeAttachment({ fingerprint, busy: false });
    } else if (msg.type === TYPE_TUNNEL_READY) {
      const address = msg.value?.address ?? "";
      const addresses = msg.value?.addresses ?? [];
      const p = this.pending.get(ws);
      if (p) {
        this.pending.delete(ws);
        p.resolve({ address, addresses });
      }
    }
  }

  webSocketClose(ws) {
    const p = this.pending.get(ws);
    if (p) {
      this.pending.delete(ws);
      p.reject(new Error("server disconnected"));
    }
  }

  webSocketError(ws) {
    this.webSocketClose(ws);
  }

  async handleClient(request) {
    let msg;
    try {
      msg = await request.json();
    } catch {
      return new Response("bad request", { status: 400 });
    }

    if (msg.type !== TYPE_TUNNEL_REQUEST) {
      return new Response("invalid message type", { status: 400 });
    }

    const id = msg.value?.id ?? "";
    const clientAddress = msg.value?.client_address ?? "";
    const clientAddresses = msg.value?.client_addresses ?? [];
    const clientFingerprint = msg.value?.client_fingerprint ?? "";

    if (!id || (!clientAddress && (!Array.isArray(clientAddresses) || clientAddresses.length === 0))) {
      return new Response("missing id or client_address", { status: 400 });
    }

    const sockets = this.ctx.getWebSockets();
    let chosen = null;
    let chosenFingerprint = "";
    for (const ws of sockets) {
      const att = ws.deserializeAttachment();
      if (att && !att.busy) {
        att.busy = true;
        ws.serializeAttachment(att);
        chosen = ws;
        chosenFingerprint = att.fingerprint;
        break;
      }
    }

    if (!chosen) {
      return new Response("no available service", { status: 404 });
    }

    const ws = chosen;
    try {
      ws.send(
        JSON.stringify({
          type: TYPE_START_TUNNEL,
          value: {
            peer_address: clientAddress,
            ...(Array.isArray(clientAddresses) && clientAddresses.length > 0
              ? { peer_addresses: clientAddresses }
              : {}),
            ...(clientFingerprint ? { peer_fingerprint: clientFingerprint } : {}),
          },
        }),
      );

      const ready = await this.waitForReady(ws, 30_000);

      return new Response(
        JSON.stringify({
          type: TYPE_START_TUNNEL,
          value: {
            peer_address: ready.address,
            ...(Array.isArray(ready.addresses) && ready.addresses.length > 0
              ? { peer_addresses: ready.addresses }
              : {}),
            ...(chosenFingerprint ? { peer_fingerprint: chosenFingerprint } : {}),
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    } catch {
      return new Response("server unavailable", { status: 503 });
    } finally {
      this.pending.delete(ws);
      const att = ws.deserializeAttachment();
      if (att) {
        att.busy = false;
        ws.serializeAttachment(att);
      }
    }
  }

  waitForReady(ws, timeoutMs) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(ws);
        reject(new Error("timeout waiting for server"));
      }, timeoutMs);
      this.pending.set(ws, {
        resolve: (addr) => {
          clearTimeout(timer);
          resolve(addr);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });
    });
  }
}

function authorize(request, expected) {
  const header = request.headers.get("Authorization") ?? "";
  if (header !== "" && !header.startsWith("Token ")) {
    return false;
  }
  const token = header.startsWith("Token ") ? header.slice("Token ".length) : "";
  return constantTimeEqual(token, expected);
}

function constantTimeEqual(a, b) {
  const ab = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!authorize(request, env.AUTH_TOKEN ?? "")) {
      return new Response("unauthorized", { status: 401 });
    }

    if (url.pathname === "/client") {
      const bodyText = await request.text();
      let parsed;
      try {
        parsed = JSON.parse(bodyText);
      } catch {
        return new Response("bad request", { status: 400 });
      }
      const id = parsed?.value?.id ?? "";
      if (!id) {
        return new Response("missing id", { status: 400 });
      }
      const stub = env.RELAY.get(env.RELAY.idFromName(id));
      return stub.fetch(
        new Request(request.url, {
          method: request.method,
          headers: request.headers,
          body: bodyText,
        }),
      );
    }

    if (url.pathname.startsWith("/server/")) {
      const id = decodeURIComponent(url.pathname.slice("/server/".length));
      if (!id) {
        return new Response("bad request", { status: 400 });
      }
      const stub = env.RELAY.get(env.RELAY.idFromName(id));
      return stub.fetch(request);
    }

    return new Response("not found", { status: 404 });
  },
};
