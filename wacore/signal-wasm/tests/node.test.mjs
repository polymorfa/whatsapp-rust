// End-to-end check of the wasm32 bindings from JavaScript.
//
// Build first, from the repository root:
//   RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build -p wacore-signal-wasm \
//     --lib --release --target wasm32-unknown-unknown
//   wasm-bindgen --target nodejs --out-dir target/signal-wasm-node \
//     target/wasm32-unknown-unknown/release/wacore_signal_wasm.wasm
// Then: node --test wacore/signal-wasm/tests/node.test.mjs
//
// The backend below is an in-memory reference for the RecordBackend contract;
// the sealer is WebCrypto AES-GCM with a non-extractable key, as in a browser.

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const pkg =
  process.env.SIGNAL_WASM_PKG ??
  fileURLToPath(
    new URL("../../../target/signal-wasm-node/wacore_signal_wasm.js", import.meta.url),
  );
const { SignalDevice } = require(pkg);

const TTL = 60_000;

class MemoryBackend {
  records = new Map();
  leases = new Map();

  #slot(scope, ns, key) {
    return `${scope}\u0000${ns}\u0000${key}`;
  }

  async get(scope, ns, key) {
    return this.records.get(this.#slot(scope, ns, key)) ?? null;
  }

  async scanKeys(scope, ns, prefix, limit) {
    const head = `${scope}\u0000${ns}\u0000`;
    const keys = [...this.records.keys()]
      .filter((slot) => slot.startsWith(head + prefix))
      .map((slot) => slot.slice(head.length))
      .sort();
    return limit === undefined ? keys : keys.slice(0, limit);
  }

  async write(fence, ops) {
    if (this.leases.get(fence.scope)?.generation !== fence.generation) {
      throw Object.assign(new Error("fence lost"), { code: "fence_lost" });
    }
    for (const op of ops) {
      if (op.op === "insert" && this.records.has(this.#slot(fence.scope, op.ns, op.key))) {
        throw Object.assign(new Error("record exists"), { code: "record_exists" });
      }
    }
    for (const op of ops) {
      const slot = this.#slot(fence.scope, op.ns, op.key);
      if (op.op === "put" || op.op === "insert") this.records.set(slot, op.value.slice());
      else if (op.op === "update") {
        if (this.records.has(slot)) this.records.set(slot, op.value.slice());
      } else this.records.delete(slot);
    }
  }

  async acquire(scope, holder, nowMs, ttlMs) {
    const row = this.leases.get(scope);
    let generation;
    if (!row) generation = 1;
    else if (row.holder === holder) generation = row.generation;
    else if (row.expiresAtMs > nowMs) return null;
    else generation = row.generation + 1;
    const lease = { scope, generation, holder, expiresAtMs: nowMs + ttlMs };
    this.leases.set(scope, lease);
    return { ...lease };
  }

  async renew(lease, nowMs, ttlMs) {
    const row = this.leases.get(lease.scope);
    if (!row || row.generation !== lease.generation || row.holder !== lease.holder) return null;
    row.expiresAtMs = nowMs + ttlMs;
    return { ...row };
  }

  async release(lease) {
    const row = this.leases.get(lease.scope);
    if (row && row.generation === lease.generation && row.holder === lease.holder) {
      row.expiresAtMs = 0;
      row.holder = "";
    }
  }

  containsBytes(needle) {
    const hex = Buffer.from(needle).toString("hex");
    return [...this.records.values()].some((v) => Buffer.from(v).toString("hex").includes(hex));
  }
}

async function webCryptoSealer() {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  return {
    async seal(aad, plaintext) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const sealed = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, plaintext),
      );
      const out = new Uint8Array(12 + sealed.length);
      out.set(iv);
      out.set(sealed, 12);
      return out;
    },
    async open(aad, sealed) {
      return new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: sealed.subarray(0, 12), additionalData: aad },
          key,
          sealed.subarray(12),
        ),
      );
    },
  };
}

async function device(scope, { backend, sealer, holder = "tab-a", now = 0 } = {}) {
  backend ??= new MemoryBackend();
  sealer ??= await webCryptoSealer();
  const signal = await SignalDevice.open(backend, sealer, scope, holder, now, TTL, true);
  return { signal, backend, sealer };
}

async function bundleFor(signal, withPrekey = true) {
  const identity = await signal.publicIdentity();
  const bundle = {
    registrationId: identity.registrationId,
    deviceId: 1,
    identityKey: identity.identityKey,
    signedPrekeyId: identity.signedPrekey.id,
    signedPrekey: identity.signedPrekey.publicKey,
    signedPrekeySignature: identity.signedPrekey.signature,
  };
  if (withPrekey) {
    const [prekey] = await signal.generatePrekeys(1);
    bundle.prekeyId = prekey.id;
    bundle.prekey = prekey.publicKey;
  }
  return bundle;
}

const ALICE = "111@s.whatsapp.net";
const BOB = "222@s.whatsapp.net";
const text = (s) => new TextEncoder().encode(s);
const read = (b) => new TextDecoder().decode(b);

test("a session runs both ways and nothing readable reaches storage", async () => {
  const alice = await device("alice");
  const bob = await device("bob");
  await alice.signal.establishSession(BOB, 1, await bundleFor(bob.signal));

  const first = await alice.signal.encrypt(BOB, 1, text("hello bob"));
  assert.equal(first.kind, "pkmsg");
  const opened = await bob.signal.decrypt(ALICE, 1, first.kind, first.ciphertext);
  assert.equal(read(opened.plaintext), "hello bob");

  const reply = await bob.signal.encrypt(ALICE, 1, text("hi alice"));
  assert.equal(reply.kind, "msg");
  assert.equal(read((await alice.signal.decrypt(BOB, 1, reply.kind, reply.ciphertext)).plaintext), "hi alice");

  for (let round = 0; round < 5; round++) {
    const out = await alice.signal.encrypt(BOB, 1, text(`a${round}`));
    assert.equal(read((await bob.signal.decrypt(ALICE, 1, out.kind, out.ciphertext)).plaintext), `a${round}`);
  }

  assert.equal(bob.backend.containsBytes(text("hello bob")), false);
  const identity = await bob.signal.publicIdentity();
  assert.equal(bob.backend.containsBytes(identity.advSecret), false);
});

test("a second tab is refused while the lease is live, then fences the first out", async () => {
  const alice = await device("alice-failover");
  const backend = new MemoryBackend();
  const sealer = await webCryptoSealer();
  const bobA = await device("bob-failover", { backend, sealer, holder: "tab-a", now: 0 });
  await alice.signal.establishSession(BOB, 1, await bundleFor(bobA.signal));
  const first = await alice.signal.encrypt(BOB, 1, text("before"));
  await bobA.signal.decrypt(ALICE, 1, first.kind, first.ciphertext);

  await assert.rejects(
    SignalDevice.open(backend, sealer, "bob-failover", "tab-b", 1, TTL, false),
    (error) => error.code === "lease_held",
  );

  const bobB = await SignalDevice.open(backend, sealer, "bob-failover", "tab-b", TTL + 1, TTL, false);
  const next = await alice.signal.encrypt(BOB, 1, text("after"));
  await assert.rejects(
    bobA.signal.decrypt(ALICE, 1, next.kind, next.ciphertext),
    (error) => error.code === "fence_lost",
  );
  assert.equal(await bobA.signal.renewLease(TTL + 2, TTL), false);
  assert.equal(read((await bobB.decrypt(ALICE, 1, next.kind, next.ciphertext)).plaintext), "after");
});

test("group messages decrypt with a distributed sender key", async () => {
  const alice = await device("alice-group");
  const bob = await device("bob-group");
  const group = "120363000000001@g.us";
  await alice.signal.establishSession(BOB, 1, await bundleFor(bob.signal));

  const skdm = await alice.signal.senderKeyDistribution(group, ALICE, 1);
  const carried = await alice.signal.encrypt(BOB, 1, skdm);
  const received = await bob.signal.decrypt(ALICE, 1, carried.kind, carried.ciphertext);
  await bob.signal.processSenderKeyDistribution(group, ALICE, 1, received.plaintext);

  const skmsg = await alice.signal.groupEncrypt(group, ALICE, 1, text("hello group"));
  assert.equal(read(await bob.signal.groupDecrypt(group, ALICE, 1, skmsg)), "hello group");
});

test("a sealer with the wrong key cannot open the device, and the lease is released", async () => {
  const backend = new MemoryBackend();
  const first = await device("bob-key", { backend });
  await first.signal.release();
  await assert.rejects(
    SignalDevice.open(backend, await webCryptoSealer(), "bob-key", "tab-b", 1, TTL, false),
    (error) => error.code === "store",
  );
  // The failed open gave its lease back, so another tab can take the scope.
  await SignalDevice.open(backend, first.sealer, "bob-key", "tab-c", 2, TTL, false);
});

test("pairing and input errors carry codes", async () => {
  const bob = await device("bob-errors");
  await assert.rejects(
    bob.signal.signPairing(text("not a container")),
    (error) => error.code === "pairing_refused" && typeof error.status === "number",
  );
  await assert.rejects(
    bob.signal.decrypt(ALICE, 1, "skmsg", new Uint8Array(4)),
    (error) => error.code === "invalid_input",
  );
  await assert.rejects(
    bob.signal.establishSession(ALICE, 1, { registrationId: 1 }),
    (error) => error.code === "invalid_input",
  );
});

// A `waE2E.Message` with only `conversation` (field 1), padded as WhatsApp
// pads (n bytes of value n, 1..=16).
function paddedConversation(body) {
  const utf8 = text(body);
  const pad = 1 + (utf8.length % 16);
  const out = new Uint8Array(2 + utf8.length + pad);
  out[0] = 0x0a;
  out[1] = utf8.length;
  out.set(utf8, 2);
  out.fill(pad, 2 + utf8.length);
  return out;
}

function conversationOf(message) {
  assert.equal(message[0], 0x0a);
  return read(message.subarray(2, 2 + message[1]));
}

test("receive buffers until delivered and recognises redelivery after", async () => {
  const alice = await device("alice-receive");
  const bob = await device("bob-receive");
  await alice.signal.establishSession(BOB, 1, await bundleFor(bob.signal));
  const sent = await alice.signal.encrypt(BOB, 1, paddedConversation("hello from js"));
  const args = [ALICE, ALICE, 1, sent.kind, sent.ciphertext, 2, false];

  const first = await bob.signal.receive(...args);
  assert.equal(first.status, "message");
  assert.equal(first.redelivered, false);
  assert.equal(conversationOf(first.message), "hello from js");

  const again = await bob.signal.receive(...args);
  assert.equal(again.redelivered, true);
  assert.equal(again.receiptKey, first.receiptKey);

  await bob.signal.markDelivered(first.receiptKey);
  const after = await bob.signal.receive(...args);
  assert.equal(after.status, "already_delivered");
  assert.equal(bob.backend.containsBytes(text("hello from js")), false);
});

function conversation(body) {
  const utf8 = text(body);
  return Uint8Array.from([0x0a, utf8.length, ...utf8]);
}

test("sends are built in the page and only ask the resolver for devices and keys", async () => {
  const alice = await device("alice-send-js");
  const bob = await device("bob-send-js");
  await alice.signal.setOwnJids("111:1@s.whatsapp.net", "900111:1@lid");
  const bobDevice = "222:1@s.whatsapp.net";
  const bobBundle = await bundleFor(bob.signal);
  const calls = { devices: [], prekeys: [] };
  const resolver = {
    async resolveDevices(jids) {
      calls.devices.push(jids);
      return [bobDevice];
    },
    async fetchPrekeys(jids) {
      calls.prekeys.push(jids);
      return Object.fromEntries(jids.filter((j) => j === bobDevice).map((j) => [j, bobBundle]));
    },
    async resolveGroup() {
      return {
        participants: ["111@s.whatsapp.net", "222@s.whatsapp.net"],
        addressingMode: "pn",
      };
    },
  };

  const first = await alice.signal.sendDirect(resolver, "222@s.whatsapp.net", conversation("hi"), "J1");
  assert.ok(first.stanza instanceof Uint8Array && first.stanza.length > 0);
  assert.deepEqual(first.unreachedDevices, []);
  assert.deepEqual(calls.devices[0].sort(), ["111@s.whatsapp.net", "222@s.whatsapp.net"]);
  assert.deepEqual(calls.prekeys, [[bobDevice]]);

  await alice.signal.sendDirect(resolver, "222@s.whatsapp.net", conversation("again"), "J2");
  assert.equal(calls.prekeys.length, 1, "an established session needs no new bundle");
  assert.equal(alice.backend.containsBytes(text("again")), false);

  const group = await alice.signal.sendGroup(resolver, "120363000000001@g.us", conversation("g"), "G1");
  assert.ok(group.stanza.length > 0);
  assert.deepEqual(group.distributionTargets, [bobDevice]);

  const unpaired = await device("unpaired-js");
  await assert.rejects(
    unpaired.signal.sendDirect(resolver, "222@s.whatsapp.net", conversation("x"), "J3"),
    (error) => error.code === "invalid_input",
  );
});
