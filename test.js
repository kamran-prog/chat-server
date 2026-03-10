"use strict";

const http = require("http");
const { io: ioClient } = require("socket.io-client");
const jwt = require("jsonwebtoken");

const {
  ChatServer,
  generateId,
  extractTimestamp,
  EncryptionService,
  MemoryCacheAdapter,
  MemoryPersistenceAdapter,
  MemoryQueueAdapter,
  Logger,
  EVENTS,
  GROUP_ROLES,
} = require("./src/index.js");

const { validate } = require("./src/middleware/validation");
const { ValidationError } = require("./src/utils/errors");
const { buildConfig, deepMerge } = require("./src/config/defaults");

const PORT = 5199;
const URL = `http://localhost:${PORT}`;
const JWT_SECRET = "test-secret-key-for-testing-only";

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    console.error(`  ✗ ${label}`);
  }
}

function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function connectClient(opts = {}) {
  return new Promise((resolve) => {
    const client = ioClient(URL, {
      transports: ["websocket"],
      autoConnect: true,
      ...opts,
    });
    client.on("connect", () => resolve(client));
    client.on("connect_error", (err) => {
      console.error("    connect_error:", err.message);
      resolve(client);
    });
  });
}

// ─── Unit Tests ───────────────────────────────────────────────────

async function testUUID() {
  console.log("\n── UUID v7 ──");
  const id1 = generateId();
  const id2 = generateId();
  assert(typeof id1 === "string" && id1.length === 36, "generates valid UUID string");
  assert(id1 < id2 || id1 === id2, "IDs are time-ordered (lexicographic)");

  const ts = extractTimestamp(id1);
  assert(ts instanceof Date, "extractTimestamp returns a Date");
  assert(Math.abs(ts.getTime() - Date.now()) < 5000, "extracted timestamp is close to now");
}

async function testEncryption() {
  console.log("\n── Encryption ──");
  const enc = new EncryptionService({ secret: "my-test-secret" });

  const plain = "Hello, encrypted world!";
  const encrypted = enc.encrypt(plain);
  assert(encrypted.encrypted && encrypted.iv && encrypted.authTag, "encrypt returns {encrypted, iv, authTag}");
  assert(encrypted.encrypted !== plain, "ciphertext differs from plaintext");

  const decrypted = enc.decrypt(encrypted);
  assert(decrypted === plain, "decrypt roundtrip matches original");

  const obj = { foo: "bar", n: 42 };
  const encObj = enc.encryptObject(obj);
  const decObj = enc.decryptObject(encObj);
  assert(decObj.foo === "bar" && decObj.n === 42, "encryptObject/decryptObject roundtrip");

  let threw = false;
  try {
    enc.decrypt({ encrypted: "bad", iv: "0".repeat(32), authTag: "0".repeat(32) });
  } catch {
    threw = true;
  }
  assert(threw, "decrypt throws on tampered data");
}

async function testCacheAdapter() {
  console.log("\n── MemoryCacheAdapter ──");
  const cache = new MemoryCacheAdapter();

  await cache.set("k1", "v1");
  assert((await cache.get("k1")) === "v1", "set/get basic");
  assert((await cache.has("k1")) === true, "has returns true for existing key");
  assert((await cache.has("missing")) === false, "has returns false for missing key");

  await cache.del("k1");
  assert((await cache.get("k1")) === undefined, "del removes key");

  await cache.set("ttl-key", "val", 1);
  assert((await cache.get("ttl-key")) === "val", "TTL key accessible before expiry");
  await wait(1200);
  assert((await cache.get("ttl-key")) === undefined, "TTL key expired after 1s");

  await cache.set("a:1", 1);
  await cache.set("a:2", 2);
  await cache.set("b:1", 3);
  const keys = await cache.keys("a:*");
  assert(keys.length === 2, "keys(pattern) filters correctly");

  await cache.clear();
  assert((await cache.keys()).length === 0, "clear empties the store");
}

async function testPersistenceAdapter() {
  console.log("\n── MemoryPersistenceAdapter ──");
  const db = new MemoryPersistenceAdapter();

  await db.saveMessage({ id: "m1", channelId: "ch1", content: "hello" });
  await db.saveMessage({ id: "m2", channelId: "ch1", content: "world" });
  await db.saveMessage({ id: "m3", channelId: "ch2", content: "other" });

  const msgs = await db.getMessages("ch1");
  assert(msgs.length === 2, "getMessages returns channel messages");
  assert(msgs[0].content === "hello", "messages in order");

  const limited = await db.getMessages("ch1", { limit: 1 });
  assert(limited.length === 1, "getMessages respects limit");

  const group = { id: "g1", name: "Test", ownerId: "u1", members: [{ userId: "u1", role: "owner" }] };
  await db.saveGroup(group);
  const fetched = await db.getGroup("g1");
  assert(fetched && fetched.name === "Test", "saveGroup/getGroup");

  await db.addGroupMember("g1", { userId: "u2", role: "member" });
  const updated = await db.getGroup("g1");
  assert(updated.members.length === 2, "addGroupMember adds member");

  await db.removeGroupMember("g1", "u2");
  const after = await db.getGroup("g1");
  assert(after.members.length === 1, "removeGroupMember removes member");

  const groups = await db.getGroupsByUser("u1");
  assert(groups.length === 1 && groups[0].id === "g1", "getGroupsByUser");

  assert((await db.getGroup("nonexistent")) === null, "getGroup returns null for missing");
  await db.close();
}

async function testQueueAdapter() {
  console.log("\n── MemoryQueueAdapter ──");
  const queue = new MemoryQueueAdapter();

  let received = null;
  await queue.subscribe("test-ch", (msg) => {
    received = msg;
  });

  await queue.publish("test-ch", { data: 42 });
  assert(received && received.data === 42, "publish/subscribe delivers message");

  await queue.unsubscribe("test-ch");
  received = null;
  await queue.publish("test-ch", { data: 99 });
  assert(received === null, "unsubscribe stops delivery");

  await queue.close();
}

async function testValidation() {
  console.log("\n── Validation ──");
  const schema = {
    name: { type: "string", required: true, maxLength: 10 },
    age: { type: "number", required: false, min: 0, max: 150 },
  };

  let err;
  try { validate({ name: "Alice" }, schema); } catch { err = true; }
  assert(!err, "valid data passes");

  try { validate({}, schema); err = false; } catch (e) { err = e instanceof ValidationError; }
  assert(err, "missing required field throws ValidationError");

  try { validate({ name: "TooLongNameXXX" }, schema); err = false; } catch (e) { err = e instanceof ValidationError; }
  assert(err, "maxLength violation throws");

  try { validate({ name: "A", age: -1 }, schema); err = false; } catch (e) { err = e instanceof ValidationError; }
  assert(err, "min violation throws");

  try { validate(null, schema); err = false; } catch (e) { err = e instanceof ValidationError; }
  assert(err, "null payload throws");
}

async function testConfig() {
  console.log("\n── Config ──");
  const config = buildConfig({ port: 9999, logging: { level: "debug" } });
  assert(config.port === 9999, "user port overrides default");
  assert(config.logging.level === "debug", "nested override works");
  assert(config.rateLimit.windowMs === 1000, "unmodified defaults preserved");

  let threw = false;
  try { buildConfig({ auth: { enabled: true } }); } catch { threw = true; }
  assert(threw, "throws when auth enabled without secret or hook");

  threw = false;
  try { buildConfig({ encryption: { enabled: true } }); } catch { threw = true; }
  assert(threw, "throws when encryption enabled without secret");

  const merged = deepMerge({ a: { b: 1, c: 2 } }, { a: { b: 10 } });
  assert(merged.a.b === 10 && merged.a.c === 2, "deepMerge merges nested objects");
}

async function testLogger() {
  console.log("\n── Logger ──");
  const entries = [];
  const logger = new Logger({ level: "debug", transport: (e) => entries.push(e) });

  logger.debug("d");
  logger.info("i");
  logger.warn("w");
  logger.error("e");
  assert(entries.length === 4, "all levels logged at debug level");
  assert(entries[0].level === "debug" && entries[3].level === "error", "correct level tags");

  const silent = new Logger({ level: "warn", transport: (e) => entries.push(e) });
  const before = entries.length;
  silent.debug("skip");
  silent.info("skip");
  silent.warn("pass");
  assert(entries.length === before + 1, "level filtering works");
}

// ─── Integration Tests ───────────────────────────────────────────

async function testServerIntegration() {
  console.log("\n── Server Integration ──");

  const server = new ChatServer({
    port: PORT,
    cors: { origin: ["http://localhost"] },
    auth: { enabled: true, jwtSecret: JWT_SECRET },
    encryption: { enabled: true, secret: "integration-test-secret-key-32ch" },
    rateLimit: { enabled: true, windowMs: 1000, maxEvents: 100 },
    logging: { level: "silent" },
  });

  await server.start();

  // Health check
  const health = await httpGet(`${URL}/health`);
  const hj = JSON.parse(health);
  assert(hj.status === "ok", "GET /health returns ok");

  // Root endpoint
  const root = await httpGet(`${URL}/`);
  const rj = JSON.parse(root);
  assert(rj.name === "chat-server", "GET / returns server info");

  // Auth rejection (no token)
  const noAuth = ioClient(URL, { transports: ["websocket"], autoConnect: true });
  const authErr = await new Promise((resolve) => {
    noAuth.on("connect_error", (err) => { noAuth.close(); resolve(err); });
    noAuth.on("connect", () => { noAuth.close(); resolve(null); });
  });
  assert(authErr !== null, "connection rejected without token");

  // Auth success (with JWT)
  const token1 = jwt.sign({ id: "user-A", sub: "user-A" }, JWT_SECRET);
  const token2 = jwt.sign({ id: "user-B", sub: "user-B" }, JWT_SECRET);
  const token3 = jwt.sign({ id: "user-C", sub: "user-C" }, JWT_SECRET);

  const clientA = await connectClient({ auth: { token: token1 } });
  const clientB = await connectClient({ auth: { token: token2 } });
  assert(clientA.connected, "client A connected with JWT");
  assert(clientB.connected, "client B connected with JWT");

  // ── Direct Messages ──
  console.log("\n── Direct Messaging ──");

  const dmReceived = new Promise((resolve) => {
    clientB.on(EVENTS.DM_RECEIVED, (data) => resolve(data));
  });

  clientA.emit(EVENTS.DM_SEND, { to: "user-B", content: "Hello B!" });

  const dm = await Promise.race([dmReceived, wait(3000).then(() => null)]);
  assert(dm !== null, "DM delivered to recipient");
  assert(dm && dm.from === "user-A", "DM has correct sender");
  assert(dm && dm.content === "Hello B!", "DM content matches");
  assert(dm && dm.id && dm.id.length === 36, "DM has UUID v7 id");

  // Typing indicator
  const typingReceived = new Promise((resolve) => {
    clientB.on(EVENTS.DM_TYPING, (data) => resolve(data));
  });
  clientA.emit(EVENTS.DM_TYPING, { to: "user-B" });
  const typing = await Promise.race([typingReceived, wait(2000).then(() => null)]);
  assert(typing && typing.from === "user-A", "typing indicator delivered");

  // Read receipt
  const readReceived = new Promise((resolve) => {
    clientB.on(EVENTS.DM_READ, (data) => resolve(data));
  });
  clientA.emit(EVENTS.DM_READ, { to: "user-B", messageId: dm?.id || "test" });
  const readR = await Promise.race([readReceived, wait(2000).then(() => null)]);
  assert(readR && readR.from === "user-A", "read receipt delivered");

  // ── Ephemeral Rooms ──
  console.log("\n── Ephemeral Rooms ──");

  const roomJoinMsg = new Promise((resolve) => {
    clientA.on(EVENTS.ROOM_MESSAGE, (data) => {
      if (data.system && data.content.includes("joined")) resolve(data);
    });
  });

  clientA.emit(EVENTS.ROOM_JOIN, { room: "lobby", name: "Alice" });
  await wait(200);
  clientB.emit(EVENTS.ROOM_JOIN, { room: "lobby", name: "Bob" });

  const joinMsg = await Promise.race([roomJoinMsg, wait(3000).then(() => null)]);
  assert(joinMsg !== null, "room join announcement received");
  assert(joinMsg && joinMsg.content.includes("Bob"), "join announcement has joiner name");

  // Room message
  const roomMsgReceived = new Promise((resolve) => {
    const handler = (data) => {
      if (!data.system) { clientA.off(EVENTS.ROOM_MESSAGE, handler); resolve(data); }
    };
    clientA.on(EVENTS.ROOM_MESSAGE, handler);
  });
  clientB.emit(EVENTS.ROOM_MESSAGE, { room: "lobby", content: "Hey room!" });
  const roomMsg = await Promise.race([roomMsgReceived, wait(3000).then(() => null)]);
  assert(roomMsg !== null && roomMsg.content === "Hey room!", "room message delivered");

  // Room members
  const membersReceived = new Promise((resolve) => {
    clientA.on(EVENTS.ROOM_MEMBERS, (data) => resolve(data));
  });
  clientA.emit(EVENTS.ROOM_MEMBERS, { room: "lobby" });
  const members = await Promise.race([membersReceived, wait(2000).then(() => null)]);
  assert(members && members.members && members.members.length === 2, "room:members returns 2 members");

  // Room leave
  const leaveMsg = new Promise((resolve) => {
    const handler = (data) => {
      if (data.system && data.content.includes("left")) { clientA.off(EVENTS.ROOM_MESSAGE, handler); resolve(data); }
    };
    clientA.on(EVENTS.ROOM_MESSAGE, handler);
  });
  clientB.emit(EVENTS.ROOM_LEAVE, { room: "lobby" });
  const lm = await Promise.race([leaveMsg, wait(2000).then(() => null)]);
  assert(lm !== null && lm.content.includes("Bob"), "room leave announcement received");

  // ── Persistent Groups ──
  console.log("\n── Persistent Groups ──");

  const groupCreated = new Promise((resolve) => {
    clientA.on(EVENTS.GROUP_CREATED, (data) => resolve(data));
  });
  clientA.emit(EVENTS.GROUP_CREATE, { name: "Dev Team" });
  const gc = await Promise.race([groupCreated, wait(3000).then(() => null)]);
  assert(gc && gc.group && gc.group.name === "Dev Team", "group:created received with group data");
  assert(gc && gc.group.ownerId === "user-A", "group owner is creator");

  const groupId = gc?.group?.id;

  // Group join
  const groupJoined = new Promise((resolve) => {
    clientB.on(EVENTS.GROUP_JOINED, (data) => resolve(data));
  });
  clientB.emit(EVENTS.GROUP_JOIN, { groupId });
  const gj = await Promise.race([groupJoined, wait(3000).then(() => null)]);
  assert(gj && gj.groupId === groupId, "group:joined received");

  // Group message
  const groupMsgReceived = new Promise((resolve) => {
    const handler = (data) => {
      if (!data.system && data.senderId === "user-B") { clientA.off(EVENTS.GROUP_MESSAGE, handler); resolve(data); }
    };
    clientA.on(EVENTS.GROUP_MESSAGE, handler);
  });
  clientB.emit(EVENTS.GROUP_MESSAGE, { groupId, content: "Group hello!" });
  const gm = await Promise.race([groupMsgReceived, wait(3000).then(() => null)]);
  assert(gm !== null && gm.content === "Group hello!", "group message delivered to members");

  // Group members
  const groupMembers = new Promise((resolve) => {
    clientA.on(EVENTS.GROUP_MEMBERS, (data) => resolve(data));
  });
  clientA.emit(EVENTS.GROUP_MEMBERS, { groupId });
  const gmem = await Promise.race([groupMembers, wait(2000).then(() => null)]);
  assert(gmem && gmem.members && gmem.members.length === 2, "group:members returns 2 members");

  // Group invite (owner invites user-C)
  const clientC = await connectClient({ auth: { token: token3 } });
  const inviteReceived = new Promise((resolve) => {
    clientC.on(EVENTS.GROUP_INVITED, (data) => resolve(data));
  });
  clientA.emit(EVENTS.GROUP_INVITE, { groupId, userId: "user-C" });
  const inv = await Promise.race([inviteReceived, wait(3000).then(() => null)]);
  assert(inv && inv.groupId === groupId, "group:invited received by invitee");

  // Group kick (owner kicks user-C)
  const kickReceived = new Promise((resolve) => {
    clientC.on(EVENTS.GROUP_KICKED, (data) => resolve(data));
  });
  clientA.emit(EVENTS.GROUP_KICK, { groupId, userId: "user-C" });
  const kicked = await Promise.race([kickReceived, wait(3000).then(() => null)]);
  assert(kicked && kicked.groupId === groupId, "group:kicked received by kicked user");

  // Group leave
  const groupLeft = new Promise((resolve) => {
    clientB.on(EVENTS.GROUP_LEFT, (data) => resolve(data));
  });
  clientB.emit(EVENTS.GROUP_LEAVE, { groupId });
  const gl = await Promise.race([groupLeft, wait(2000).then(() => null)]);
  assert(gl && gl.groupId === groupId, "group:left received");

  // ── Notifications ──
  console.log("\n── Notifications ──");

  const notifReceived = new Promise((resolve) => {
    clientB.on(EVENTS.NOTIFICATION_RECEIVED, (data) => resolve(data));
  });
  clientA.emit(EVENTS.NOTIFICATION_SEND, { to: "user-B", title: "Hey!", body: "Check this out" });
  const notif = await Promise.race([notifReceived, wait(3000).then(() => null)]);
  assert(notif && notif.title === "Hey!", "targeted notification delivered");
  assert(notif && notif.from === "user-A", "notification has correct sender");

  // Broadcast notification
  const broadcastReceived = new Promise((resolve) => {
    const handler = (data) => {
      if (data.broadcast) { clientB.off(EVENTS.NOTIFICATION_RECEIVED, handler); resolve(data); }
    };
    clientB.on(EVENTS.NOTIFICATION_RECEIVED, handler);
  });
  clientA.emit(EVENTS.NOTIFICATION_BROADCAST, { title: "Server Update", body: "v2 is live" });
  const bc = await Promise.race([broadcastReceived, wait(3000).then(() => null)]);
  assert(bc && bc.title === "Server Update", "broadcast notification delivered");
  assert(bc && bc.broadcast === true, "broadcast flag set");

  // ── Disconnect cleanup ──
  console.log("\n── Disconnect Cleanup ──");

  clientC.close();
  clientB.close();
  clientA.close();
  await wait(500);

  // Verify cache is cleaned up (user keys removed)
  const userASocket = await server.cache.get("user:user-A");
  const userBSocket = await server.cache.get("user:user-B");
  assert(userASocket === undefined, "user-A cache entry cleaned on disconnect");
  assert(userBSocket === undefined, "user-B cache entry cleaned on disconnect");

  await server.stop();
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve(data));
    }).on("error", reject);
  });
}

// ─── Run All ──────────────────────────────────────────────────────

async function main() {
  console.log("═══════════════════════════════════════════");
  console.log(" Chat Server — Full Test Suite");
  console.log("═══════════════════════════════════════════");

  // Unit tests
  await testUUID();
  await testEncryption();
  await testCacheAdapter();
  await testPersistenceAdapter();
  await testQueueAdapter();
  await testValidation();
  await testConfig();
  await testLogger();

  // Integration tests
  await testServerIntegration();

  // Results
  console.log("\n═══════════════════════════════════════════");
  console.log(` Results: ${passed} passed, ${failed} failed`);
  console.log("═══════════════════════════════════════════\n");

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Test runner error:", err);
  process.exit(1);
});
