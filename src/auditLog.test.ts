import { describe, it, beforeEach } from "node:test";
import assert from "node:assert";
import { AuditLog, redactSecrets } from "./auditLog.js";

await describe("AuditLog", async () => {
  let auditLog: AuditLog;

  await Promise.resolve(beforeEach(() => {
    auditLog = new AuditLog();
  }));

  await it("records an entry for a mutation", () => {
    const entry = auditLog.append({
      actor: "tenant-1",
      action: "charge.create",
      targetId: "ch_123",
      targetType: "charge",
      after: { amount: 100, currency: "USD" },
    });
    assert.match(entry.id, /^audit_/);
    assert.strictEqual(entry.actor, "tenant-1");
    assert.strictEqual(entry.action, "charge.create");
    assert.strictEqual(entry.targetId, "ch_123");
    assert.strictEqual(auditLog.size(), 1);
  });

  await it("does not record an entry for a read", () => {
    assert.strictEqual(auditLog.size(), 0);
  });

  await it("queries by target id", () => {
    auditLog.append({
      actor: "tenant-1",
      action: "charge.create",
      targetId: "ch_123",
      targetType: "charge",
      after: { amount: 100 },
    });
    auditLog.append({
      actor: "tenant-1",
      action: "charge.create",
      targetId: "ch_456",
      targetType: "charge",
      after: { amount: 200 },
    });
    const entries = auditLog.queryByTarget("ch_123");
    assert.strictEqual(entries.length, 1);
    assert.strictEqual(entries[0].targetId, "ch_123");
  });

  await it("queries by actor", () => {
    auditLog.append({
      actor: "tenant-a",
      action: "charge.create",
      targetId: "ch_1",
      targetType: "charge",
      after: { amount: 100 },
    });
    auditLog.append({
      actor: "tenant-b",
      action: "charge.create",
      targetId: "ch_2",
      targetType: "charge",
      after: { amount: 200 },
    });
    const entries = auditLog.queryByActor("tenant-a");
    assert.strictEqual(entries.length, 1);
    assert.strictEqual(entries[0].actor, "tenant-a");
  });

  await it("supports pagination", () => {
    for (let i = 0; i < 5; i++) {
      auditLog.append({
        actor: "tenant-1",
        action: "charge.create",
        targetId: `ch_${i}`,
        targetType: "charge",
        after: { amount: i },
      });
    }
    const entries = auditLog.queryByActor("tenant-1", 2, 1);
    assert.strictEqual(entries.length, 2);
    assert.strictEqual(entries[0].targetId, "ch_1");
    assert.strictEqual(entries[1].targetId, "ch_2");
  });

  await it("never redacts non-sensitive fields", () => {
    const payload = { amount: 100, currency: "USD" };
    const redacted = redactSecrets(payload);
    assert.strictEqual(redacted.amount, 100);
    assert.strictEqual(redacted.currency, "USD");
  });

  await it("redacts secrets from payloads", () => {
    const payload = {
      amount: 100,
      apiToken: "super-secret",
      password: "hunter2",
      nested: { ssn: "123-45-6789", name: "Alice" },
    };
    const redacted = redactSecrets(payload);
    assert.strictEqual(redacted.apiToken, "[REDACTED]");
    assert.strictEqual(redacted.password, "[REDACTED]");
    assert.strictEqual((redacted.nested as Record<string, unknown>).ssn, "[REDACTED]");
    assert.strictEqual((redacted.nested as Record<string, unknown>).name, "Alice");
  });

  await it("entries are ordered by timestamp", () => {
    auditLog.append({
      actor: "tenant-1",
      action: "charge.create",
      targetId: "ch_1",
      targetType: "charge",
      after: { amount: 100 },
    });
    auditLog.append({
      actor: "tenant-1",
      action: "charge.create",
      targetId: "ch_2",
      targetType: "charge",
      after: { amount: 200 },
    });
    const entries = auditLog.queryByActor("tenant-1");
    assert.ok(entries[0].timestamp <= entries[1].timestamp);
  });
});
