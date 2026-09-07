import { createHash, randomUUID } from "node:crypto";
import { AuditLog, redactSecrets } from "./auditLog.js";

export const CHARGE_KEY_TTL_MS = 24 * 60 * 60 * 1000;
export const MAX_IDEMPOTENCY_KEY_LENGTH = 255;

export type ChargeInput = {
  amount: number;
  currency: string;
  source: string;
  description?: string;
};

export type Charge = ChargeInput & {
  id: string;
  tenantId: string;
  createdAt: number;
  status: "succeeded";
};

export type StoredChargeResponse = {
  statusCode: number;
  body: unknown;
};

export type ChargeIdempotencyRecord = {
  tenantId: string;
  key: string;
  fingerprint: string;
  createdAt: number;
  expiresAt: number;
  state: "in_progress" | "completed";
  response?: StoredChargeResponse;
};

export type IdempotencyClaim =
  | { kind: "claimed"; record: ChargeIdempotencyRecord }
  | { kind: "replay"; record: ChargeIdempotencyRecord; response: StoredChargeResponse }
  | { kind: "conflict"; record: ChargeIdempotencyRecord }
  | { kind: "in_progress"; record: ChargeIdempotencyRecord };

export interface ChargeIdempotencyStore {
  claim(
    tenantId: string,
    key: string,
    fingerprint: string,
    now?: number
  ): IdempotencyClaim;
  complete(
    record: ChargeIdempotencyRecord,
    response: StoredChargeResponse,
    now?: number
  ): void;
  release(record: ChargeIdempotencyRecord): void;
  prune(now?: number): number;
  size(): number;
}

/**
 * An in-process store used by the API gateway. `claim` performs the lookup and
 * insert as one synchronous operation, which is the atomic boundary required
 * by concurrent requests in this process. A production multi-process adapter
 * can implement the same contract with INSERT ... ON CONFLICT.
 */
export class InMemoryChargeIdempotencyStore implements ChargeIdempotencyStore {
  private readonly records = new Map<string, ChargeIdempotencyRecord>();

  claim(
    tenantId: string,
    key: string,
    fingerprint: string,
    now = Date.now()
  ): IdempotencyClaim {
    this.prune(now);
    const namespacedKey = this.namespace(tenantId, key);
    const existing = this.records.get(namespacedKey);
    if (existing) {
      if (existing.fingerprint !== fingerprint)
        return { kind: "conflict", record: existing };
      if (existing.state === "in_progress")
        return { kind: "in_progress", record: existing };
      if (!existing.response) return { kind: "in_progress", record: existing };
      return {
        kind: "replay",
        record: existing,
        response: cloneResponse(existing.response),
      };
    }

    const record: ChargeIdempotencyRecord = {
      tenantId,
      key,
      fingerprint,
      createdAt: now,
      expiresAt: now + CHARGE_KEY_TTL_MS,
      state: "in_progress",
    };
    this.records.set(namespacedKey, record);
    return { kind: "claimed", record };
  }

  complete(
    record: ChargeIdempotencyRecord,
    response: StoredChargeResponse,
    now = Date.now()
  ): void {
    const current = this.records.get(this.namespace(record.tenantId, record.key));
    if (current !== record) return;
    current.state = "completed";
    current.response = cloneResponse(response);
    current.expiresAt = now + CHARGE_KEY_TTL_MS;
  }

  release(record: ChargeIdempotencyRecord): void {
    const namespacedKey = this.namespace(record.tenantId, record.key);
    if (this.records.get(namespacedKey) === record && record.state === "in_progress") {
      this.records.delete(namespacedKey);
    }
  }

  prune(now = Date.now()): number {
    let removed = 0;
    for (const [key, record] of this.records) {
      if (record.expiresAt <= now) {
        this.records.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  size(): number {
    return this.records.size;
  }

  private namespace(tenantId: string, key: string): string {
    return `${tenantId}\u0000${key}`;
  }
}

export class InMemoryChargeStore {
  private readonly charges: Charge[] = [];
  private readonly auditLog?: AuditLog;

  constructor(auditLog?: AuditLog) {
    this.auditLog = auditLog;
  }

  create(tenantId: string, input: ChargeInput, now = Date.now()): Charge {
    const charge: Charge = {
      ...input,
      id: `ch_${randomUUID()}`,
      tenantId,
      createdAt: now,
      status: "succeeded",
    };
    this.charges.push(charge);
    this.auditLog?.append({
      actor: tenantId,
      action: "charge.create",
      targetId: charge.id,
      targetType: "charge",
      after: redactSecrets(charge as unknown as Record<string, unknown>),
    });
    return cloneCharge(charge);
  }

  list(tenantId: string): Charge[] {
    return this.charges
      .filter((charge) => charge.tenantId === tenantId)
      .map(cloneCharge);
  }

  get(tenantId: string, chargeId: string): Charge | undefined {
    const charge = this.charges.find(
      (candidate) => candidate.tenantId === tenantId && candidate.id === chargeId
    );
    return charge === undefined ? undefined : cloneCharge(charge);
  }

  count(tenantId?: string): number {
    return tenantId === undefined
      ? this.charges.length
      : this.charges.filter((charge) => charge.tenantId === tenantId).length;
  }

  clear(): void {
    this.charges.length = 0;
  }
}

export function canonicalChargePayload(input: ChargeInput): string {
  return JSON.stringify({
    amount: input.amount,
    currency: input.currency,
    description: input.description ?? null,
    source: input.source,
  });
}

export function chargeFingerprint(
  tenantId: string,
  method: string,
  path: string,
  input: ChargeInput
): string {
  return createHash("sha256")
    .update(
      `${method.toUpperCase()}\n${path}\n${tenantId}\n${canonicalChargePayload(input)}`
    )
    .digest("hex");
}

export function validateIdempotencyKey(value: string | undefined): string | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  const key = value.trim();
  if (key.length > MAX_IDEMPOTENCY_KEY_LENGTH) return undefined;
  if (!/^[A-Za-z0-9._~:-]+$/.test(key)) return undefined;
  return key;
}

export function validateChargeInput(
  body: unknown
): { ok: true; value: ChargeInput } | { ok: false; message: string } {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, message: "charge body must be an object" };
  }
  const record = body as Record<string, unknown>;
  if (!Number.isSafeInteger(record.amount) || (record.amount as number) <= 0) {
    return { ok: false, message: "amount must be a positive safe integer" };
  }
  if (typeof record.currency !== "string" || !/^[A-Z]{3}$/.test(record.currency)) {
    return { ok: false, message: "currency must be a three-letter uppercase code" };
  }
  if (
    typeof record.source !== "string" ||
    record.source.length < 1 ||
    record.source.length > 256
  ) {
    return { ok: false, message: "source must be 1-256 characters" };
  }
  if (
    record.description !== undefined &&
    (typeof record.description !== "string" || record.description.length > 500)
  ) {
    return { ok: false, message: "description must be at most 500 characters" };
  }
  return {
    ok: true,
    value: {
      amount: record.amount as number,
      currency: record.currency,
      source: record.source,
      ...(record.description === undefined
        ? {}
        : { description: record.description as string }),
    },
  };
}

function cloneCharge(charge: Charge): Charge {
  return { ...charge };
}

function cloneResponse(response: StoredChargeResponse): StoredChargeResponse {
  return {
    statusCode: response.statusCode,
    body:
      response.body === undefined
        ? undefined
        : JSON.parse(JSON.stringify(response.body)),
  };
}
