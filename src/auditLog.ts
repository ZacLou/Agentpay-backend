import { randomUUID } from "node:crypto";

export type AuditAction = "charge.create" | "charge.update" | "charge.refund";

export interface AuditEntry {
  id: string;
  actor: string; // tenantId or apiKey prefix
  action: AuditAction;
  targetId: string;
  targetType: string;
  before?: Record<string, unknown>;
  after?: Record<string, unknown>;
  timestamp: number;
  requestId?: string;
}

/**
 * Append-only, immutable audit log for state-changing payments operations.
 * Entries are never updated or deleted.
 */
export class AuditLog {
  private readonly entries: AuditEntry[] = [];

  append(entry: Omit<AuditEntry, "id" | "timestamp">): AuditEntry {
    const fullEntry: AuditEntry = {
      ...entry,
      id: `audit_${randomUUID()}`,
      timestamp: Date.now(),
    };
    this.entries.push(fullEntry);
    return fullEntry;
  }

  /** Query by target id, ordered by timestamp ascending. */
  queryByTarget(targetId: string, limit?: number, offset?: number): AuditEntry[] {
    const matches = this.entries.filter((e) => e.targetId === targetId);
    return this.paginate(matches, limit, offset);
  }

  /** Query by actor, ordered by timestamp ascending. */
  queryByActor(actor: string, limit?: number, offset?: number): AuditEntry[] {
    const matches = this.entries.filter((e) => e.actor === actor);
    return this.paginate(matches, limit, offset);
  }

  /** Total count of entries. */
  size(): number {
    return this.entries.length;
  }

  /** Clear all entries (test helper only). */
  clear(): void {
    this.entries.length = 0;
  }

  private paginate(items: AuditEntry[], limit?: number, offset?: number): AuditEntry[] {
    const start = offset ?? 0;
    const end = limit === undefined ? undefined : start + limit;
    return items.slice(start, end);
  }
}

/**
 * Redacts sensitive fields from a payload before recording in the audit log.
 * Removes any key that looks like a secret, token, password, or PII.
 */
export function redactSecrets(
  payload: Record<string, unknown>
): Record<string, unknown> {
  const sensitiveKeys = /token|secret|password|ssn|sin|pin|cvv|authorization|auth/i;
  const redacted: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (sensitiveKeys.test(key)) {
      redacted[key] = "[REDACTED]";
    } else if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      redacted[key] = redactSecrets(value as Record<string, unknown>);
    } else {
      redacted[key] = value;
    }
  }
  return redacted;
}
