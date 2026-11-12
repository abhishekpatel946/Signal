import { readFileSync } from "fs";
import { join } from "path";
import type { Account, Payload } from "./types";

let cached: Payload | null = null;

export function loadPayload(): Payload {
  if (cached) return cached;
  const path = join(process.cwd(), "data", "accounts.json");
  const raw = readFileSync(path, "utf8");
  cached = JSON.parse(raw) as Payload;
  return cached;
}

export function loadAccounts(): Account[] {
  return loadPayload().accounts;
}

export function getAccount(domain: string): Account | undefined {
  const needle = domain.toLowerCase();
  return loadAccounts().find((a) => a.domain.toLowerCase() === needle);
}

export function listMeta() {
  const payload = loadPayload();
  return payload.stats;
}

export function loadMetrics(): Record<string, number> | null {
  try {
    const path = join(process.cwd(), "data", "metrics.json");
    return JSON.parse(readFileSync(path, "utf8")) as Record<string, number>;
  } catch {
    return null;
  }
}
