export type Verdict = 'accept' | 'review' | 'reject';

export interface Reason {
  code: string;
  weight?: number;
  text?: string;
  detail?: string;
}

export interface VerifyResult {
  ok: boolean;
  verdict: Verdict;
  /** 0 (clean) to 100 (certain cheat). null when Pyrmi could not be reached. */
  risk: number | null;
  reasons: Reason[];
  /**
   * How much of the browser telemetry the server could check against what it saw itself (which page sent it, the
   * browser's own request headers, its own clock). 'corroborated' still isn't proof of a person: a person in their
   * own browser can send what the real script would. 'unverified' adds the unverified_client reason.
   */
  client?: 'corroborated' | 'unverified' | 'none';
  /**
   * The gate for payouts, prizes and account changes: an accept with corroborated telemetry, a real key press or
   * click, and no reason beyond wrapped_runtime, devtools_open, ip_changed or idle_input. Independent of
   * reviewAt/rejectAt. Use trusted(v) rather than reading it, so a failOpen stand-in verdict is never trusted.
   */
  trusted?: boolean;
  session?: string | null;
  player?: string;
  score?: number | null;
  unverified?: boolean;
}

export interface VerifyInput {
  /** The token from Pyrmi.start() in the browser. */
  token: string;
  /** Optional number the action carries (a score, points, a quantity). Checked against your caps. */
  score?: number;
  /** How long the action took, if you know. Used for impossible-time and rate checks. */
  durationMs?: number;
  /** Your user id or name. Shown on the dashboard. */
  player?: string;
  /** Same as player. */
  user?: string;
  /** Whatever a deterministic app records (inputs, moves). Only passed to simulate. */
  replay?: unknown;
  /** Re-run the app from the replay on your server. A different score means the result was faked. */
  simulate?: (replay: unknown) => { score: number; durationMs?: number } | Promise<{ score: number; durationMs?: number }>;
}

export interface PyrmiOptions {
  secretKey?: string;
  /** Defaults to https://pyrmi.com/api/v1. Point it at your own deployment if you self-host. */
  endpoint?: string;
  timeoutMs?: number;
  /** When Pyrmi can't be reached: false (default) rejects the action, true accepts it unverified. */
  failOpen?: boolean;
}

export declare class Pyrmi {
  constructor(opts?: PyrmiOptions);
  verify(input: VerifyInput): Promise<VerifyResult>;
}
/** The server's `trusted` flag, safely (false for a failOpen stand-in). Use it to gate sensitive actions. */
export declare function trusted(v: VerifyResult | null | undefined): boolean;
export default Pyrmi;
