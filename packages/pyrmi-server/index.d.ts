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
  session?: string | null;
  player?: string;
  score?: number | null;
  unverified?: boolean;
}

export interface VerifyInput {
  /** The token from Pyrmi.start() in the browser. */
  token: string;
  score: number;
  /** How long the run lasted, if your game knows. Used for impossible-time and score-rate checks. */
  durationMs?: number;
  /** Your player id or name. Shown on the dashboard. */
  player?: string;
  /** Whatever your game records (inputs, moves). Only passed to simulate. */
  replay?: unknown;
  /** Re-run the game from the replay on your server. A different score means the run was faked. */
  simulate?: (replay: unknown) => { score: number; durationMs?: number } | Promise<{ score: number; durationMs?: number }>;
}

export interface PyrmiOptions {
  secretKey?: string;
  /** Defaults to https://pyrmi.com/api/v1. Point it at your own deployment if you self-host. */
  endpoint?: string;
  timeoutMs?: number;
  /** When Pyrmi can't be reached: false (default) rejects the score, true accepts it unverified. */
  failOpen?: boolean;
}

export declare class Pyrmi {
  constructor(opts?: PyrmiOptions);
  verify(input: VerifyInput): Promise<VerifyResult>;
}
export default Pyrmi;
