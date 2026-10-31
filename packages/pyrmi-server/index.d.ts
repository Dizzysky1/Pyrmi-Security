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
  /** 'ok': the action arrived exactly as the page sealed it. 'bad': it was changed or is stale (a reject). 'none': not sealed. */
  signed?: 'ok' | 'bad' | 'none';
  /** The browser's context was forwarded (req or client) and checked against the browser that started the session. */
  bound?: boolean;
  session?: string | null;
  player?: string;
  score?: number | null;
  unverified?: boolean;
}

export interface ClientContext {
  ua: string;
  ip?: string;
  /** The Sec-CH-UA header. */
  ch?: string;
  /** The Sec-Fetch-Site header ('' when the request had none). */
  sfs?: string;
}

export interface VerifyInput {
  /** The token from Pyrmi.start() in the browser. Not needed with sealed. */
  token?: string;
  /** The parsed JSON body the page sent, made with Pyrmi.seal({ ... }). Checked for changes on the way. */
  sealed?: Record<string, unknown> & { pyrmi?: { token: string; ts: number; sig: string } };
  /** Your incoming request; its browser headers and address are forwarded so a relayed session is caught. */
  req?: { headers: Record<string, string | string[] | undefined> | { get(name: string): string | null }; socket?: { remoteAddress?: string }; ip?: string };
  /** Instead of req: the browser's context yourself. */
  client?: ClientContext;
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
  /** Proxies of yours in front of this server, so req's address is read from the right X-Forwarded-For entry. */
  trustProxyHops?: number;
  /** Your Cloudflare Turnstile widget's secret key, for verifyTurnstile(). Defaults to TURNSTILE_SECRET_KEY. */
  turnstileSecret?: string;
  /** Override Cloudflare's siteverify URL (tests). */
  turnstileEndpoint?: string;
}

export interface TurnstileResult {
  success: boolean;
  errorCodes: string[];
  hostname?: string;
  action?: string;
}

export interface TurnstileOptions {
  /** The visitor's IP address. */
  remoteip?: string;
  /** The data-action your widget was given. A token made for another action fails. */
  action?: string;
  /** Your site's hostname. A token made on another host fails. */
  hostname?: string;
}

export declare class Pyrmi {
  constructor(opts?: PyrmiOptions);
  verify(input: VerifyInput): Promise<VerifyResult>;
  /** Checks a Turnstile token with Cloudflare. Fails closed (success: false) on any doubt. */
  verifyTurnstile(token: string | null | undefined, opts?: TurnstileOptions): Promise<TurnstileResult>;
}
/**
 * The server's `trusted` flag, safely (false for a failOpen stand-in). Use it to gate sensitive actions. Pass a
 * verifyTurnstile() result as the second argument to require Turnstile to have passed too.
 */
export declare function trusted(v: VerifyResult | null | undefined, turnstile?: TurnstileResult | null): boolean;
export default Pyrmi;
