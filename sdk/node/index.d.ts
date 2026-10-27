export declare class KeprError extends Error {}
export declare function socketPath(): string;
export type GenerateKind = 'hex' | 'base62' | 'pass' | 'uuid' | 'words';
export declare const GENERATE_KINDS: GenerateKind[];
export interface SetOptions { generate?: GenerateKind; ttlSecs?: number; requiresConsent?: boolean; requiresFido2?: boolean }
/** One credential's metadata (never a value). Fields from newer daemons (tags, folder…) pass through. */
export interface CredInfo {
  name: string;
  size: number;
  modified: string;
  expiresAt: string | null;
  recordType: string | null;
  boundHosts: string[] | null;
  sealed: boolean;
  requiresConsent: boolean;
  requiresFido2: boolean;
  tags?: string[];
  [extra: string]: unknown;
}
export declare function credInfo(raw: Record<string, any>): CredInfo;
export declare class Client {
  constructor(opts?: { path?: string; timeoutMs?: number });
  request(req: Record<string, unknown>): Promise<Record<string, any>>;
  get(name: string): Promise<string>;
  set(name: string, value?: string | null, opts?: SetOptions): Promise<Record<string, any>>;
  generate(name: string, kind?: GenerateKind, opts?: Omit<SetOptions, 'generate'>): Promise<Record<string, any>>;
  delete(name: string): Promise<void>;
  list(): Promise<Array<Record<string, any>>>;
  credentials(): Promise<CredInfo[]>;
  info(name: string): Promise<CredInfo | null>;
  history(name: string): Promise<Array<{ version: number; saved_at: string; size: number; sealed?: boolean }>>;
  restore(name: string, version: number): Promise<void>;
  usage(days?: number): Promise<Record<string, any>>;
  health(maxAgeDays?: number): Promise<Array<{ name: string; issues: string[]; age_days: number }>>;
  sshSign(name: string, data: Uint8Array): Promise<Buffer>;
  status(): Promise<Record<string, any>>;
  ping(): Promise<boolean>;
}
