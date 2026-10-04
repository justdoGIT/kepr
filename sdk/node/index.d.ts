export declare class KeprError extends Error {}
export declare function socketPath(): string;
export interface SetOptions { generate?: 'hex' | 'base62' | 'pass' | 'uuid' | 'words'; ttlSecs?: number; requiresConsent?: boolean }
export declare class Client {
  constructor(opts?: { path?: string; timeoutMs?: number });
  request(req: Record<string, unknown>): Promise<Record<string, any>>;
  get(name: string): Promise<string>;
  set(name: string, value?: string | null, opts?: SetOptions): Promise<Record<string, any>>;
  delete(name: string): Promise<void>;
  list(): Promise<Array<Record<string, any>>>;
  history(name: string): Promise<Array<{ version: number; saved_at: string; size: number; sealed?: boolean }>>;
  restore(name: string, version: number): Promise<void>;
  usage(days?: number): Promise<Record<string, any>>;
  health(maxAgeDays?: number): Promise<Array<{ name: string; issues: string[]; age_days: number }>>;
  sshSign(name: string, data: Uint8Array): Promise<Buffer>;
  status(): Promise<Record<string, any>>;
  ping(): Promise<boolean>;
}
