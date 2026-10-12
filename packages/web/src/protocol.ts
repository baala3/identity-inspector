import type { Protocol, Report } from '@identity-inspector/core';

export interface InspectRequest {
  id: number;
  input: string;
  protocol?: Protocol;
  /** ISO evaluation instant; now when absent. */
  at?: string;
  proxy: string;
}

export type InspectResponse =
  | { id: number; report: Report; raw: Record<string, string> }
  | { id: number; error: string };
