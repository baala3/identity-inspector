import { collect, evaluate, type Fetcher } from '@identity-inspector/core';
import type { InspectRequest, InspectResponse } from './protocol.js';

/**
 * Fetches through the proxy, which accepts a URL and nothing else, so no
 * header set here could reach a target (ADR 0001).
 */
const viaProxy =
  (proxy: string): Fetcher =>
  async (url) => {
    try {
      const response = await fetch(`${proxy}/fetch?url=${encodeURIComponent(url)}`);
      const body = await response.json();
      if (!response.ok)
        return {
          url,
          status: 0,
          headers: {},
          body: '',
          error: body.error ?? `proxy HTTP ${response.status}`,
        };
      return body;
    } catch (error) {
      return {
        url,
        status: 0,
        headers: {},
        body: '',
        error: `proxy unreachable: ${String(error)}`,
      };
    }
  };

self.onmessage = async ({ data }: MessageEvent<InspectRequest>) => {
  const reply = (message: InspectResponse) => self.postMessage(message);
  try {
    const workspace = await collect(
      data.input,
      viaProxy(data.proxy),
      data.protocol ? { protocol: data.protocol } : {},
    );
    const report = evaluate(workspace, data.at ? new Date(data.at) : new Date());
    reply({
      id: data.id,
      report,
      raw: Object.fromEntries(workspace.evidence.map((e) => [e.id, e.raw])),
    });
  } catch (error) {
    reply({ id: data.id, error: error instanceof Error ? error.message : String(error) });
  }
};
