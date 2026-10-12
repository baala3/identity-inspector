// Outbound requests may only reach public hosts (ADR 0004).

export type Resolver = (hostname: string) => Promise<string[]>;

function ipv4(address: string): number[] | undefined {
  const parts = address.split('.');
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255))
    return undefined;
  return parts.map(Number);
}

function publicV4([a = 0, b = 0, c = 0]: number[]): boolean {
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 198 && (b === 18 || b === 19))
  );
}

/** Expands an IPv6 literal to its eight groups, or undefined when it is not one. */
function ipv6(address: string): number[] | undefined {
  let text = address;
  const tail = ipv4(text.slice(text.lastIndexOf(':') + 1));
  if (tail) {
    const [a = 0, b = 0, c = 0, d = 0] = tail;
    text = `${text.slice(0, text.lastIndexOf(':') + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves[1] ? halves[1].split(':') : [];
  const gap = halves.length === 2 ? 8 - head.length - rest.length : 0;
  const groups = [...head, ...Array<string>(Math.max(gap, 0)).fill('0'), ...rest];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return undefined;
  return groups.map((g) => Number.parseInt(g, 16));
}

function publicV6(groups: number[]): boolean {
  const [g0 = 0, g1 = 0, , , , g5 = 0, g6 = 0, g7 = 0] = groups;
  const embedded = [g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff];
  // IPv4-mapped and NAT64 addresses are judged by the IPv4 address inside.
  if (groups.slice(0, 5).every((g) => g === 0) && g5 === 0xffff) return publicV4(embedded);
  if (g0 === 0x64 && g1 === 0xff9b) return publicV4(embedded);
  if (groups.slice(0, 7).every((g) => g === 0)) return false; // :: and ::1
  if ((g0 & 0xfe00) === 0xfc00) return false; // unique local
  if ((g0 & 0xffc0) === 0xfe80) return false; // link local
  if ((g0 & 0xff00) === 0xff00) return false; // multicast
  return true;
}

export function isPublicAddress(address: string): boolean {
  const v4 = ipv4(address);
  if (v4) return publicV4(v4);
  const v6 = ipv6(address);
  return v6 ? publicV6(v6) : false;
}

const PRIVATE_SUFFIXES = ['localhost', '.local', '.internal', '.lan', '.home.arpa', '.corp'];
const PORTS = new Set(['', '80', '443', '8443']);

/** Returns why the URL may not be fetched, or undefined when it may. */
export async function refusal(url: URL, resolve: Resolver): Promise<string | undefined> {
  if (url.protocol !== 'https:' && url.protocol !== 'http:')
    return 'only http and https are fetched';
  if (url.username || url.password) return 'URLs carrying credentials are not fetched';
  if (!PORTS.has(url.port)) return `port ${url.port} is not allowed`;

  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (ipv4(host) || ipv6(host)) {
    return isPublicAddress(host) ? undefined : 'the address is not public';
  }
  if (!host.includes('.') || PRIVATE_SUFFIXES.some((s) => host === s || host.endsWith(s))) {
    return 'the host name is not public';
  }
  const addresses = await resolve(host);
  if (!addresses.length) return 'the host name does not resolve';
  return addresses.every(isPublicAddress)
    ? undefined
    : 'the host name resolves to a non-public address';
}

/** Resolves over DNS-over-HTTPS, which works in a Worker where sockets do not. */
export const dohResolver: Resolver = async (hostname) => {
  const lookup = async (type: 'A' | 'AAAA') => {
    const response = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`,
      { headers: { accept: 'application/dns-json' } },
    );
    if (!response.ok) return [];
    const body = (await response.json()) as { Answer?: Array<{ type: number; data: string }> };
    // 1 is A, 28 is AAAA; anything else in the answer is a CNAME hop.
    return (body.Answer ?? []).filter((a) => a.type === 1 || a.type === 28).map((a) => a.data);
  };
  return (await Promise.all([lookup('A'), lookup('AAAA')])).flat();
};
