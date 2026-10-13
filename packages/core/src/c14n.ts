import type { Element, Node } from '@xmldom/xmldom';

const XMLNS = 'http://www.w3.org/2000/xmlns/';

export interface C14nOptions {
  /** A subtree left out of the output: the signature itself, for an enveloped signature. */
  omit?: Node;
  /** Prefixes handled the inclusive way, from an InclusiveNamespaces PrefixList. */
  inclusive?: string[];
  comments?: boolean;
}

const text = (value: string) =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');

const attribute = (value: string) =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/"/g, '&quot;')
    .replace(/\t/g, '&#x9;')
    .replace(/\n/g, '&#xA;')
    .replace(/\r/g, '&#xD;');

/** The namespace a prefix is bound to at this element, looking outward. Empty when unbound. */
function inScope(element: Element, prefix: string): string {
  const name = prefix ? `xmlns:${prefix}` : 'xmlns';
  for (let node: Node | null = element; node?.nodeType === 1; node = node.parentNode) {
    if ((node as Element).hasAttribute(name)) return (node as Element).getAttribute(name) ?? '';
  }
  return '';
}

/**
 * Exclusive XML Canonicalization 1.0 of one element and everything under it.
 * This is the one canonicalizer every environment shares (ADR 0002).
 */
export function canonicalize(root: Element, options: C14nOptions = {}): string {
  const inclusive = new Set((options.inclusive ?? []).map((p) => (p === '#default' ? '' : p)));
  const out: string[] = [];

  /** `rendered` is what the nearest output ancestors have already declared, by prefix. */
  const element = (node: Element, rendered: Map<string, string>) => {
    const attributes = Array.from(node.attributes).filter(
      (a) => a.namespaceURI !== XMLNS && a.name !== 'xmlns' && !a.name.startsWith('xmlns:'),
    );

    // A prefix is declared here only if this element or one of its attributes uses it.
    const used = new Set<string>([node.prefix ?? '']);
    for (const a of attributes) if (a.prefix && a.prefix !== 'xml') used.add(a.prefix);
    for (const prefix of inclusive) used.add(prefix);

    const declared = new Map(rendered);
    const declarations: Array<[string, string]> = [];
    for (const prefix of used) {
      if (prefix === 'xml') continue;
      const uri =
        prefix === (node.prefix ?? '') ? (node.namespaceURI ?? '') : inScope(node, prefix);
      if ((rendered.get(prefix) ?? '') === uri) continue;
      // An inclusive prefix that is not bound here has nothing to declare.
      if (!uri && prefix) continue;
      declarations.push([prefix, uri]);
      declared.set(prefix, uri);
    }
    declarations.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    attributes.sort((a, b) => {
      const [left, right] = [a.namespaceURI ?? '', b.namespaceURI ?? ''];
      if (left !== right) return left < right ? -1 : 1;
      const [first, second] = [a.localName ?? a.name, b.localName ?? b.name];
      return first < second ? -1 : first > second ? 1 : 0;
    });

    out.push(`<${node.tagName}`);
    for (const [prefix, uri] of declarations) {
      out.push(` ${prefix ? `xmlns:${prefix}` : 'xmlns'}="${attribute(uri)}"`);
    }
    for (const a of attributes) out.push(` ${a.name}="${attribute(a.value)}"`);
    out.push('>');
    for (const child of Array.from(node.childNodes)) visit(child, declared);
    out.push(`</${node.tagName}>`);
  };

  const visit = (node: Node, rendered: Map<string, string>) => {
    if (node === options.omit) return;
    switch (node.nodeType) {
      case 1:
        element(node as Element, rendered);
        break;
      case 3:
      case 4:
        out.push(text(node.nodeValue ?? ''));
        break;
      case 7:
        out.push(`<?${node.nodeName}${node.nodeValue ? ` ${node.nodeValue}` : ''}?>`);
        break;
      case 8:
        if (options.comments) out.push(`<!--${node.nodeValue ?? ''}-->`);
        break;
    }
  };

  visit(root, new Map());
  return out.join('');
}
