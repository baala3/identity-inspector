import { DOMParser, type Document, type Element } from '@xmldom/xmldom';
import type { Evidence } from './model.js';

export type Json = Record<string, unknown>;

const jsonCache = new WeakMap<Evidence, Json | undefined>();
const xmlCache = new WeakMap<Evidence, XmlResult>();

/** The evidence body as a JSON object, or undefined when it is not one. */
export function json(evidence: Evidence): Json | undefined {
  if (!jsonCache.has(evidence)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(evidence.raw);
    } catch {
      parsed = undefined;
    }
    const isObject = typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed);
    jsonCache.set(evidence, isObject ? (parsed as Json) : undefined);
  }
  return jsonCache.get(evidence);
}

export function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

export function objects(value: unknown): Json[] {
  return Array.isArray(value)
    ? value.filter((v): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v))
    : [];
}

export type XmlResult =
  | { document: Document; error?: undefined }
  | { document?: undefined; error: string };

/**
 * Parses XML with the one parser every environment shares (see ADR 0002).
 * DTDs and entity declarations are refused rather than processed.
 */
export function parseXml(text: string): XmlResult {
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
    return { error: 'document declares a DTD or entities, which are refused' };
  }
  try {
    const document = new DOMParser({
      onError: (level, message) => {
        if (level !== 'warning') throw new Error(message);
      },
    }).parseFromString(text, 'text/xml');
    if (!document.documentElement) return { error: 'document has no root element' };
    return { document };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { error: message.split('\n')[0] ?? message };
  }
}

export function xml(evidence: Evidence): XmlResult {
  let result = xmlCache.get(evidence);
  if (!result) {
    result = parseXml(evidence.raw);
    xmlCache.set(evidence, result);
  }
  return result;
}

export function descendants(parent: Document | Element, ns: string, name: string): Element[] {
  return Array.from(parent.getElementsByTagNameNS(ns, name));
}

export function childElements(parent: Element, ns: string, name: string): Element[] {
  return Array.from(parent.childNodes).filter(
    (node): node is Element =>
      node.nodeType === 1 &&
      (node as Element).namespaceURI === ns &&
      (node as Element).localName === name,
  );
}

export function isHttps(url: unknown): boolean {
  if (typeof url !== 'string') return false;
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}
