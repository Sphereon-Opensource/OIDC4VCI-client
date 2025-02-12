import { BAD_PARAMS, DecodeURIAsJsonOpts, EncodeJsonAsURIOpts, JsonURIMode, OpenId4VCIVersion, SearchValue } from '../types';

/**
 * @type {(json: {[s:string]: never} | ArrayLike<never> | string | object, opts?: EncodeJsonAsURIOpts)} encodes a Json object into a URI
 * @param { {[s:string]: never} | ArrayLike<never> | string | object } json
 * @param {EncodeJsonAsURIOpts} [opts] Option to encode json as uri
 *          - urlTypeProperties: a list of properties of which the value is a URL
 *          - arrayTypeProperties: a list of properties which are an array
 */

// /* eslint-disable @typescript-eslint/no-explicit-any */
export function convertJsonToURI(
  json:
    | {
        [s: string]: never;
      }
    | ArrayLike<never>
    | string
    | object,
  opts?: EncodeJsonAsURIOpts,
): string {
  if (typeof json === 'string') {
    return convertJsonToURI(JSON.parse(json), opts);
  }

  const results = [];

  function encodeAndStripWhitespace(key: string): string {
    return encodeURIComponent(key.replace(' ', ''));
  }

  let components: string;
  if ((opts?.version && opts.version > OpenId4VCIVersion.VER_1_0_08 && !opts.mode) || opts?.mode === JsonURIMode.JSON_STRINGIFY) {
    // v11 changed from encoding every param to a encoded json object with a credential_offer param key
    components = encodeAndStripWhitespace(JSON.stringify(json));
  } else {
    // version 8 or lower, or mode is x-form-www-urlencoded
    for (const [key, value] of Object.entries(json)) {
      if (!value) {
        continue;
      }
      //Skip properties that are not of URL type
      if (!opts?.uriTypeProperties?.includes(key)) {
        results.push(`${key}=${value}`);
        continue;
      }
      if (opts?.arrayTypeProperties?.includes(key) && Array.isArray(value)) {
        results.push(value.map((v) => `${encodeAndStripWhitespace(key)}=${customEncodeURIComponent(v, /\./g)}`).join('&'));
        continue;
      }
      const isBool = typeof value == 'boolean';
      const isNumber = typeof value == 'number';
      const isString = typeof value == 'string';
      let encoded;
      if (isBool || isNumber) {
        encoded = `${encodeAndStripWhitespace(key)}=${value}`;
      } else if (isString) {
        encoded = `${encodeAndStripWhitespace(key)}=${customEncodeURIComponent(value, /\./g)}`;
      } else {
        encoded = `${encodeAndStripWhitespace(key)}=${customEncodeURIComponent(JSON.stringify(value), /\./g)}`;
      }
      results.push(encoded);
    }
    components = results.join('&');
  }
  if (opts?.baseUrl) {
    if (opts.baseUrl.endsWith('=')) {
      if (opts.param) {
        throw Error('Cannot combine param with an url ending in =');
      }
      return `${opts.baseUrl}${components}`;
    } else if (!opts.baseUrl.includes('?')) {
      return `${opts.baseUrl}?${opts.param ? opts.param + '=' : ''}${components}`;
    } else if (opts.baseUrl.endsWith('?')) {
      return `${opts.baseUrl}${opts.param ? opts.param + '=' : ''}${components}`;
    } else {
      return `${opts.baseUrl}${opts.param ? '&' + opts.param : ''}=${components}`;
    }
  }
  return components;
}

/**
 * @type {(uri: string, opts?: DecodeURIAsJsonOpts): unknown} convertURIToJsonObject converts an URI into a Json object decoding its properties
 * @param {string} uri
 * @param {DecodeURIAsJsonOpts} [opts]
 *          - requiredProperties: the required properties
 *          - arrayTypeProperties: properties that can show up more that once
 * @returns JSON object
 */
export function convertURIToJsonObject(uri: string, opts?: DecodeURIAsJsonOpts): unknown {
  if (!uri || (opts?.requiredProperties && !opts.requiredProperties?.every((p) => uri.includes(p)))) {
    throw new Error(BAD_PARAMS);
  }

  const uriComponents = getURIComponentsAsArray(uri, opts?.arrayTypeProperties);
  return decodeJsonProperties(uriComponents);
}

export function decodeJsonProperties(parts: string[] | string[][]): unknown {
  const result: { [s: string]: unknown } | ArrayLike<unknown> = {};
  for (const key in parts) {
    const value = parts[key];
    if (!value) {
      continue;
    }
    if (Array.isArray(value)) {
      result[decodeURIComponent(key)] = value.map((v) => decodeURIComponent(v));
      continue
    }

    const isBool = typeof value == 'boolean';
    const isNumber = typeof value == 'number';
    const isString = typeof value == 'string';
    const isObject = typeof value == 'object';
    if (isBool || isNumber) {
      result[decodeURIComponent(key)] = value;
    } else if (isString) {
      const decoded = decodeURIComponent(value);
      if (decoded.startsWith('{') && decoded.endsWith('}')) {
        result[decodeURIComponent(key)] = JSON.parse(decoded);
      } else {
        result[decodeURIComponent(key)] = decoded;
      }
    } else if(isObject) {
      result[decodeURIComponent(key)] = decodeJsonProperties(value)
    }
  }
  return result;
}

/**
 * @function get URI Components as Array
 * @param {string} uri uri
 * @param {string[]} [arrayTypes] array of string containing array like keys
 */
export function getURIComponentsAsArray(uri: string, arrayTypes?: string[]): string[] | string[][] {
  const parts = uri.includes('?') ? uri.split('?')[1] : uri.includes('://') ? uri.split('://')[1] : uri;
  const json: string[] | string[][] = [];
  const dict: string[] = parts.split('&');
  for (const entry of dict) {
    const pair: string[] = entry.split('=');
    const p0: any = pair[0];
    const p1: any = pair[1];
    if (arrayTypes?.includes(p0)) {
      const key = json[p0];
      if (Array.isArray(key)) {
        key.push(p1);
      } else {
        json[p0] = [p1];
      }
      continue;
    }
    json[p0] = p1;
  }
  return json;
}

/**
 * @function customEncodeURIComponent is used to encode chars that are not encoded by default
 * @param searchValue The pattern/regexp to find the char(s) to be encoded
 * @param uriComponent query string
 */
function customEncodeURIComponent(uriComponent: string, searchValue: SearchValue): string {
  // -_.!~*'() are not escaped because they are considered safe.
  // Add them to the regex as you need
  return encodeURIComponent(uriComponent).replace(searchValue, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}
