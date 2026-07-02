// src/util/canonical-json.js

/**
 * Deterministic JSON canonicalization (JCS-inspired).
 * Produces a stable, reproducible string from any JSON-compatible value.
 * Handles edge cases: undefined, Infinity, NaN, Date, Buffer, sparse arrays, circular refs.
 *
 * @param {*} obj - Value to canonicalize
 * @param {Set} [seen] - Internal: circular reference tracking
 * @returns {string} Canonical JSON string
 * @throws {TypeError} For circular references, Infinity, or NaN values
 */
function canonicalize(obj, seen) {
  // Handle primitives
  if (obj === undefined) {
    // undefined is not valid JSON — skip keys with undefined values (JSON.stringify behavior)
    return undefined;
  }
  if (obj === null) {
    return 'null';
  }
  if (typeof obj === 'boolean') {
    return obj ? 'true' : 'false';
  }
  if (typeof obj === 'number') {
    // FIX B4: Reject Infinity and NaN explicitly instead of silently converting to null
    if (!Number.isFinite(obj)) {
      throw new TypeError(
        `canonicalize: number value is not finite (${obj}). ` +
        'Infinity and NaN are not valid in JSON and indicate a data integrity issue.'
      );
    }
    return JSON.stringify(obj);
  }
  if (typeof obj === 'string') {
    return JSON.stringify(obj);
  }

  // FIX B5: Handle Date objects — convert to ISO string (matches JSON.stringify behavior)
  if (obj instanceof Date) {
    return JSON.stringify(obj.toISOString());
  }

  // FIX B7: Handle Buffer objects — serialize as base64 string
  if (Buffer.isBuffer(obj)) {
    return JSON.stringify(obj.toString('base64'));
  }

  // Handle arrays (including sparse arrays)
  if (Array.isArray(obj)) {
    // FIX B3: Circular reference detection
    seen = seen || new Set();
    if (seen.has(obj)) {
      throw new TypeError('canonicalize: circular reference detected');
    }
    seen.add(obj);

    // FIX B6: Handle sparse arrays by iterating all indices
    const len = obj.length;
    const items = [];
    for (let i = 0; i < len; i++) {
      // Has own property at this index?
      if (Object.prototype.hasOwnProperty.call(obj, i)) {
        const val = canonicalize(obj[i], seen);
        if (val !== undefined) {
          items.push(val);
        } else {
          // Value is explicitly undefined at this index — treat as null
          items.push('null');
        }
      } else {
        // Hole in sparse array — treat as null
        items.push('null');
      }
    }
    seen.delete(obj);
    return '[' + items.join(',') + ']';
  }

  // Handle objects
  if (typeof obj === 'object') {
    // FIX B3: Circular reference detection
    seen = seen || new Set();
    if (seen.has(obj)) {
      throw new TypeError('canonicalize: circular reference detected');
    }
    seen.add(obj);

    const keys = Object.keys(obj).sort();
    const pairs = [];
    for (const k of keys) {
      const val = canonicalize(obj[k], seen);
      // FIX B2: Skip undefined values entirely (matches JSON.stringify behavior)
      if (val === undefined) continue;
      pairs.push(JSON.stringify(k) + ':' + val);
    }
    seen.delete(obj);
    return '{' + pairs.join(',') + '}';
  }

  // Unsupported type
  throw new TypeError(`canonicalize: unsupported type ${typeof obj}`);
}

module.exports = { canonicalize };