// src/util/canonical-json.js
function canonicalize(obj) {
  if (Array.isArray(obj)) {
    return '[' + obj.map((v) => canonicalize(v)).join(',') + ']';
  }
  if (obj && typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    return (
      '{' +
      keys
        .map((k) => {
          return JSON.stringify(k) + ':' + canonicalize(obj[k]);
        })
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(obj);
}

module.exports = { canonicalize };