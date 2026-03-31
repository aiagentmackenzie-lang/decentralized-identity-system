// tests/cli/cli.test.js
const { parseArgs, parseClaims } = require('../../src/cli/index');

describe('CLI Module', () => {
  describe('parseArgs', () => {
    it('should parse command', () => {
      const result = parseArgs(['did:create']);
      expect(result.command).toBe('did:create');
    });

    it('should parse options with values', () => {
      const result = parseArgs(['vc:issue', '--issuer', 'did:demo:abc', '--subject', 'did:demo:def']);
      expect(result.options.issuer).toBe('did:demo:abc');
      expect(result.options.subject).toBe('did:demo:def');
    });

    it('should parse positional arguments', () => {
      const result = parseArgs(['did:resolve', 'did:demo:abc123']);
      expect(result.positional).toEqual(['did:demo:abc123']);
    });

    it('should handle boolean flags', () => {
      const result = parseArgs(['cmd', '--verbose']);
      expect(result.options.verbose).toBe(true);
    });
  });

  describe('parseClaims', () => {
    it('should parse single claim', () => {
      const options = { claim: 'role=admin' };
      const claims = parseClaims(options);
      expect(claims).toEqual({ role: 'admin' });
    });

    it('should return empty object when no claims', () => {
      const options = {};
      const claims = parseClaims(options);
      expect(claims).toEqual({});
    });

    it('should handle malformed claim gracefully', () => {
      const options = { claim: 'invalid-claim' };
      const claims = parseClaims(options);
      expect(claims).toEqual({});
    });
  });
});