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

    it('should accumulate repeated --claim flags into an array', () => {
      const result = parseArgs(['vc:issue', '--claim', 'role=admin', '--claim', 'dept=eng']);
      expect(result.options.claim).toEqual(['role=admin', 'dept=eng']);
    });

    it('should handle three or more repeated --claim flags', () => {
      const result = parseArgs(['vc:issue', '--claim', 'a=1', '--claim', 'b=2', '--claim', 'c=3']);
      expect(result.options.claim).toEqual(['a=1', 'b=2', 'c=3']);
    });

    it('should not turn non-claim duplicated keys into arrays', () => {
      // Only --claim should accumulate; other flags are overwritten as before
      const result = parseArgs(['cmd', '--other', 'val1', '--other', 'val2']);
      expect(result.options.other).toBe('val2');
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

    it('should parse multiple claims from an array', () => {
      const options = { claim: ['role=admin', 'department=engineering', 'level=5'] };
      const claims = parseClaims(options);
      expect(claims).toEqual({ role: 'admin', department: 'engineering', level: '5' });
    });
  });
});