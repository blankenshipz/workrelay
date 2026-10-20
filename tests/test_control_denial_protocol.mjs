import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CONTROL_DENIAL_CODES, safeControlFailure, safeControlResult } from '../src/workrelay/mcp.mjs';

test('MCP control denial enum matches actual Python constant, not exception descriptions', () => {
  const path = fileURLToPath(new URL('../src/workrelay/cli.py', import.meta.url));
  const script = 'import ast,json,sys; t=ast.parse(open(sys.argv[1]).read()); n=next(n for n in t.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=="CONTROL_DENIAL_CODES" for x in n.targets)); print(json.dumps(sorted(ast.literal_eval(n.value.args[0]))))';
  const actual = JSON.parse(execFileSync('/usr/bin/python3', ['-c', script, path], { encoding: 'utf8' }));
  assert.deepEqual([...CONTROL_DENIAL_CODES].sort(), actual);
  assert.equal(Object.isFrozen(CONTROL_DENIAL_CODES), true);
});

test('every finite denial code and sentinel survive errors and status with safe time only', () => {
  for (const denial_code of CONTROL_DENIAL_CODES) {
    for (const denied_at_ms of [0, 1, Number.MAX_SAFE_INTEGER]) {
      const fields = { denial_code, denied_at_ms };
      assert.deepEqual(safeControlResult({ phase: 'denied', ...fields }), { phase: 'denied', ...fields });
      const error = safeControlFailure({ error: 'PRIVATE', code: 'CONTROL_NOT_SENT', ...fields, stack: 'PRIVATE', credential: 'PRIVATE' });
      assert.equal(error.denial_code, denial_code); assert.equal(error.denied_at_ms, denied_at_ms);
      assert.doesNotMatch(JSON.stringify(error), /PRIVATE/);
    }
    for (const denied_at_ms of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, Infinity, NaN, true, '123', {}, [], null, undefined]) {
      assert.equal(safeControlFailure({ code: 'CONTROL_NOT_SENT', denial_code, denied_at_ms }).denied_at_ms, null);
      assert.equal(safeControlResult({ phase: 'denied', denial_code, denied_at_ms }).denied_at_ms, null);
    }
  }
  for (const denial_code of ['DENIAL_REASON_NOT_RECORDED', 'PRIVATE\nQUOTA_DENIED', 'quota_denied', {}, [], null, undefined]) {
    for (const project of [safeControlFailure, safeControlResult]) {
      const result = project({ phase: 'denied', denial_code, denied_at_ms: 123 });
      assert.equal(result.denial_code, 'DENIAL_REASON_NOT_RECORDED'); assert.equal(result.denied_at_ms, null);
      assert.doesNotMatch(JSON.stringify(result), /PRIVATE/);
    }
  }
});

test('legacy denied operation stays unknown/null without backfill; unaffected statuses unchanged', () => {
  const legacy = { phase: 'denied', recorded_phase: 'denied', effect: 'not_applied' };
  assert.deepEqual(safeControlResult(legacy), { ...legacy, denial_code: 'DENIAL_REASON_NOT_RECORDED', denied_at_ms: null });
  assert.deepEqual(legacy, { phase: 'denied', recorded_phase: 'denied', effect: 'not_applied' });
  const unchanged = { phase: 'accepted', effect: 'recorded', operation_id: 'fixture' };
  assert.deepEqual(safeControlResult(unchanged), unchanged);
  assert.deepEqual(safeControlResult({ denial_code: 'QUOTA_DENIED', denied_at_ms: 0 }), { denial_code: 'QUOTA_DENIED', denied_at_ms: 0 });
});
