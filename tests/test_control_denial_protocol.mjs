import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ATTESTATION_CHECK_IDS, CONTROL_DENIAL_CODES, CONTROL_LOOKUP_CODES, safeControlFailure, safeControlResult } from '../src/workrelay/mcp.mjs';

test('MCP control denial enum matches actual Python constant, not exception descriptions', () => {
  const path = fileURLToPath(new URL('../src/workrelay/cli.py', import.meta.url));
  const script = 'import ast,json,sys; t=ast.parse(open(sys.argv[1]).read()); n=next(n for n in t.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=="CONTROL_DENIAL_CODES" for x in n.targets)); print(json.dumps(sorted(ast.literal_eval(n.value.args[0]))))';
  const actual = JSON.parse(execFileSync('/usr/bin/python3', ['-c', script, path], { encoding: 'utf8' }));
  assert.deepEqual([...CONTROL_DENIAL_CODES].sort(), actual);
  assert.equal(Object.isFrozen(CONTROL_DENIAL_CODES), true);
});

test('attestation check enum matches native source exactly and projects only denied attestation predicates', () => {
  const path = fileURLToPath(new URL('../src/workrelay/attestor.py', import.meta.url));
  const script = 'import ast,json,sys; t=ast.parse(open(sys.argv[1]).read()); n=next(n for n in t.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=="ATTESTATION_CHECK_IDS" for x in n.targets)); print(json.dumps(sorted(ast.literal_eval(n.value.args[0]))))';
  assert.deepEqual([...ATTESTATION_CHECK_IDS].sort(), JSON.parse(execFileSync('/usr/bin/python3', ['-c', script, path], { encoding: 'utf8' })));
  assert.equal(Object.isFrozen(ATTESTATION_CHECK_IDS), true);
  for (const attestation_check_id of ATTESTATION_CHECK_IDS) {
    for (const project of [safeControlResult, safeControlFailure]) {
      assert.equal(project({ phase: 'denied', denial_code: 'ATTESTATION_FAILED', attestation_check_id }).attestation_check_id, attestation_check_id);
      for (const denial_code of [...CONTROL_DENIAL_CODES.filter(code => code !== 'ATTESTATION_FAILED'), 'PRIVATE', undefined]) {
        assert.equal(project({ phase: 'denied', denial_code, attestation_check_id }).attestation_check_id, null);
      }
    }
  }
  for (const attestation_check_id of [undefined, null, '', 'guard_source', 'GUARD_SOURCE\nPRIVATE', 'PRIVATE/path', {}, [], ['GUARD_SOURCE'], 1, true]) {
    for (const project of [safeControlResult, safeControlFailure]) {
      const result = project({ phase: 'denied', denial_code: 'ATTESTATION_FAILED', attestation_check_id });
      assert.equal(result.attestation_check_id, null);
      assert.doesNotMatch(JSON.stringify(result), /PRIVATE/);
    }
  }
  for (const phase of ['accepted', 'uncertain', 'pre_post', 'unknown', undefined, 'PRIVATE']) {
    const fields = { phase, denial_code: 'ATTESTATION_FAILED', denied_at_ms: 123, attestation_check_id: 'PRIVATE' };
    assert.deepEqual(safeControlResult(fields), { phase });
    const error = safeControlFailure(fields);
    for (const key of ['denial_code', 'denied_at_ms', 'attestation_check_id']) assert.equal(error[key], undefined);
    assert.doesNotMatch(JSON.stringify(error), /PRIVATE/);
  }
});

test('every finite denial code and sentinel survive errors and status with safe time only', () => {
  for (const denial_code of CONTROL_DENIAL_CODES) {
    for (const denied_at_ms of [0, 1, Number.MAX_SAFE_INTEGER]) {
      const fields = { denial_code, denied_at_ms, attestation_check_id: null };
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
  assert.deepEqual(safeControlResult(legacy), { ...legacy, denial_code: 'DENIAL_REASON_NOT_RECORDED', denied_at_ms: null, attestation_check_id: null });
  assert.deepEqual(legacy, { phase: 'denied', recorded_phase: 'denied', effect: 'not_applied' });
  const unchanged = { phase: 'accepted', effect: 'recorded', operation_id: 'fixture' };
  assert.deepEqual(safeControlResult(unchanged), unchanged);
  assert.deepEqual(safeControlResult({ denial_code: 'QUOTA_DENIED', denied_at_ms: 0 }), {});
});

test('scoped receipt lookup codes match control source and never claim global absence/no-effect or echo raw advice', () => {
  const path = fileURLToPath(new URL('../src/workrelay/managed_control.py', import.meta.url));
  const script = 'import ast,json,sys; t=ast.parse(open(sys.argv[1]).read()); print(json.dumps(sorted({n.args[0].value for n in ast.walk(t) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="OperationLookupError" and n.args and isinstance(n.args[0],ast.Constant)})))';
  assert.deepEqual([...CONTROL_LOOKUP_CODES].sort(), JSON.parse(execFileSync('/usr/bin/python3', ['-c', script, path], { encoding: 'utf8' })));
  for (const code of CONTROL_LOOKUP_CODES) for (const project of [safeControlResult, safeControlFailure]) {
    const result = project({ code, error: 'PRIVATE', guidance: 'PRIVATE replay now', phase: 'denied', effect: 'no_post_permitted',
      lookup_scope: 'PRIVATE', native_observation: 'PRIVATE', task_outcome: 'PRIVATE', replay_permitted: true,
      operation_id: 'fixture', session_id: 'PRIVATE/../../session', stack: 'PRIVATE' });
    assert.equal(result.code, code); assert.equal(result.phase, 'unknown'); assert.equal(result.effect, 'not_established');
    assert.equal(result.lookup_scope, 'current_authenticated_binding'); assert.equal(result.native_observation, 'not_run');
    assert.equal(result.replay_permitted, false); assert.equal(result.task_outcome, 'unverified');
    assert.equal(result.session_id, undefined); assert.equal(result.operation_id, 'fixture');
    assert.match(result.guidance, /operator/i); assert.match(result.guidance, /replay/); assert.doesNotMatch(JSON.stringify(result), /PRIVATE/);
  }
});
