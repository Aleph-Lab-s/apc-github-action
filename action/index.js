'use strict';
const fs = require('node:fs');
const path = require('node:path');
const ALLOWED_RISKS = new Set(['read_only', 'low']);
const HARD_DENY_RISKS = new Set(['consequential', 'irreversible', 'critical', 'financial', 'privileged', 'high', 'high_consequence', 'sensitive', 'production_mutation']);
function workspacePath(input) {
  const root = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd());
  const resolved = path.resolve(root, input);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) throw new Error('Path must remain inside GITHUB_WORKSPACE');
  return resolved;
}
function readJson(file) {
  const raw = fs.readFileSync(file, 'utf8');
  if (Buffer.byteLength(raw, 'utf8') > 256 * 1024) throw new Error('JSON input exceeds 256 KiB limit');
  return JSON.parse(raw);
}
function safeToken(value, field) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256 || /[\r\n\0]/.test(value)) throw new Error(`Invalid ${field}`);
  return value;
}
function evaluate(request, policy) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error('Action request must be a JSON object');
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new Error('Policy must be a JSON object');
  if (policy.version !== 1) throw new Error('Unsupported policy version; expected version 1');
  const actionId = safeToken(request.action_id, 'action_id');
  const operation = safeToken(request.operation, 'operation');
  const target = safeToken(request.target, 'target');
  const risk = safeToken(request.risk_class, 'risk_class').toLowerCase();
  const reversible = request.reversible;
  if (typeof reversible !== 'boolean') throw new Error('reversible must be a boolean');
  const environment = typeof request.environment === 'string' ? request.environment.toLowerCase() : 'unknown';
  const policyDefault = String(policy.default_decision || 'deny').toLowerCase();
  if (policyDefault !== 'deny') throw new Error('default_decision must be deny in the free release');
  // The free candidate only allows known low-risk classes; unknown/high-impact classes always deny.
  if (reversible === false || HARD_DENY_RISKS.has(risk) || !ALLOWED_RISKS.has(risk)) {
    return { decision: 'DENY', reason: 'FREE_RC_HIGH_CONSEQUENCE_ACTION_BLOCKED', actionId, operation, target, risk, reversible, environment };
  }
  if (!Array.isArray(policy.rules)) throw new Error('policy.rules must be an array');
  for (const rule of policy.rules) {
    if (!rule || typeof rule !== 'object' || !rule.match || typeof rule.match !== 'object') continue;
    const matches = Object.entries(rule.match).every(([key, value]) => request[key] === value || (key === 'risk_class' && String(request[key]).toLowerCase() === String(value).toLowerCase()));
    if (matches) {
      const decision = String(rule.decision || 'deny').toLowerCase();
      if (!['allow', 'deny'].includes(decision)) throw new Error(`Invalid decision in policy rule ${rule.id || '(unnamed)'}`);
      return { decision: decision.toUpperCase(), reason: safeToken(rule.id || `POLICY_RULE_${decision.toUpperCase()}`, 'rule id'), actionId, operation, target, risk, reversible, environment };
    }
  }
  return { decision: policyDefault.toUpperCase(), reason: 'POLICY_DEFAULT', actionId, operation, target, risk, reversible, environment };
}
function getInput(name, fallback) { return process.env[`INPUT_${name.toUpperCase()}`] || fallback; }
function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) fs.appendFileSync(outputFile, `${name}=${String(value).replace(/[\r\n]/g, ' ')}\n`);
}
function main() {
  const requestFile = workspacePath(getInput('request-path', 'apc-action-request.json'));
  const policyFile = workspacePath(getInput('policy-path', '.apc/policy.json'));
  const reportFile = workspacePath(getInput('report-path', 'apc-decision-report.json'));
  const request = readJson(requestFile);
  const policy = readJson(policyFile);
  const result = evaluate(request, policy);
  const report = {
    schema_version: 1, product: 'APC GitHub Free RC', mode: 'PRE-FLIGHT_ONLY',
    decision: result.decision, reason: result.reason,
    action: { action_id: result.actionId, operation: result.operation, target: result.target, risk_class: result.risk, reversible: result.reversible, environment: result.environment },
    policy_version: policy.version,
    repository: process.env.GITHUB_REPOSITORY || null,
    workflow_run_id: process.env.GITHUB_RUN_ID || null,
    evaluated_at: new Date().toISOString(),
    disclaimer: 'This report is a preflight evaluation, not proof of provider-side enforcement. Free RC never authorizes consequential or irreversible effects.'
  };
  fs.mkdirSync(path.dirname(reportFile), {recursive:true});
  fs.writeFileSync(reportFile, JSON.stringify(report, null, 2) + '\n', {mode:0o600});
  setOutput('decision', result.decision); setOutput('reason', result.reason);
  console.log(`APC preflight: ${result.decision} (${result.reason})`);
  if (result.decision !== 'ALLOW') { console.error(`APC fail-closed gate denied action ${result.actionId}: ${result.reason}`); process.exitCode = 1; }
}
if (require.main === module) {
  try { main(); } catch (err) { console.error(`APC gate error (fail-closed): ${err.message}`); process.exitCode = 1; }
}
module.exports = {evaluate, workspacePath};
