
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {evaluate, workspacePath} = require('../action/index.js');
const policy = {version:1, default_decision:'deny', rules:[
 {id:'allow-read-only',match:{risk_class:'read_only',reversible:true},decision:'allow'},
 {id:'allow-dev-low',match:{risk_class:'low',reversible:true,environment:'development'},decision:'allow'}
]};
const base = {action_id:'a1',operation:'read',target:'sandbox',risk_class:'read_only',reversible:true,environment:'development'};
test('allows explicit read-only policy rule',()=>assert.equal(evaluate(base,policy).decision,'ALLOW'));
test('denies unknown risk even if a rule tries to allow it',()=>assert.equal(evaluate({...base,risk_class:'unknown'}, {...policy,rules:[{id:'bad-allow',match:{risk_class:'unknown'},decision:'allow'}]}).decision,'DENY'));
test('hard-denies irreversible even if policy says allow',()=>assert.equal(evaluate({...base,risk_class:'irreversible',reversible:false}, {...policy,rules:[{id:'bad-allow',match:{risk_class:'irreversible',reversible:false},decision:'allow'}]}).decision,'DENY'));
test('hard-denies consequential risk even if reversible',()=>assert.equal(evaluate({...base,risk_class:'consequential'},policy).decision,'DENY'));
test('rejects policy configured with allow-by-default',()=>assert.throws(()=>evaluate(base,{...policy,default_decision:'allow'}),/must be deny/));
test('rejects unsupported policy version',()=>assert.throws(()=>evaluate(base,{...policy,version:9}),/Unsupported policy version/));
test('rejects non-boolean reversibility',()=>assert.throws(()=>evaluate({...base,reversible:'false'},policy),/boolean/));
test('rejects missing action identifier',()=>assert.throws(()=>evaluate({...base,action_id:''},policy),/action_id/));
test('rejects unsafe workspace traversal',()=>assert.throws(()=>workspacePath('../outside.json'),/inside GITHUB_WORKSPACE/));
