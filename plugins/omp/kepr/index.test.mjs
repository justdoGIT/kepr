import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import kepr from './index.ts';

function harness(check = text => ({text: text.replaceAll('SENSITIVE_TEST', '[removed]'), found: 1})) {
  const handlers = new Map();
  const calls = [];
  let active = 0, maximum = 0;
  const run = async (event, payload) => {
    calls.push(payload.text);
    active++; maximum = Math.max(maximum, active);
    await new Promise(resolve => setImmediate(resolve));
    active--;
    return { code: 0, message: JSON.stringify(check(payload.text)) };
  };
  kepr({on: (name, fn) => handlers.set(name, fn), registerCommand() {}}, run);
  return {context: handlers.get('context'), handlers, calls, get maximum() { return maximum; }};
}

test('redaction retains tool linkage, safe fields, signatures and saved history', async () => {
  const h = harness();
  const signed = {type:'thinking',thinking:'safe',thinkingSignature:'opaque'};
  const image = {type:'image',data:'opaque'};
  const messages = [{role:'assistant',content:[
    {type:'text',text:'SENSITIVE_TEST'},
    {type:'toolCall',id:'saved',arguments:{nested:['SENSITIVE_TEST'],path:'keep.txt'}}, signed,image,
  ]}];
  const out = await h.context({messages});
  assert.equal(out.messages[0].content[0].text,'[removed]');
  assert.equal(out.messages[0].content[1].arguments.nested[0],'[removed]');
  assert.equal(out.messages[0].content[1].arguments.path,'keep.txt');
  assert.equal(out.messages[0].content[1].id,'saved');
  assert.equal(out.messages[0].content[2],signed);
  assert.equal(out.messages[0].content[3],image);
  assert.equal(messages[0].content[0].text,'SENSITIVE_TEST');
});

test('long histories bound concurrency and coalesce identical in-flight text', async () => {
  const h = harness();
  await h.context({messages:Array.from({length:32},()=>({role:'user',content:'SENSITIVE_TEST'}))});
  assert.equal(h.calls.length,1);
  await h.context({messages:Array.from({length:64},(_,i)=>({role:'user',content:`SENSITIVE_TEST_${i}`}))});
  assert.ok(h.maximum<=8);
});

test('failed checks are withheld and never cached', async () => {
  for (const reply of [{}, {text:'unchecked'}, {text:'unchecked',found:-1}]) {
    const h = harness(()=>reply);
    for (let i=0;i<2;i++) {
      const out=await h.context({messages:[{role:'toolResult',content:'SENSITIVE_TEST'}]});
      assert.match(out.messages[0].content,/withheld by kepr/);
    }
    assert.equal(h.calls.length,2);
  }
});

test('signed reasoning and invalid arguments are refused, not corrupted', async () => {
  const h=harness();
  await assert.rejects(h.context({messages:[{content:[{type:'thinking',thinking:'SENSITIVE_TEST',thinkingSignature:'opaque'}]}]}),/signed reasoning/);
  await assert.rejects(h.context({messages:[{content:[{type:'toolCall',arguments:'{'}]}]}),/valid JSON/);
});

test('successful unchanged checks are reused without retaining a second payload', async () => {
  const h=harness(text=>({text,found:0}));
  const event={messages:[{role:'user',content:'kepr-ph-synthetic'}]};
  assert.equal(await h.context(event),undefined);
  assert.equal(await h.context(event),undefined);
  assert.equal(h.calls.length,1);
});

test('cache evicts redacted payloads by bytes, not only entry count', async () => {
  const clean='x'.repeat(3*1024*1024);
  const h=harness(()=>({text:clean,found:1}));
  for (const content of ['first','second','first']) await h.context({messages:[{content}]});
  assert.deepEqual(h.calls,['first','second','first']);
});

test('missing executable fails closed for context, signed reasoning, tools and input', () => {
  const module = new URL('./index.ts',import.meta.url).href;
  const source=`import kepr from ${JSON.stringify(module)};
    const handlers=new Map(); const emit=process.emit;
    kepr({on:(n,f)=>handlers.set(n,f),registerCommand(){}});
    if(process.emit!==emit) throw new Error('global emit changed');
    const out=await handlers.get('context')({messages:[{content:'synthetic unchecked'}]});
    if(!out.messages[0].content.includes('withheld')) throw new Error('unchecked context');
    let refused=false;
    try {await handlers.get('context')({messages:[{content:[{type:'thinking',thinking:'unchecked',thinkingSignature:'opaque'}]}]});} catch {refused=true;}
    if(!refused) throw new Error('unchecked signature');
    if(!(await handlers.get('tool_call')({toolName:'read',input:{}})).block) throw new Error('unchecked tool');
    if(!(await handlers.get('input')({text:'safe'},{hasUI:false})).handled) throw new Error('unchecked input');`;
  const child=spawnSync(process.execPath,['--input-type=module','-e',source],{env:{PATH:'/usr/bin:/bin',KEPR_BIN:'/nonexistent/kepr-review'},encoding:'utf8',timeout:15000});
  assert.equal(child.status,0,child.stderr);
});
