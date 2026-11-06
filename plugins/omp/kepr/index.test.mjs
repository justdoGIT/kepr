import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import vm from 'node:vm';
import { EventEmitter } from 'node:events';

async function harness(response = text => ({ text: text.replaceAll('SENSITIVE_TEST', '[removed]'), found: 1 })) {
  const source = await readFile(new URL('./index.ts', import.meta.url), 'utf8');
  const code = stripTypeScriptTypes(source)
    .replace(/import \{ spawn,[^}]+\} from "node:child_process";/, '')
    .replace('import { readFileSync } from "node:fs";', '')
    .replace('import { join } from "node:path";', '')
    .replace('import { registerProviders } from "./providers.ts";', '')
    .replace('export default function kepr', 'function kepr');
  const handlers = new Map();
  const calls = [];
  let active = 0;
  let maxConcurrent = 0;
  const spawn = () => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
    child.stdin = new EventEmitter(); child.kill = () => {};
    child.stdin.end = raw => {
      const { text } = JSON.parse(raw);
      calls.push(text);
      active++;
      maxConcurrent = Math.max(maxConcurrent, active);
      queueMicrotask(() => {
        child.stdout.emit('data', JSON.stringify(response(text)));
        active--;
        child.emit('close', 0);
      });
    };
    return child;
  };
  const sandbox = { spawn, process: { env: {}, emit() {} }, setTimeout, clearTimeout };
  vm.runInNewContext(code + '\nkepr(pi);', { ...sandbox, pi: {
    on: (event, handler) => handlers.set(event, handler), registerCommand() {},
  }});
  return { context: handlers.get('context'), calls, get maxConcurrent() { return maxConcurrent; } };
}

test('context redacts tool results and assistant text, retaining tool linkage', async () => {
  const { context, calls } = await harness();
  const messages = [
    { role: 'toolResult', toolCallId: 'call_example', content: [{ type: 'text', text: 'SENSITIVE_TEST' }] },
    { role: 'assistant', content: [{ type: 'text', text: 'SENSITIVE_TEST' }] },
  ];
  const result = await context({ messages });
  assert.ok(result, 'tool output must be checked before a model request');
  assert.equal(result.messages[0].toolCallId, 'call_example');
  assert.equal(result.messages[0].content[0].text, '[removed]');
  assert.equal(result.messages[1].content[0].text, '[removed]');
  assert.ok(calls.length > 0);
  assert.equal(messages[0].content[0].text, 'SENSITIVE_TEST', 'saved history is not mutated');
});
test('structured tool arguments preserve safe sibling fields', async () => {
  const marker = ['-----', 'BEGIN', 'KEY', '-----'].join('');
  const { context } = await harness(text => ({ text: text.replace(marker, '[removed]'), found: 1 }));
  const result = await context({ messages: [{ role: 'assistant', content: [{
    type: 'toolCall',
    arguments: { pem: `${marker}\\ntruncated`, safe: 'keep-me' },
  }] }] });
  assert.equal(result.messages[0].content[0].arguments.pem, '[removed]\\ntruncated');
  assert.equal(result.messages[0].content[0].arguments.safe, 'keep-me');
});

test('long histories keep redaction child processes bounded and deduplicated', async () => {
  const h = await harness();
  const repeated = Array.from({ length: 32 }, () => ({ role: 'assistant', content: 'SENSITIVE_TEST_REPEAT' }));
  await h.context({ messages: repeated });
  assert.equal(h.calls.length, 1, 'identical text shares one in-flight hook');
  const messages = Array.from({ length: 32 }, (_, i) => ({ role: 'assistant', content: `SENSITIVE_TEST_${i}` }));
  await h.context({ messages });
  assert.ok(h.maxConcurrent <= 8, `started ${h.maxConcurrent} concurrent hooks`);
});



test('context preserves opaque blocks and cleans thinking and tool arguments', async () => {
  const { context } = await harness();
  const thinking = { type: 'thinking', thinking: 'SENSITIVE_TEST' };
  const signature = { type: 'thinking', thinking: 'safe', thinkingSignature: 'keep-signature' };
  const image = { type: 'image', data: 'opaque-image', mimeType: 'image/png' };
  const messages = [{ role: 'assistant', content: [thinking, image,
    { type: 'toolCall', id: 'call_saved', name: 'read', arguments: { nested: ['SENSITIVE_TEST'] } },
    signature,
  ] }];
  const out = await context({ messages });
  assert.equal(out.messages[0].content[0].thinking, '[removed]');
  assert.equal(out.messages[0].content[3], signature);
  assert.equal(out.messages[0].content[1], image);
  assert.equal(out.messages[0].content[2].id, 'call_saved');
  assert.equal(out.messages[0].content[2].arguments.nested[0], '[removed]');
});

test('invalid redactor output withholds text and is not cached', async () => {
  const { context, calls } = await harness(() => ({}));
  const messages = [{ role: 'toolResult', content: 'SENSITIVE_TEST' }];
  for (let i = 0; i < 2; i++) {
    const out = await context({ messages });
    assert.match(out.messages[0].content, /withheld by kepr/);
    assert.ok(!out.messages[0].content.includes('SENSITIVE_TEST'));
  }
  assert.equal(calls.length, 2);
});

test('unchanged context keeps placeholders and reuses successful checks', async () => {
  const { context, calls } = await harness();
  const messages = [{ role: 'user', content: 'kepr-ph-example' }];
  assert.equal(await context({ messages }), undefined);
  assert.equal(await context({ messages }), undefined);
  assert.equal(calls.length, 1);
});


test('signed thinking is never edited or sent unchecked', async () => {
  const { context } = await harness();
  const content = { type: 'thinking', thinking: 'SENSITIVE_TEST', thinkingSignature: 'opaque' };
  await assert.rejects(context({ messages: [{ role: 'assistant', content: [content] }] }), /signed reasoning/);
  assert.equal(content.thinking, 'SENSITIVE_TEST');
});
