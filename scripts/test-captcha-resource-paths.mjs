import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const local = 'http://localhost:8765';
const upstream = 'https://id.vk.ru';
// Offline regression: run the injected script against browser API fixtures.
const project = 'https://st.vk.ru/vkid/vkid-bff/dist/projects/notRobotCaptcha-web/';
const calls = [];
class Form { submit() {} }
class Xhr { open() {} send() {} addEventListener() {} }
const context = {
  URL, Request, Response, Blob, Promise, console,
  btoa: value => Buffer.from(value, 'binary').toString('base64'),
  atob: value => Buffer.from(value, 'base64').toString('binary'),
  __ftpCaptcha: { local, upstream }, location: { protocol: 'http:' },
  navigator: {}, setTimeout: () => {},
  HTMLFormElement: Form, XMLHttpRequest: Xhr,
  MutationObserver: class { observe() {} },
  document: { body: { style: {}, append() {} }, documentElement: {}, querySelectorAll: () => [], addEventListener() {}, createElement: () => ({ style: {}, append() {} }) },
  fetch: async value => { calls.push(value); return new Response('{}', { headers: { 'Content-Type': 'application/json' } }); },
  open: value => value,
};
context.window = context;
vm.runInNewContext(readFileSync(new URL('../internal/provider/vk/internal/captcha/manual/inject.js', import.meta.url), 'utf8'), context);
await context.fetch(project + 'entrypoints/entry.243b7a49.js');
const entry = new URL(calls.pop(), local);
assert.ok(entry.pathname.startsWith('/local-captcha-resource/'));
const publicPath = new URL('../', new URL('.', entry));
const decode = uri => {
  const value = new URL(uri, local);
  const [origin, ...parts] = value.pathname.slice('/local-captcha-resource/'.length).split('/');
  return Buffer.from(origin, 'base64url').toString() + '/' + parts.join('/') + value.search;
};
for (const name of ['chunks/js/iui_subapp.a79f2d53.js', 'chunks/js/394.e400a060.js', 'chunks/css/iui_subapp.f2b1747b.css']) {
  assert.equal(decode(new URL(name + '?cache-bust=true&retry-attempt=2', publicPath)), project + name + '?cache-bust=true&retry-attempt=2');
}
const font = new URL('../../fonts/400latin.woff2', new URL('chunks/css/main.css', publicPath));
assert.equal(decode(font), project + 'fonts/400latin.woff2');
await context.fetch('//st.vk.ru/vkid/entry.js');
assert.equal(decode(calls.pop()), 'https://st.vk.ru/vkid/entry.js');
await context.fetch(new Request('https://api.vk.ru/method/offlineFixture', { method: 'POST', body: 'fixture=value', headers: { 'X-Fixture': 'preserved' } }));
const request = calls.pop();
assert.equal(decode(request.url), 'https://api.vk.ru/method/offlineFixture');
assert.equal(request.method, 'POST');
assert.equal(request.headers.get('X-Fixture'), 'preserved');
assert.equal(await request.text(), 'fixture=value');
const broken = new URL('chunks/js/394.e400a060.js', new URL('../', new URL('.', local + '/generic_proxy?proxy_url=' + encodeURIComponent(project + 'entrypoints/entry.243b7a49.js'))));
assert.equal(broken.pathname, '/chunks/js/394.e400a060.js');
console.log('PASS: CDN publicPath, chunks, CSS fonts, HTTPS and fetch(Request)');
