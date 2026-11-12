// Local JavaScript contract test. No browser, network, or VK requests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../internal/provider/vk/internal/captcha/manual/inject.js'), 'utf8');
function page(capturePow) {
  const requests = [];
  const context = {
    __ftpCaptcha: {local:'http://localhost:8765',upstream:'https://id.vk.ru',capturePow,powPath:'/local-captcha-pow/opaque'},
    document:{body:{style:{},append(){}},documentElement:{},querySelectorAll(){return []},addEventListener(){},createElement(){return {style:{},append(){}}}},
    navigator:{sendBeacon(){throw new Error('capture must not submit token')}},
    location:{protocol:'http:'},
    fetch(url, options){requests.push({url, options});return Promise.resolve({ok:true,clone(){return this},json(){return Promise.resolve({response:{success_token:'private-fixture-token'}})}})},
    XMLHttpRequest:class {open(){} send(){}}, HTMLFormElement:class {submit(){}},
    MutationObserver:class {observe(){}}, open(){},close(){},setTimeout(){},
    atob(s){return Buffer.from(s,'base64').toString('binary')},
  };
  context.window=context;
  vm.createContext(context);vm.runInContext(source,context);
  return {context,requests};
}
const encode = obj => 'v2.'+Buffer.from(JSON.stringify(obj)).toString('base64');
(async()=>{
 const {context,requests}=page(true);
 context.captchaPowResult=encode({hash:'',telemetry:{}});
 context.captchaPowResult=encode({hash:'0'.repeat(64),telemetry:{},error:'timeout'});
 context.captchaPowResult='malformed';
 assert.equal(requests.length,0,'intermediate or invalid assignment escaped');
 const final=encode({hash:'0'.repeat(64),nonce:1,telemetry:{},duration_ms:1});
 context.captchaPowResult=final;
 context.captchaPowResult=final;
 assert.equal(requests.length,1,'final envelope must be captured once');
 assert.equal(requests[0].url,'/local-captcha-pow/opaque');
 assert.equal(new URLSearchParams(requests[0].options.body).get('pow'),final);
 await context.fetch('https://api.vk.ru/method/captchaNotRobot.check');
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(requests.length,2,'capture path submitted a solver token');
 const manual=page(false);
 assert.equal(Object.getOwnPropertyDescriptor(manual.context,'captchaPowResult'),undefined,'legacy page was hooked');
 console.log('PASS: final assignment, intermediate/error filtering, one-shot capture, token separation, legacy mode');
})().catch(error=>{console.error(error.message);process.exitCode=1});
