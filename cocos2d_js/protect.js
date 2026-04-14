#!/usr/bin/env node
/**
 * Cocos2d Playable Ad 一键加密混淆 CLI
 *
 * 等价于 tool.html 默认配置：
 *   1. 加密 Cocos2d 资源（deflate+XXTEA+hash+蜜罐+解密器VMP）
 *   2. 链接跳转保护（自动提取商店链接，10% 概率替换）
 *   3. JS 全混淆（轻度：变量重命名+压缩）
 *
 * 用法:
 *   node protect.js <输入HTML> [输出HTML] [选项]
 *
 * 选项:
 *   --no-vmp         关闭解密器 VMP
 *   --no-redirect    关闭链接跳转保护
 *   --no-obf         关闭 JS 混淆
 *   --redirect-url <URL>   手动指定保护链接（默认自动提取）
 *   --redirect-rate <0-100> 替换概率（默认 10）
 *   --obf-preset <low|medium|high> 混淆预设（默认 low）
 *
 * 示例:
 *   node protect.js game.html
 *   node protect.js game.html out.html --obf-preset medium
 *   node protect.js game.html --no-redirect --no-obf
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

// ============ 所有依赖从 protect.js 所在目录加载 ============
const _dir = __dirname;
const JSZip = require(path.join(_dir, 'jszip.min.js'));
const PAKO_INFLATE_SRC = fs.readFileSync(path.join(_dir, 'pako_inflate.min.js'), 'utf8');

let JavaScriptObfuscator;
try {
  global.self = global;
  global.window = global;
  const _obfMod = require(path.join(_dir, 'javascript-obfuscator.js'));
  JavaScriptObfuscator = _obfMod.JavaScriptObfuscator || _obfMod;
} catch (e) {}

// ============ 常量与配置 ============
const ZIP_MAGIC = Buffer.from([0x50, 0x4B, 0x03, 0x04]);
const DELTA = 0x9E3779B9;
const HEAVY_THRESHOLD = 500 * 1024;

const OBF_PRESETS = {
  low: {
    compact: true, simplify: true, target: 'browser',
    identifierNamesGenerator: 'hexadecimal',
    stringArray: false, stringArrayRotate: false, stringArrayShuffle: false,
    stringArrayCallsTransform: false, stringArrayIndexShift: false,
    stringArrayWrappersCount: 0, splitStrings: false,
    controlFlowFlattening: false, deadCodeInjection: false,
    debugProtection: false, disableConsoleOutput: false,
    selfDefending: false, numbersToExpressions: false,
    transformObjectKeys: false, unicodeEscapeSequence: false,
    renameGlobals: false, renameProperties: false, log: false,
  },
  medium: {
    compact: true, simplify: true, target: 'browser',
    identifierNamesGenerator: 'hexadecimal',
    stringArray: true, stringArrayThreshold: 0.75, stringArrayEncoding: ['rc4'],
    stringArrayRotate: true, stringArrayShuffle: true,
    stringArrayCallsTransform: true, stringArrayIndexShift: true,
    stringArrayWrappersCount: 1, stringArrayWrappersType: 'variable',
    stringArrayWrappersParametersMaxCount: 2,
    splitStrings: false, splitStringsChunkLength: 10,
    controlFlowFlattening: true, controlFlowFlatteningThreshold: 0.5,
    deadCodeInjection: true, deadCodeInjectionThreshold: 0.4,
    debugProtection: true, debugProtectionInterval: 4000,
    disableConsoleOutput: true, selfDefending: false,
    numbersToExpressions: false, transformObjectKeys: false,
    unicodeEscapeSequence: false,
    renameGlobals: false, renameProperties: false, log: false,
  },
  high: {
    compact: true, simplify: true, target: 'browser',
    identifierNamesGenerator: 'hexadecimal',
    stringArray: true, stringArrayThreshold: 1, stringArrayEncoding: ['rc4'],
    stringArrayRotate: true, stringArrayShuffle: true,
    stringArrayCallsTransform: true, stringArrayIndexShift: true,
    stringArrayWrappersCount: 2, stringArrayWrappersType: 'function',
    stringArrayWrappersParametersMaxCount: 4,
    splitStrings: true, splitStringsChunkLength: 5,
    controlFlowFlattening: true, controlFlowFlatteningThreshold: 0.75,
    deadCodeInjection: true, deadCodeInjectionThreshold: 0.4,
    numbersToExpressions: true, transformObjectKeys: true,
    unicodeEscapeSequence: true,
    debugProtection: true, debugProtectionInterval: 4000,
    disableConsoleOutput: true, selfDefending: false,
    renameGlobals: false, renameProperties: false, log: false,
  },
};

// ============ 工具函数 ============
function strExpr(str) {
  const xorKey = crypto.randomInt(30, 230);
  const codes = [];
  for (let i = 0; i < str.length; i++) codes.push(str.charCodeAt(i) ^ xorKey);
  return `[${codes.join(',')}].map(function(c){return String.fromCharCode(c^${xorKey})}).join("")`;
}

function rand(min, max) { return Math.floor(Math.random() * (max - min)) + min; }

// ============ 暗桩（Canary）============
function genCanaries(count) {
  const canaries = [];
  for (let i = 0; i < count; i++) canaries.push({ propName: '_$' + crypto.randomBytes(3).toString('hex'), value: crypto.randomInt(0x1000, 0xFFFF) });
  return canaries;
}
function genCanarySetterCode(canaries) {
  return canaries.map(c => `window[${strExpr(c.propName)}]=${c.value};`).join('');
}
function genCanaryChecks(canaries) {
  const checks = [];
  for (let i = 0; i < canaries.length; i++) {
    const c = canaries[i], p = strExpr(c.propName), d = crypto.randomInt(3000, 15000), t = i % 4;
    if (t === 0) checks.push(`setTimeout(function(){if(window[${p}]!==${c.value}){try{document.documentElement.innerHTML="";}catch(e){}}},${d});`);
    else if (t === 1) checks.push(`setTimeout(function(){if(window[${p}]!==${c.value}){try{location.href="about:blank";}catch(e){}}},${d});`);
    else if (t === 2) checks.push(`try{if(window[${p}]!==${c.value})throw 0;}catch(e){setTimeout(function(){try{document.body.innerHTML="";}catch(e){}},${d});}`);
    else checks.push(`setTimeout(function(){if(window[${p}]!==${c.value}){try{var _c=document.querySelector("canvas");if(_c)_c.getContext("2d").clearRect(0,0,99999,99999);}catch(e){}}},${d});`);
  }
  return checks;
}
function injectCanaryCheck(jsCode, check) {
  return jsCode + ';\n' + check;
}

// ============ XXTEA ============
function xxteaEncryptU32(data, key) {
  const n = data.length;
  if (n < 2) return data;
  let z = data[n - 1], y, sum = 0, q = Math.floor(6 + 52 / n);
  while (q-- > 0) {
    sum = (sum + DELTA) >>> 0;
    const e = (sum >>> 2) & 3;
    for (let p = 0; p < n - 1; p++) {
      y = data[p + 1];
      data[p] = (data[p] + ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))) >>> 0;
      z = data[p];
    }
    y = data[0];
    data[n - 1] = (data[n - 1] + ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[((n - 1) & 3) ^ e] ^ z)))) >>> 0;
    z = data[n - 1];
  }
  return data;
}
function bytesToU32(bytes) {
  const n = Math.ceil(bytes.length / 4), u32 = new Uint32Array(n);
  for (let i = 0; i < bytes.length; i++) u32[i >> 2] |= bytes[i] << ((i & 3) * 8);
  return u32;
}
function u32ToBytes(u32, bl) {
  const b = Buffer.alloc(bl);
  for (let i = 0; i < bl; i++) b[i] = (u32[i >> 2] >>> ((i & 3) * 8)) & 0xFF;
  return b;
}
function xxteaEncrypt(bytes, key16) {
  const tl = 4 + bytes.length, padded = Math.max(8, Math.ceil(tl / 4) * 4);
  const buf = Buffer.alloc(padded);
  buf.writeUInt32LE(bytes.length, 0);
  bytes.copy(buf, 4);
  const u32 = bytesToU32(buf), ku32 = bytesToU32(key16);
  xxteaEncryptU32(u32, ku32);
  return u32ToBytes(u32, padded);
}

// ============ 密钥派生 ============
const GLOBAL_SECRET = crypto.randomBytes(16);
function deriveKey(secretBytes, filename) {
  const buf = Buffer.alloc(16);
  secretBytes.copy(buf, 0);
  for (let i = 0; i < filename.length; i++) {
    const c = filename.charCodeAt(i);
    buf[i % 16] = (buf[i % 16] ^ c) & 0xFF;
    buf[(i + 1) % 16] = (buf[(i + 1) % 16] + (c * 7)) & 0xFF;
    buf[(i + 5) % 16] = (buf[(i + 5) % 16] ^ (c << 2)) & 0xFF;
  }
  for (let r = 0; r < 4; r++) {
    for (let i = 0; i < 16; i++) {
      buf[i] = (buf[i] + buf[(i + 7) % 16] * 13 + buf[(i + 3) % 16]) & 0xFF;
      buf[i] ^= (r * 17 + i * 31) & 0xFF;
    }
  }
  return buf;
}

// ============ 文件名 Hash ============
function hashName(str) {
  let h1 = 0x811c9dc5 | 0, h2 = 0xcbf29ce4 | 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h1 ^= c; h1 = Math.imul(h1, 0x01000193);
    h2 ^= (c * 31) | 0; h2 = Math.imul(h2, 0x9e3779b1);
  }
  return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
}
function shouldKeepOriginalName(name) {
  return name.startsWith('@')
    || /^index[a-zA-Z0-9.]*\.js$/.test(name)
    || /vconsole\.min/.test(name);
}

// ============ ZIP 检测 ============
function isZipBase64(b64) {
  if (!b64 || b64.length < 8) return false;
  try { const buf = Buffer.from(b64.substring(0, 16), 'base64'); return buf.length >= 4 && buf.slice(0, 4).equals(ZIP_MAGIC); } catch (e) { return false; }
}

// ============ 提取商店链接 ============
async function extractStoreUrl(html) {
  const urls = new Set();
  const re = /https?:\/\/(?:play\.google\.com\/store|apps\.apple\.com\/app|itms-apps:)[^\s'"<>)\\]+/g;
  let m;
  while ((m = re.exec(html)) !== null) urls.add(m[0]);
  // 搜索 ZIP 内
  try {
    const zm = html.match(/window\.\w+\s*=\s*"([A-Za-z0-9+/=]{100,})"/);
    if (zm) {
      const zb = Buffer.from(zm[1], 'base64');
      const z = await JSZip.loadAsync(zb);
      for (const name of Object.keys(z.files)) {
        const f = z.files[name];
        if (f.dir) continue;
        try {
          const c = await f.async('string');
          const re2 = /https?:\/\/(?:play\.google\.com\/store|apps\.apple\.com\/app|itms-apps:)[^\s'"<>)\\]+/g;
          let m2;
          while ((m2 = re2.exec(c)) !== null) urls.add(m2[0]);
        } catch (e) {}
      }
    }
  } catch (e) {}
  return [...urls];
}

// ============ Proxy 解密器生成（同 encrypt_res.js） ============
function genProxyDecoderCode(globalSecret, trapKeys) {
  const sObject = strExpr('Object'), sDefProp = strExpr('defineProperty'), sFc = strExpr('fromCharCode');
  const sRes = strExpr('__res'), sValue = strExpr('value'), sWritable = strExpr('writable');
  const sCfg = strExpr('configurable'), sGet = strExpr('get'), sSet = strExpr('set');
  const sHas = strExpr('has'), sDelP = strExpr('deleteProperty'), sOwnKeys = strExpr('ownKeys');
  const sGetOwnPD = strExpr('getOwnPropertyDescriptor');
  const sPako = strExpr('pako'), sInflateRaw = strExpr('inflateRaw');
  const xk = crypto.randomInt(50, 200);
  const secretEncoded = Array.from(globalSecret).map(b => b ^ xk);

  // 读取 encrypt_res.js 的运行时代码
  return fs.readFileSync(path.join(__dirname, 'encrypt_res.js'), 'utf8')
    .match(/return `\n([\s\S]*?)`;/)[1]
    // 不行，太脆弱。直接内联生成。
    ? '' : '';
}
// 实际上直接复用 encrypt_res.js 的 genProxyDecoderCode
// 通过 require 方式不行因为 encrypt_res.js 是 CLI 脚本
// 所以直接把生成逻辑写在这里

function genDecoderCode(globalSecret, trapKeys) {
  const sObject = strExpr('Object'), sDefProp = strExpr('defineProperty'), sFc = strExpr('fromCharCode');
  const sRes = strExpr('__res'), sCfg = strExpr('configurable');
  const sGet = strExpr('get'), sSet = strExpr('set'), sHas = strExpr('has');
  const sDelP = strExpr('deleteProperty'), sOwnKeys = strExpr('ownKeys');
  const sGetOwnPD = strExpr('getOwnPropertyDescriptor');
  const sPako = strExpr('pako'), sInflateRaw = strExpr('inflateRaw');
  const xk = crypto.randomInt(50, 200);
  const secretEncoded = Array.from(globalSecret).map(b => b ^ xk);

  return `
;(function(){
var _W=window;
var _O=_W[${sObject}];
var _dp=_O[${sDefProp}];
var _S=String;
var _fc=_S[${sFc}];
var _gs=[${secretEncoded.join(',')}].map(function(c){return c^${xk};});
var _files=Object.create(null);

var _trapSet=Object.create(null);
var _trapKeys=[${trapKeys.map(k => strExpr(k)).join(',')}];
for(var _ti=0;_ti<_trapKeys.length;_ti++)_trapSet[_trapKeys[_ti]]=true;

function _bomb(){
  var _s="";
  try{_s=new Array(1048577).join("\\x00");for(var _i=0;_i<1200;_i++)_s+=_s;}catch(_e){}
  return _s;
}

function _deriveKey(filename){
  var buf=new Array(16);
  for(var i=0;i<16;i++)buf[i]=_gs[i];
  for(var i=0;i<filename.length;i++){
    var c=filename.charCodeAt(i);
    buf[i%16]=(buf[i%16]^c)&0xFF;
    buf[(i+1)%16]=(buf[(i+1)%16]+(c*7))&0xFF;
    buf[(i+5)%16]=(buf[(i+5)%16]^(c<<2))&0xFF;
  }
  for(var r=0;r<4;r++){
    for(var i=0;i<16;i++){
      buf[i]=(buf[i]+buf[(i+7)%16]*13+buf[(i+3)%16])&0xFF;
      buf[i]^=(r*17+i*31)&0xFF;
    }
  }
  return buf;
}

function _hashName(str){
  var h1=0x811c9dc5|0;var h2=0xcbf29ce4|0;
  for(var i=0;i<str.length;i++){
    var c=str.charCodeAt(i);
    h1^=c;h1=Math.imul(h1,0x01000193);
    h2^=(c*31)|0;h2=Math.imul(h2,0x9e3779b1);
  }
  var s1=(h1>>>0).toString(16);var s2=(h2>>>0).toString(16);
  while(s1.length<8)s1="0"+s1;while(s2.length<8)s2="0"+s2;
  return s1+s2;
}

var _DELTA=0x9E3779B9;
function _xxteaDec(data,key){
  var n=data.length;if(n<2)return data;
  var y=data[0],z;var q=Math.floor(6+52/n);var sum=(q*_DELTA)>>>0;
  while(sum!==0){
    var e=(sum>>>2)&3;var p;
    for(p=n-1;p>0;p--){z=data[p-1];var mx=(((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(key[(p&3)^e]^z));data[p]=(data[p]-mx)>>>0;y=data[p];}
    z=data[n-1];var mx=(((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(key[(0&3)^e]^z));data[0]=(data[0]-mx)>>>0;y=data[0];
    sum=(sum-_DELTA)>>>0;
  }
  return data;
}
function _bytesToU32(bytes){var n=Math.ceil(bytes.length/4);var u32=new Uint32Array(n);for(var i=0;i<bytes.length;i++)u32[i>>2]|=bytes[i]<<((i&3)*8);return u32;}
function _key16ToU32(buf){var u32=new Array(4);for(var i=0;i<4;i++){u32[i]=(buf[i*4])|(buf[i*4+1]<<8)|(buf[i*4+2]<<16)|(buf[i*4+3]<<24);u32[i]=u32[i]>>>0;}return u32;}

function _decFile(b64,filename){
  var key16=_deriveKey(filename);var keyU32=_key16ToU32(key16);
  var bin=atob(b64);var bytes=new Uint8Array(bin.length);
  for(var i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);
  var u32=_bytesToU32(bytes);_xxteaDec(u32,keyU32);
  var decBytes=new Uint8Array(bytes.length);
  for(var i=0;i<bytes.length;i++)decBytes[i]=(u32[i>>2]>>>((i&3)*8))&0xFF;
  var origLen=decBytes[0]|(decBytes[1]<<8)|(decBytes[2]<<16)|(decBytes[3]<<24);
  origLen=origLen>>>0;if(origLen>decBytes.length-4)origLen=decBytes.length-4;
  var compressed=decBytes.subarray(4,4+origLen);
  var pk=_W[${sPako}];
  return pk[${sInflateRaw}](compressed,{to:"string"});
}

var _allowedNames=[${strExpr('super_eval')},${strExpr('super_boot')},${strExpr('super_load')},${strExpr('super_reg_search')},${strExpr('getRes')},${strExpr('super_html')}];

function _lookup(k){
  var v=_files[k];if(v!==undefined&&v!==null)return {v:v,origName:k};
  v=_files[_hashName(k)];if(v!==undefined&&v!==null)return {v:v,origName:k};
  var idx=0;
  while((idx=k.indexOf("/",idx+1))>0){var suffix=k.substring(idx+1);if(suffix.length>0){v=_files[_hashName(suffix)];if(v!==undefined&&v!==null)return {v:v,origName:suffix};}}
  return null;
}

var _handler={};

_handler[${sGet}]=function(t,k){
  if(typeof k==="symbol")return undefined;
  if(typeof k==="string"&&(k in _trapSet)){return _bomb();}
  if(typeof k==="string"&&k.length===16&&(k in _files)){
    var _hx=true;for(var _ci=0;_ci<16;_ci++){var _cc=k.charCodeAt(_ci);if(!((_cc>=48&&_cc<=57)||(_cc>=97&&_cc<=102))){_hx=false;break;}}
    if(_hx)return _files[k];
  }
  var r=_lookup(k);if(!r)return undefined;
  var v=r.v;if(typeof v!=="string")return v;
  if(v.charCodeAt(0)!==7||v.charCodeAt(1)!==27||v.charCodeAt(2)!==14||v.charCodeAt(3)!==3)return v;
  var _stk="";try{throw new Error();}catch(_se){_stk=_se.stack||"";}
  var _sok=false;for(var _ai=0;_ai<_allowedNames.length;_ai++){if(_stk.indexOf(_allowedNames[_ai])>=0){_sok=true;break;}}
  if(!_sok)return v;
  try{return _decFile(v.substring(4),r.origName);}catch(e){return v;}
};

_handler[${sSet}]=function(t,k,v){_files[k]=v;return true;};
_handler[${sDelP}]=function(t,k){delete _files[k];return true;};
_handler[${sHas}]=function(t,k){return !!_lookup(k);};
_handler[${sOwnKeys}]=function(t){return Object.keys(_files);};
_handler[${sGetOwnPD}]=function(t,k){if(k in _files)return {enumerable:true,configurable:true,value:undefined};return undefined;};

var _proxy=new Proxy({},_handler);
try{
  var _desc={};
  _desc[${sGet}]=function(){return _proxy;};
  _desc[${sSet}]=function(v){if(v&&typeof v==="object"&&v!==_proxy){try{var ks=Object.keys(v);for(var i=0;i<ks.length;i++){_files[ks[i]]=v[ks[i]];}}catch(e){}}};
  _desc[${sCfg}]=false;
  _dp(_W,${sRes},_desc);
}catch(e){_W[${sRes}]=_proxy;}
})();`;
}

// ============ 链接跳转保护 ============
function genRedirectCode(targetUrl, rate) {
  const sOpen = strExpr('open'), sAssign = strExpr('assign'), sReplace = strExpr('replace');
  const sHref = strExpr('href'), sInstall = strExpr('install'), sLocation = strExpr('location');
  const sMraid = strExpr('mraid'), sCreate = strExpr('createElement'), sClick = strExpr('click');
  const sAddEvent = strExpr('addEventListener'), sDefProp = strExpr('defineProperty');
  const sUrl = strExpr(targetUrl);
  const rateCheck = rate >= 100 ? 'true' : `(Math.random()*100<${rate})`;

  return `
;(function(){
var _W=window;var _D=document;var _U=${sUrl};
function _pick(u){if(typeof u!=="string"||u===_U)return u;return ${rateCheck}?_U:u;}
var _origOpen=_W[${sOpen}];
_W[${sOpen}]=function(u){return _origOpen.call(_W,_pick(u));};
try{var _loc=_W[${sLocation}];var _origAssign=_loc[${sAssign}].bind(_loc);var _origReplace=_loc[${sReplace}].bind(_loc);
_loc[${sAssign}]=function(u){return _origAssign(_pick(u));};_loc[${sReplace}]=function(u){return _origReplace(_pick(u));};
try{var _locProto=Object.getPrototypeOf(_loc);var _hrefDesc=Object.getOwnPropertyDescriptor(_locProto,${sHref});
if(_hrefDesc&&_hrefDesc.set){var _origHrefSet=_hrefDesc.set;Object[${sDefProp}](_locProto,${sHref},{get:_hrefDesc.get,set:function(u){_origHrefSet.call(this,_pick(u));},configurable:true,enumerable:true});}}catch(e){}
}catch(e){}
function _hookMraid(){try{var _m=_W[${sMraid}];if(_m&&_m[${sOpen}]){var _orig=_m[${sOpen}].bind(_m);_m[${sOpen}]=function(u){return _orig(_pick(u));};}}catch(e){}}
_hookMraid();var _mi=setInterval(function(){_hookMraid();},200);setTimeout(function(){clearInterval(_mi);},10000);
try{var _installVal=_W[${sInstall}];Object[${sDefProp}](_W,${sInstall},{get:function(){return _installVal;},set:function(v){if(typeof v==="function"){var _o=v;_installVal=function(){return _o.call(_W);};}else{_installVal=v;}},configurable:true});}catch(e){}
_D[${sAddEvent}](${sClick},function(e){var t=e.target;while(t&&t.tagName!=="A")t=t.parentElement;if(t&&t.tagName==="A"&&t.href){e.preventDefault();e.stopPropagation();_origOpen.call(_W,_pick(t.href));}},true);
var _origCreate=_D[${sCreate}].bind(_D);_D[${sCreate}]=function(tag){var el=_origCreate(tag);if(tag&&tag.toLowerCase()==="a"){try{Object[${sDefProp}](el,${sHref},{get:function(){return _U;},set:function(v){},configurable:true,enumerable:true});}catch(e){}}return el;};
})();`;
}

// ============ JS 混淆 ============
function extractScripts(html) {
  const regex = /<script([^>]*)>([\s\S]*?)<\/script>/gi;
  let match, lastIndex = 0;
  const parts = [];
  while ((match = regex.exec(html)) !== null) {
    parts.push({ type: 'html', content: html.slice(lastIndex, match.index) });
    parts.push({ type: 'script', attrs: match[1], content: match[2] });
    lastIndex = match.index + match[0].length;
  }
  parts.push({ type: 'html', content: html.slice(lastIndex) });
  return parts;
}

function obfuscateCode(code, cfg, sizeBytes) {
  let useCfg = Object.assign({}, cfg);
  if (sizeBytes && sizeBytes > HEAVY_THRESHOLD) {
    useCfg.controlFlowFlattening = false;
    useCfg.controlFlowFlatteningThreshold = 0;
    useCfg.deadCodeInjection = false;
    useCfg.deadCodeInjectionThreshold = 0;
  }
  try {
    return JavaScriptObfuscator.obfuscate(code, useCfg).getObfuscatedCode();
  } catch (e) {
    try { return JavaScriptObfuscator.obfuscate(code, OBF_PRESETS.low).getObfuscatedCode(); } catch (e2) { return null; }
  }
}

function obfuscateHtml(html, cfg) {
  const parts = extractScripts(html);
  const scriptCount = parts.filter(p => p.type === 'script').length;
  console.log(`  找到 ${scriptCount} 个 script 标签`);
  let si = 0;
  const processed = [];
  for (const part of parts) {
    if (part.type === 'html') { processed.push(part.content); continue; }
    si++;
    const cleanAttrs = (part.attrs || '').replace(/\s*data-(vendor|vmp)="1"/g, '');
    const trimmed = part.content.trim();
    if (trimmed.length < 5) { processed.push(`<script${cleanAttrs}>${part.content}<\/script>`); continue; }
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) { processed.push(`<script${cleanAttrs}>${part.content}<\/script>`); continue; }
    if (/data-vendor="1"/.test(part.attrs || '')) { console.log(`  [${si}] 跳过（vendor）`); processed.push(`<script${cleanAttrs}>${part.content}<\/script>`); continue; }
    if (/data-vmp="1"/.test(part.attrs || '')) { console.log(`  [${si}] 跳过（已VMP）`); processed.push(`<script${cleanAttrs}>${part.content}<\/script>`); continue; }
    const sizeKB = (part.content.length / 1024).toFixed(1);
    console.log(`  [${si}] 混淆中 (${sizeKB}KB)...`);
    const result = obfuscateCode(part.content, cfg, part.content.length);
    if (result) {
      console.log(`  [${si}] 完成`);
      processed.push(`<script${cleanAttrs}>${result}<\/script>`);
    } else {
      console.log(`  [${si}] 失败，保留原文`);
      processed.push(`<script${cleanAttrs}>${part.content}<\/script>`);
    }
  }
  return processed.join('');
}

// ============ 主流程 ============
async function main() {
  // 解析参数
  const args = process.argv.slice(2);
  const flags = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--no-vmp') flags.noVmp = true;
    else if (args[i] === '--no-redirect') flags.noRedirect = true;
    else if (args[i] === '--no-obf') flags.noObf = true;
    else if (args[i] === '--redirect-url' && args[i + 1]) flags.redirectUrl = args[++i];
    else if (args[i] === '--redirect-rate' && args[i + 1]) flags.redirectRate = parseInt(args[++i]);
    else if (args[i] === '--obf-preset' && args[i + 1]) flags.obfPreset = args[++i];
    else positional.push(args[i]);
  }

  if (positional.length === 0) {
    console.log('用法: node protect.js <输入HTML> [输出HTML] [选项]');
    console.log('');
    console.log('选项:');
    console.log('  --no-vmp              关闭解密器 VMP');
    console.log('  --no-redirect         关闭链接跳转保护');
    console.log('  --no-obf              关闭 JS 混淆');
    console.log('  --redirect-url <URL>  手动指定保护链接（默认自动提取）');
    console.log('  --redirect-rate <N>   替换概率 0-100（默认 10）');
    console.log('  --obf-preset <P>      混淆预设 low|medium|high（默认 low）');
    console.log('');
    console.log('示例:');
    console.log('  node protect.js game.html');
    console.log('  node protect.js game.html out.html --obf-preset medium');
    console.log('  node protect.js game.html --no-redirect --no-obf');
    process.exit(1);
  }

  const inputFile = positional[0];
  const outputFile = positional[1] || inputFile.replace(/\.html?$/i, '.protected.html');
  const useVmp = !flags.noVmp;
  const useRedirect = !flags.noRedirect;
  const useObf = !flags.noObf;
  const redirectRate = flags.redirectRate ?? 10;
  const obfPreset = flags.obfPreset || 'low';

  console.log('========================================');
  console.log('Cocos2d Playable Ad 一键加密保护');
  console.log('========================================\n');
  console.log('输入:', inputFile);
  console.log('配置: 资源加密=ON  VMP=' + (useVmp ? 'ON' : 'OFF') + '  跳转保护=' + (useRedirect ? 'ON' : 'OFF') + '  JS混淆=' + (useObf ? obfPreset : 'OFF'));
  console.log('');

  let html = fs.readFileSync(inputFile, 'utf8');
  const origSize = Buffer.byteLength(html);

  // ========== 步骤 1: 加密资源 ==========
  console.log('=== 步骤 1: 加密 Cocos2d 资源 ===');

  const pattern = /(\s*;?\s*)(window\.\w+)\s*=\s*"([A-Za-z0-9+/=]{100,})"/g;
  let zipMatch = null, m;
  while ((m = pattern.exec(html)) !== null) {
    if (isZipBase64(m[3])) { zipMatch = m; break; }
  }
  if (!zipMatch) { console.log('  未找到 ZIP 容器，跳过资源加密'); }
  else {
    const [full, prefix, fullName, value] = zipMatch;
    console.log(`  找到 ${fullName} (${(value.length / 1024).toFixed(1)}KB)`);
    const zipBytes = Buffer.from(value, 'base64');
    const zip = await JSZip.loadAsync(zipBytes);
    console.log(`  全局密钥: ${GLOBAL_SECRET.toString('hex')}`);

    // 生成暗桩
    const CANARY_COUNT = crypto.randomInt(5, 9);
    const canaries = genCanaries(CANARY_COUNT);
    const canaryChecks = genCanaryChecks(canaries);
    let canaryIdx = 0, canaryInjected = 0;

    let fileCount = 0, totalSize = 0, totalEnc = 0, hashedCount = 0, keptCount = 0;
    const newZip = new JSZip();
    const fileNames = Object.keys(zip.files);

    function encryptAndAdd(name, contentBytes) {
      const keepName = shouldKeepOriginalName(name);
      const compressed = zlib.deflateRawSync(contentBytes, { level: 9 });
      const fileKey = deriveKey(GLOBAL_SECRET, name);
      const encrypted = xxteaEncrypt(compressed, fileKey);
      const b64 = '\x07\x1B\x0E\x03' + encrypted.toString('base64');
      totalEnc += b64.length;
      newZip.file(keepName ? name : hashName(name), b64);
      if (keepName) keptCount++; else hashedCount++;
    }

    for (const name of fileNames) {
      const f = zip.files[name];
      if (f.dir) continue;
      const contentBytes = await f.async('nodebuffer');
      totalSize += contentBytes.length;
      if (name === '__res') {
        try {
          const resObj = JSON.parse(contentBytes.toString('utf8'));
          const keys = Object.keys(resObj);
          for (const rk of keys) encryptAndAdd(rk, Buffer.from(resObj[rk], 'utf8'));
          console.log(`  __res 拆解: ${keys.length} 个内联资源`);
        } catch (e) { encryptAndAdd(name, contentBytes); }
        fileCount++;
        continue;
      }
      fileCount++;
      // JS 文件注入暗桩后再加密
      if (name.endsWith('.js') && canaryIdx < canaryChecks.length && contentBytes.length > 500) {
        const modified = injectCanaryCheck(contentBytes.toString('utf8'), canaryChecks[canaryIdx]);
        encryptAndAdd(name, Buffer.from(modified, 'utf8'));
        canaryIdx++;
        canaryInjected++;
        continue;
      }
      encryptAndAdd(name, contentBytes);
    }

    console.log(`  暗桩: ${canaryInjected} 个检查点注入到 ZIP 内 JS 文件`);

    // 蜜罐
    const trapKeys = [];
    const TRAP_COUNT = crypto.randomInt(3, 6);
    const existingKeys = new Set(Object.keys(newZip.files));
    for (let i = 0; i < TRAP_COUNT; i++) {
      let tk;
      do { tk = crypto.randomBytes(8).toString('hex'); } while (existingKeys.has(tk));
      existingKeys.add(tk);
      trapKeys.push(tk);
      newZip.file(tk, '\x07\x1B\x0E\x03' + crypto.randomBytes(crypto.randomInt(200, 2000)).toString('base64'));
    }
    console.log(`  蜜罐: ${trapKeys.length} 个  hash: ${hashedCount}  保留原名: ${keptCount}`);
    console.log(`  加密 ${fileCount} 个文件: ${(totalSize / 1024).toFixed(1)}KB → ${(totalEnc / 1024).toFixed(1)}KB`);

    const newZipBytes = await newZip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE', compressionOptions: { level: 6 } });
    const newB64 = newZipBytes.toString('base64');
    html = html.slice(0, zipMatch.index) + prefix + fullName + ' = "' + newB64 + '"' + html.slice(zipMatch.index + full.length);

    // 生成解密器（末尾附加暗桩 setter）
    let decoderCode = genDecoderCode(GLOBAL_SECRET, trapKeys);
    const canarySetters = genCanarySetterCode(canaries);
    decoderCode = decoderCode.replace(/\}\)\(\);?\s*$/, canarySetters + '})();');

    // 解密器先 VMP (high)
    if (useVmp && JavaScriptObfuscator) {
      console.log('  解密器 VMP (high) 中...');
      try {
        decoderCode = JavaScriptObfuscator.obfuscate(decoderCode, OBF_PRESETS.high).getObfuscatedCode();
        console.log(`  VMP 完成 (${(decoderCode.length / 1024).toFixed(1)}KB)`);
      } catch (e) { console.log('  VMP 失败:', e.message); }
    }

    // 交叉合并：VMP 后的解密器合并进 super_load 块
    const pakoSrc = PAKO_INFLATE_SRC;
    const pakoScript = `<script data-vendor="1">${pakoSrc}<\/script>`;

    const scriptRegex = /<script([^>]*)>([\s\S]*?)<\/script>/gi;
    let scriptMatch;
    let targetIdx = -1, targetStart = -1, targetEnd = -1, targetAttrs = '', targetContent = '';
    while ((scriptMatch = scriptRegex.exec(html)) !== null) {
      if (scriptMatch[2].indexOf('super_load') >= 0) {
        targetIdx = scriptMatch.index;
        targetStart = scriptMatch.index;
        targetEnd = scriptMatch.index + scriptMatch[0].length;
        targetAttrs = scriptMatch[1];
        targetContent = scriptMatch[2];
        break;
      }
    }

    if (targetIdx >= 0) {
      const merged = decoderCode + ';\n' + targetContent;
      console.log(`  交叉合并: 解密器 (${(decoderCode.length/1024).toFixed(1)}KB) + super_load 块 (${(targetContent.length/1024).toFixed(1)}KB)`);

      const headEndIdx = html.indexOf('</head>');
      if (headEndIdx >= 0 && headEndIdx < targetIdx) {
        const beforeTarget = html.slice(0, headEndIdx) + pakoScript + html.slice(headEndIdx, targetStart);
        const afterTarget = html.slice(targetEnd);
        html = beforeTarget + `<script${targetAttrs}>` + merged + `<\/script>` + afterTarget;
      } else {
        html = html.slice(0, targetStart) + pakoScript + `<script${targetAttrs}>` + merged + `<\/script>` + html.slice(targetEnd);
      }
      console.log('  合并完成');
    } else {
      console.log('  未找到 super_load 块，回退为独立注入');
      const inject = pakoScript + `<script>${decoderCode}<\/script>`;
      const headEndIdx = html.indexOf('</head>');
      if (headEndIdx >= 0) html = html.slice(0, headEndIdx) + inject + html.slice(headEndIdx);
      else html = inject + html;
    }
    console.log('  资源加密完成');
  }

  // ========== 步骤 2: 链接跳转保护 ==========
  if (useRedirect) {
    console.log('\n=== 步骤 2: 链接跳转保护 ===');
    let redirectUrl = flags.redirectUrl;
    if (!redirectUrl) {
      const found = await extractStoreUrl(fs.readFileSync(inputFile, 'utf8'));
      if (found.length > 0) {
        redirectUrl = found[0];
        console.log(`  自动提取: ${redirectUrl}`);
      }
    }
    if (redirectUrl) {
      if (!/^https?:\/\//i.test(redirectUrl)) redirectUrl = 'https://' + redirectUrl;
      console.log(`  保护链接: ${redirectUrl}  概率: ${redirectRate}%`);
      const hookCode = genRedirectCode(redirectUrl, redirectRate);
      const hookScript = `<script>${hookCode}<\/script>`;
      const bodyMatch = html.match(/<body[^>]*>/i);
      if (bodyMatch) {
        const idx = bodyMatch.index + bodyMatch[0].length;
        html = html.slice(0, idx) + hookScript + html.slice(idx);
      } else {
        html = hookScript + html;
      }
      console.log('  跳转保护注入完成');
    } else {
      console.log('  未找到商店链接，跳过');
    }
  }

  // ========== 步骤 3: JS 全混淆 ==========
  if (useObf) {
    if (!JavaScriptObfuscator) {
      console.log('\n=== 步骤 3: JS 全混淆（跳过：javascript-obfuscator 未找到）===');
    } else {
      console.log(`\n=== 步骤 3: JS 全混淆 (${obfPreset}) ===`);
      const cfg = OBF_PRESETS[obfPreset] || OBF_PRESETS.low;
      html = obfuscateHtml(html, cfg);
      console.log('  混淆完成');
    }
  }

  // ========== 输出 ==========
  fs.writeFileSync(outputFile, html, 'utf8');
  const newSize = Buffer.byteLength(html);
  console.log(`\n输出: ${outputFile}`);
  console.log(`大小: ${(origSize / 1024).toFixed(1)}KB → ${(newSize / 1024).toFixed(1)}KB`);
  console.log('完成！');
}

main().catch(e => { console.error('错误:', e.message); console.error(e.stack); });
