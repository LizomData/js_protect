/**
 * Cocos2d 资源加密工具 (XXTEA + Deflate)
 *
 * 流程: 明文 → deflateRaw → XXTEA → base64 → 存到 ZIP
 * 运行时: ZIP → __res 字符串 → atob → XXTEA dec → 长度头 → inflateRaw → 明文
 *
 * 用法: node encrypt_res.js <输入HTML> [输出HTML]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const JSZip = require(path.join(__dirname, '..', 'jszip.min.js'));

const ZIP_MAGIC = Buffer.from([0x50, 0x4B, 0x03, 0x04]);

// ============ 字符串编码（隐藏关键字符串）============
function strExpr(str) {
  const xorKey = crypto.randomInt(30, 230);
  const codes = [];
  for (let i = 0; i < str.length; i++) {
    codes.push(str.charCodeAt(i) ^ xorKey);
  }
  return `[${codes.join(',')}].map(function(c){return String.fromCharCode(c^${xorKey})}).join("")`;
}

// ============ XXTEA 算法 ============

const DELTA = 0x9E3779B9;

function xxteaEncryptU32(data, key) {
  const n = data.length;
  if (n < 2) return data;
  let z = data[n - 1];
  let y;
  let sum = 0;
  let q = Math.floor(6 + 52 / n);

  while (q-- > 0) {
    sum = (sum + DELTA) >>> 0;
    const e = (sum >>> 2) & 3;
    let p;
    for (p = 0; p < n - 1; p++) {
      y = data[p + 1];
      const mx = (((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
      data[p] = (data[p] + mx) >>> 0;
      z = data[p];
    }
    y = data[0];
    const mx = (((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[((n - 1) & 3) ^ e] ^ z));
    data[n - 1] = (data[n - 1] + mx) >>> 0;
    z = data[n - 1];
  }
  return data;
}

function bytesToU32(bytes) {
  const len = bytes.length;
  const n = Math.ceil(len / 4);
  const u32 = new Uint32Array(n);
  for (let i = 0; i < len; i++) {
    u32[i >> 2] |= bytes[i] << ((i & 3) * 8);
  }
  return u32;
}

function u32ToBytes(u32, byteLen) {
  const bytes = Buffer.alloc(byteLen);
  for (let i = 0; i < byteLen; i++) {
    bytes[i] = (u32[i >> 2] >>> ((i & 3) * 8)) & 0xFF;
  }
  return bytes;
}

// CRC32 (poly 0xEDB88320, 标准实现)
let _crcTable = null;
function crc32(bytes) {
  if (!_crcTable) {
    _crcTable = new Int32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      _crcTable[i] = c;
    }
  }
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) crc = _crcTable[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// FNV-1a 32-bit (用于资源集合 hash)
function fnv32(str) {
  let h = 0x811c9dc5 | 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

// 完整加密：bytes → [4字节长度][4字节CRC32][明文][padding] → XXTEA → 输出
function xxteaEncrypt(bytes, key16) {
  const totalLen = 4 + 4 + bytes.length; // length + crc + data
  const padded = Math.max(8, Math.ceil(totalLen / 4) * 4);
  const buf = Buffer.alloc(padded);
  buf.writeUInt32LE(bytes.length, 0);
  buf.writeUInt32LE(crc32(bytes), 4);
  bytes.copy(buf, 8);
  const u32 = bytesToU32(buf);
  const keyU32 = bytesToU32(key16);
  xxteaEncryptU32(u32, keyU32);
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
// 64-bit 双 FNV-1a，输出 16 hex 字符（Node/浏览器一致）
function hashName(str) {
  let h1 = 0x811c9dc5 | 0;
  let h2 = 0xcbf29ce4 | 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h1 ^= c;          h1 = Math.imul(h1, 0x01000193);
    h2 ^= (c * 31)|0; h2 = Math.imul(h2, 0x9e3779b1);
  }
  return (h1 >>> 0).toString(16).padStart(8, '0') +
         (h2 >>> 0).toString(16).padStart(8, '0');
}

// 必须保留原名的文件（super_load/super_boot/super_reg_search 字面量匹配）
function shouldKeepOriginalName(name) {
  return name.startsWith('@')
      || /^index[a-zA-Z0-9.]*\.js$/.test(name)
      || /vconsole\.min/.test(name);
}

// ============ ZIP 检测 ============
function isZipBase64(b64Str) {
  if (!b64Str || b64Str.length < 8) return false;
  try {
    const buf = Buffer.from(b64Str.substring(0, 16), 'base64');
    return buf.length >= 4 && buf.slice(0, 4).equals(ZIP_MAGIC);
  } catch (e) {
    return false;
  }
}

// ============ 提取 HTML 中的 inline window.__res ============
function extractInlineRes(html) {
  const re = /window\s*(?:\.\s*__res|\[\s*['"]__res['"]\s*\])\s*=\s*\{/g;
  let m, best = null;
  while ((m = re.exec(html)) !== null) {
    const start = m.index + m[0].length - 1; // 指向 {
    let depth = 0, end = -1, inStr = false, esc = false, quote = null;
    for (let i = start; i < html.length; i++) {
      const ch = html[i];
      if (esc) { esc = false; continue; }
      if (inStr) {
        if (ch === '\\') { esc = true; continue; }
        if (ch === quote) { inStr = false; quote = null; }
        continue;
      }
      if (ch === '"' || ch === "'") { inStr = true; quote = ch; continue; }
      if (ch === '{') depth++;
      if (ch === '}') { depth--; if (depth === 0) { end = i + 1; break; } }
    }
    if (end < 0) continue;
    const objStr = html.substring(start, end);
    let obj;
    try { obj = new Function('return ' + objStr)(); } catch (e) { continue; }
    if (!obj || typeof obj !== 'object') continue;
    let trailEnd = end;
    while (trailEnd < html.length && /\s/.test(html[trailEnd])) trailEnd++;
    if (html[trailEnd] === ';') trailEnd++;
    const size = Object.keys(obj).length;
    if (!best || size > best.size) {
      best = { obj, fullStart: m.index, fullEnd: trailEnd, size };
    }
  }
  return best;
}

// ============ 暗桩（Canary）============
function genCanaries(count) {
  const canaries = [];
  for (let i = 0; i < count; i++) {
    canaries.push({ propName: '_$' + crypto.randomBytes(3).toString('hex'), value: crypto.randomInt(0x1000, 0xFFFF) });
  }
  return canaries;
}

// 解密器 IIFE 末尾设置暗桩变量
function genCanarySetterCode(canaries) {
  return canaries.map(c => `window[${strExpr(c.propName)}]=${c.value};`).join('');
}

// 暗桩检查代码（注入到 ZIP 内的 JS 文件）
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

// 在 JS 文件末尾追加暗桩检查（最安全的注入位置）
function injectCanaryCheck(jsCode, check) {
  return jsCode + ';\n' + check;
}

// ============ Proxy 解密器代码生成 ============
// 注意：依赖全局 pako（pako_inflate.min.js 之前已注入）
function genProxyDecoderCode(globalSecret, trapKeys, integrityInfo) {
  const sObject = strExpr('Object');
  const sDefProp = strExpr('defineProperty');
  const sFc = strExpr('fromCharCode');
  const sRes = strExpr('__res');
  const sValue = strExpr('value');
  const sWritable = strExpr('writable');
  const sCfg = strExpr('configurable');
  const sGet = strExpr('get');
  const sSet = strExpr('set');
  const sHas = strExpr('has');
  const sDelP = strExpr('deleteProperty');
  const sOwnKeys = strExpr('ownKeys');
  const sGetOwnPD = strExpr('getOwnPropertyDescriptor');
  const sPako = strExpr('pako');
  const sInflateRaw = strExpr('inflateRaw');

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

// 蜜罐 trap keys（XOR 编码隐藏）
var _trapSet=Object.create(null);
var _trapKeys=[${trapKeys.map(k => strExpr(k)).join(',')}];
for(var _ti=0;_ti<_trapKeys.length;_ti++)_trapSet[_trapKeys[_ti]]=true;

// 蜜罐炸弹
function _bomb(){
  var _s="";
  try{_s=new Array(1048577).join("\\x00");for(var _i=0;_i<1200;_i++)_s+=_s;}catch(_e){}
  return _s;
}

// 完整性校验
var _intExpectedCount=${integrityInfo.count};
var _intExpectedHash=${strExpr(integrityInfo.keysHash)};
var _intChecked=false;
var _integrityFailed=false;

// FNV-1a 32-bit
function _fnv32(str){
  var h=0x811c9dc5|0;
  for(var i=0;i<str.length;i++){h^=str.charCodeAt(i);h=Math.imul(h,0x01000193);}
  return (h>>>0).toString(16);
}

function _checkIntegrity(){
  if(_intChecked)return !_integrityFailed;
  _intChecked=true;
  var ks=Object.keys(_files);
  // 数量校验
  if(ks.length!==_intExpectedCount){_integrityFailed=true;return false;}
  // key 列表 hash 校验
  ks.sort();
  if(_fnv32(ks.join("|"))!==_intExpectedHash){_integrityFailed=true;return false;}
  return true;
}

// CRC32 (poly 0xEDB88320)
var _crcTable=null;
function _crc32(bytes){
  if(!_crcTable){
    _crcTable=new Int32Array(256);
    for(var i=0;i<256;i++){
      var c=i;
      for(var j=0;j<8;j++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);
      _crcTable[i]=c;
    }
  }
  var crc=0xFFFFFFFF;
  for(var i=0;i<bytes.length;i++)crc=_crcTable[(crc^bytes[i])&0xFF]^(crc>>>8);
  return (crc^0xFFFFFFFF)>>>0;
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

// 文件名 hash（与 encrypt 端 hashName 完全一致）
function _hashName(str){
  var h1=0x811c9dc5|0;
  var h2=0xcbf29ce4|0;
  for(var i=0;i<str.length;i++){
    var c=str.charCodeAt(i);
    h1^=c;h1=Math.imul(h1,0x01000193);
    h2^=(c*31)|0;h2=Math.imul(h2,0x9e3779b1);
  }
  var s1=(h1>>>0).toString(16);
  var s2=(h2>>>0).toString(16);
  while(s1.length<8)s1="0"+s1;
  while(s2.length<8)s2="0"+s2;
  return s1+s2;
}

var _DELTA=0x9E3779B9;
function _xxteaDec(data,key){
  var n=data.length;
  if(n<2)return data;
  var y=data[0],z;
  var q=Math.floor(6+52/n);
  var sum=(q*_DELTA)>>>0;
  while(sum!==0){
    var e=(sum>>>2)&3;
    var p;
    for(p=n-1;p>0;p--){
      z=data[p-1];
      var mx=(((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(key[(p&3)^e]^z));
      data[p]=(data[p]-mx)>>>0;
      y=data[p];
    }
    z=data[n-1];
    var mx=(((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(key[(0&3)^e]^z));
    data[0]=(data[0]-mx)>>>0;
    y=data[0];
    sum=(sum-_DELTA)>>>0;
  }
  return data;
}

function _bytesToU32(bytes){
  var n=Math.ceil(bytes.length/4);
  var u32=new Uint32Array(n);
  for(var i=0;i<bytes.length;i++){
    u32[i>>2]|=bytes[i]<<((i&3)*8);
  }
  return u32;
}

function _key16ToU32(buf){
  var u32=new Array(4);
  for(var i=0;i<4;i++){
    u32[i]=(buf[i*4])|(buf[i*4+1]<<8)|(buf[i*4+2]<<16)|(buf[i*4+3]<<24);
    u32[i]=u32[i]>>>0;
  }
  return u32;
}

// 文件解密：base64 → bytes → XXTEA → 去长度头 → inflateRaw → 字符串
function _decFile(b64,filename){
  var key16=_deriveKey(filename);
  var keyU32=_key16ToU32(key16);
  var bin=atob(b64);
  var bytes=new Uint8Array(bin.length);
  for(var i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);
  var u32=_bytesToU32(bytes);
  _xxteaDec(u32,keyU32);
  var decBytes=new Uint8Array(bytes.length);
  for(var i=0;i<bytes.length;i++){
    decBytes[i]=(u32[i>>2]>>>((i&3)*8))&0xFF;
  }
  // [4字节长度][4字节CRC32][压缩明文][padding]
  var origLen=decBytes[0]|(decBytes[1]<<8)|(decBytes[2]<<16)|(decBytes[3]<<24);
  origLen=origLen>>>0;
  var expectedCrc=(decBytes[4]|(decBytes[5]<<8)|(decBytes[6]<<16)|(decBytes[7]<<24))>>>0;
  if(origLen>decBytes.length-8)origLen=decBytes.length-8;
  var compressed=decBytes.subarray(8,8+origLen);
  // 校验 CRC32（密文被篡改 → CRC 不匹配）
  if(_crc32(compressed)!==expectedCrc){_integrityFailed=true;throw 0;}
  // inflateRaw → 字符串
  var pk=_W[${sPako}];
  return pk[${sInflateRaw}](compressed,{to:"string"});
}

// 合法调用方函数名（XOR 编码隐藏，不直接出现在源码里）
var _allowedNames=[
  ${strExpr('super_eval')},
  ${strExpr('super_boot')},
  ${strExpr('super_load')},
  ${strExpr('super_reg_search')},
  ${strExpr('getRes')},
  ${strExpr('super_html')}
];

var _handler={};

// 查找 _files：直接 → hash → 路径后缀逐级尝试 hash
// 返回 {v: 值, origName: 密钥派生用的原始文件名}
function _lookup(k){
  // 1. 直接查（@ 入口、inline 资源、__res 合并）
  var v=_files[k];
  if(v!==undefined&&v!==null)return {v:v,origName:k};
  // 2. 整体 hash 查
  v=_files[_hashName(k)];
  if(v!==undefined&&v!==null)return {v:v,origName:k};
  // 3. 路径后缀逐级 hash（处理 file:///full/path/application.js → application.js）
  var idx=0;
  while((idx=k.indexOf("/",idx+1))>0){
    var suffix=k.substring(idx+1);
    if(suffix.length>0){
      v=_files[_hashName(suffix)];
      if(v!==undefined&&v!==null)return {v:v,origName:suffix};
    }
  }
  return null;
}

_handler[${sGet}]=function(t,k){
  if(typeof k==="symbol")return undefined;
  // 蜜罐检测：trap key 被访问 → 直接炸弹
  if(typeof k==="string"&&(k in _trapSet)){return _bomb();}
  // 直接用 hash 值访问 → 返回密文不解密（合法代码永远用原名，用 hash 的只有攻击者）
  if(typeof k==="string"&&k.length===16&&(k in _files)){
    var _hx=true;
    for(var _ci=0;_ci<16;_ci++){var _cc=k.charCodeAt(_ci);if(!((_cc>=48&&_cc<=57)||(_cc>=97&&_cc<=102))){_hx=false;break;}}
    if(_hx)return _files[k];
  }
  var r=_lookup(k);
  if(!r)return undefined;
  var v=r.v;
  if(typeof v!=="string")return v;
  // 检查 magic prefix → 加密资源，否则原样返回（inline 明文直接放行）
  if(v.charCodeAt(0)!==7||v.charCodeAt(1)!==27||v.charCodeAt(2)!==14||v.charCodeAt(3)!==3)return v;
  // 完整性已失败 → 返回密文
  if(_integrityFailed)return v;
  // 栈帧检查：非合法调用方直接返回原密文（含 magic prefix），不解密
  var _stk="";
  try{throw new Error();}catch(_se){_stk=_se.stack||"";}
  var _sok=false;
  for(var _ai=0;_ai<_allowedNames.length;_ai++){if(_stk.indexOf(_allowedNames[_ai])>=0){_sok=true;break;}}
  if(!_sok)return v;
  // 首次解密前做集合校验
  if(!_intChecked&&!_checkIntegrity())return v;
  try{
    return _decFile(v.substring(4),r.origName);
  }catch(e){
    return v;
  }
};

_handler[${sSet}]=function(t,k,v){
  _files[k]=v;
  return true;
};

_handler[${sDelP}]=function(t,k){
  delete _files[k];
  return true;
};

_handler[${sHas}]=function(t,k){
  return !!_lookup(k);
};

_handler[${sOwnKeys}]=function(t){
  return Object.keys(_files);
};

_handler[${sGetOwnPD}]=function(t,k){
  if(k in _files)return {enumerable:true,configurable:true,value:undefined};
  return undefined;
};

var _proxy=new Proxy({},_handler);

try{
  var _desc={};
  _desc[${sGet}]=function(){return _proxy;};
  _desc[${sSet}]=function(v){
    // 拦截 window.__res = {...} 形式的 inline 赋值，把内容合并到 _files
    if(v&&typeof v==="object"&&v!==_proxy){
      try{
        var ks=Object.keys(v);
        for(var i=0;i<ks.length;i++){_files[ks[i]]=v[ks[i]];}
      }catch(e){}
    }
  };
  _desc[${sCfg}]=false;
  _dp(_W,${sRes},_desc);
}catch(e){
  _W[${sRes}]=_proxy;
}
})();`;
}

// ============ 主流程 ============

async function processHTML(inputPath, outputPath) {
  console.log('读取文件:', inputPath);
  let html = fs.readFileSync(inputPath, 'utf8');
  const origSize = Buffer.byteLength(html);

  // 提取并移除 HTML 中的 inline window.__res = {...}
  const inlineRes = extractInlineRes(html);
  if (inlineRes) {
    console.log(`发现 inline window.__res: ${inlineRes.size} 个资源 → 合并进 ZIP`);
    html = html.slice(0, inlineRes.fullStart) + 'window.__res={};' + html.slice(inlineRes.fullEnd);
  }

  const pattern = /(\s*;?\s*)(window\.\w+)\s*=\s*"([A-Za-z0-9+/=]{100,})"/g;
  let zipMatch = null;
  let m;
  while ((m = pattern.exec(html)) !== null) {
    if (isZipBase64(m[3])) { zipMatch = m; break; }
  }
  if (!zipMatch) {
    console.error('未找到 ZIP 容器变量！');
    return;
  }

  const [full, prefix, fullName, value] = zipMatch;
  console.log(`找到 ${fullName} (${(value.length / 1024).toFixed(1)}KB base64)`);

  const zipBytes = Buffer.from(value, 'base64');
  console.log(`ZIP 二进制: ${(zipBytes.length / 1024).toFixed(1)}KB`);

  console.log('解压 ZIP...');
  const zip = await JSZip.loadAsync(zipBytes);

  // 把 inline 资源合并进 zip 对象
  if (inlineRes) {
    let merged = 0;
    for (const [k, v] of Object.entries(inlineRes.obj)) {
      if (typeof v === 'string') {
        zip.file(k, v);
        merged++;
      }
    }
    console.log(`  合并 ${merged} 个 inline 资源到 ZIP`);
  }

  console.log(`全局密钥: ${GLOBAL_SECRET.toString('hex')}`);
  console.log('每个文件: deflateRaw → XXTEA(filename派生密钥) → base64');

  let fileCount = 0;
  let totalSize = 0;
  let totalEnc = 0;
  const newZip = new JSZip();
  const fileNames = Object.keys(zip.files);

  // 生成暗桩
  const CANARY_COUNT = crypto.randomInt(5, 9);
  const canaries = genCanaries(CANARY_COUNT);
  const canaryChecks = genCanaryChecks(canaries);
  let canaryIdx = 0; // 轮流分配到不同 JS 文件

  let hashedCount = 0;
  let keptCount = 0;
  let resExpanded = 0;
  let canaryInjected = 0;

  // 加密单个文件并加入 newZip
  function encryptAndAdd(name, contentBytes) {
    const keepName = shouldKeepOriginalName(name);
    const compressed = zlib.deflateRawSync(contentBytes, { level: 9 });
    const fileKey = deriveKey(GLOBAL_SECRET, name);
    const encrypted = xxteaEncrypt(compressed, fileKey);
    const b64 = '\x07\x1B\x0E\x03' + encrypted.toString('base64');
    totalEnc += b64.length;
    const zipKey = keepName ? name : hashName(name);
    newZip.file(zipKey, b64);
    if (keepName) keptCount++; else hashedCount++;
  }

  for (const name of fileNames) {
    const f = zip.files[name];
    if (f.dir) continue;
    const contentBytes = await f.async('nodebuffer');
    totalSize += contentBytes.length;

    // __res 是 JSON，拆成独立文件分别加密
    if (name === '__res') {
      try {
        const resObj = JSON.parse(contentBytes.toString('utf8'));
        const keys = Object.keys(resObj);
        for (const rk of keys) {
          const val = Buffer.from(resObj[rk], 'utf8');
          encryptAndAdd(rk, val);
          resExpanded++;
        }
        console.log(`  __res 拆解: ${keys.length} 个内联资源 → 独立加密`);
      } catch (e) {
        console.log('  __res 解析失败，整体加密:', e.message);
        encryptAndAdd(name, contentBytes);
      }
      fileCount++;
      continue;
    }

    fileCount++;
    // JS 文件：注入暗桩检查后再加密
    if (name.endsWith('.js') && canaryIdx < canaryChecks.length) {
      const jsCode = contentBytes.toString('utf8');
      if (jsCode.length > 500) { // 只对有一定体积的 JS 注入（太小的可能不安全）
        const modified = injectCanaryCheck(jsCode, canaryChecks[canaryIdx]);
        encryptAndAdd(name, Buffer.from(modified, 'utf8'));
        canaryIdx++;
        canaryInjected++;
        continue;
      }
    }
    encryptAndAdd(name, contentBytes);
  }

  console.log(`  暗桩: ${canaryInjected} 个检查点注入到 ZIP 内 JS 文件`);

  // 生成蜜罐 trap 文件（随机 hash 名 + 随机密文，混入 ZIP 中与真实文件无法区分）
  const TRAP_COUNT = crypto.randomInt(3, 6); // 3-5 个蜜罐
  const trapKeys = [];
  const existingKeys = new Set(Object.keys(newZip.files));
  for (let i = 0; i < TRAP_COUNT; i++) {
    let tk;
    do {
      tk = crypto.randomBytes(8).toString('hex'); // 16 hex chars，与真实 hash 格式一致
    } while (existingKeys.has(tk));
    existingKeys.add(tk);
    trapKeys.push(tk);
    // 伪造密文：magic prefix + 随机 base64（长度随机 200-2000 字节，看起来像真加密文件）
    const fakeLen = crypto.randomInt(200, 2000);
    const fakeContent = '\x07\x1B\x0E\x03' + crypto.randomBytes(fakeLen).toString('base64');
    newZip.file(tk, fakeContent);
  }
  console.log(`  蜜罐 trap 文件: ${trapKeys.length} 个`);

  console.log(`  文件名 hash: ${hashedCount} 个, 保留原名: ${keptCount} 个`);
  console.log(`加密了 ${fileCount} 个文件`);
  console.log(`原始: ${(totalSize / 1024).toFixed(1)}KB → 加密后(base64): ${(totalEnc / 1024).toFixed(1)}KB`);

  console.log('重新打包 ZIP...');
  const newZipBytes = await newZip.generateAsync({
    type: 'nodebuffer',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 },
  });
  console.log(`新 ZIP: ${(newZipBytes.length / 1024).toFixed(1)}KB`);

  const newB64 = newZipBytes.toString('base64');
  let output = html.slice(0, zipMatch.index)
    + prefix + fullName + ' = "' + newB64 + '"'
    + html.slice(zipMatch.index + full.length);

  // 注入 pako_inflate.min.js（独立块）
  const pakoSrc = fs.readFileSync(path.join(__dirname, '..', 'pako_inflate.min.js'), 'utf8');
  const pakoScript = `<script>${pakoSrc}<\/script>`;

  // 计算资源完整性信息
  const finalKeys = Object.keys(newZip.files).filter(n => !newZip.files[n].dir).sort();
  const integrityInfo = { count: finalKeys.length, keysHash: fnv32(finalKeys.join('|')) };
  console.log(`  完整性: 文件数=${integrityInfo.count}, keys hash=${integrityInfo.keysHash}`);

  // 生成解密器（末尾附加暗桩 setter）
  let decoderCode = genProxyDecoderCode(GLOBAL_SECRET, trapKeys, integrityInfo);
  const canarySetters = genCanarySetterCode(canaries);
  decoderCode = decoderCode.replace(/\}\)\(\);?\s*$/, canarySetters + '})();');

  // 交叉合并：解密器合并进包含 super_load 的游戏脚本块
  const scriptRegex = /<script([^>]*)>([\s\S]*?)<\/script>/gi;
  let scriptMatch;
  let targetIdx = -1, targetStart = -1, targetEnd = -1, targetAttrs = '', targetContent = '';
  while ((scriptMatch = scriptRegex.exec(output)) !== null) {
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

    const headEndIdx = output.indexOf('</head>');
    if (headEndIdx >= 0 && headEndIdx < targetIdx) {
      const beforeTarget = output.slice(0, headEndIdx) + pakoScript + output.slice(headEndIdx, targetStart);
      const afterTarget = output.slice(targetEnd);
      output = beforeTarget + `<script${targetAttrs}>` + merged + `<\/script>` + afterTarget;
    } else {
      output = output.slice(0, targetStart) + pakoScript + `<script${targetAttrs}>` + merged + `<\/script>` + output.slice(targetEnd);
    }
    console.log(`  合并完成，总块大小: ${(merged.length/1024).toFixed(1)}KB`);
  } else {
    console.log('  未找到 super_load 块，回退为独立注入');
    const proxyScript = `<script>${decoderCode}<\/script>`;
    const inject = pakoScript + proxyScript;
    const headEndIdx = output.indexOf('</head>');
    if (headEndIdx >= 0) {
      output = output.slice(0, headEndIdx) + inject + output.slice(headEndIdx);
    } else {
      output = inject + output;
    }
  }

  fs.writeFileSync(outputPath, output, 'utf8');
  console.log(`\n输出: ${outputPath}`);
  console.log(`大小: ${(origSize / 1024).toFixed(1)}KB → ${(Buffer.byteLength(output) / 1024).toFixed(1)}KB`);
  console.log('完成！');
}

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log('用法: node encrypt_res.js <输入HTML> [输出HTML]');
  console.log('');
  console.log('每个文件: deflateRaw → XXTEA(filename派生密钥) → base64');
  process.exit(1);
}

const inputFile = args[0];
const outputFile = args[1] || inputFile.replace('.html', '.encrypted.html');

console.log('========================================');
console.log('Cocos 资源加密 (Deflate + XXTEA + Proxy)');
console.log('========================================\n');

processHTML(inputFile, outputFile).catch(e => {
  console.error('错误:', e.message);
  console.error(e.stack);
});
