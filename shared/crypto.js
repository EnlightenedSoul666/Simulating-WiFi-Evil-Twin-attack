// shared/crypto.js
const crypto = require('crypto');
function genEd25519(){ return crypto.generateKeyPairSync('ed25519',{ publicKeyEncoding:{type:'spki',format:'pem'}, privateKeyEncoding:{type:'pkcs8',format:'pem'} }); }
function genX25519(){ return crypto.generateKeyPairSync('x25519',{ publicKeyEncoding:{type:'spki',format:'pem'}, privateKeyEncoding:{type:'pkcs8',format:'pem'} }); }
function signEd25519(priv, data){ return crypto.sign(null, data, priv).toString('base64'); }
function verifyEd25519(pub, data, sig){ try{ return crypto.verify(null, data, pub, Buffer.from(sig,'base64')); }catch{ return false; } }
function deriveSharedX25519(myPrivPem, theirPubPem){ const myPriv=crypto.createPrivateKey(myPrivPem); const theirPub=crypto.createPublicKey(theirPubPem); return crypto.diffieHellman({ privateKey: myPriv, publicKey: theirPub }); }
function hkdf(km, salt=Buffer.alloc(0), info=Buffer.alloc(0), len=32){ return crypto.hkdfSync('sha256', km, salt, info, len); }
function encryptGCM(plaintext,key32,aad=null){ const iv=crypto.randomBytes(12); const c=crypto.createCipheriv('aes-256-gcm',key32,iv); if(aad)c.setAAD(aad); const ct=Buffer.concat([c.update(Buffer.from(plaintext,'utf8')),c.final()]); const tag=c.getAuthTag(); return { iv:iv.toString('base64'), ct:ct.toString('base64'), tag:tag.toString('base64')}; }
function decryptGCM(enc,key32,aad=null){ const iv=Buffer.from(enc.iv,'base64'); const ct=Buffer.from(enc.ct,'base64'); const tag=Buffer.from(enc.tag,'base64'); const d=crypto.createDecipheriv('aes-256-gcm',key32,iv); if(aad)d.setAAD(aad); d.setAuthTag(tag); const pt=Buffer.concat([d.update(ct),d.final()]); return pt.toString('utf8'); }
module.exports={ genEd25519,genX25519,signEd25519,verifyEd25519,deriveSharedX25519,hkdf,encryptGCM,decryptGCM };
