const fs = require('fs');
const util = require('util');
const readdir = util.promisify(fs.readdir);
const readFile = util.promisify(fs.readFile);
var nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');
const {
  decodeUTF8,
  encodeUTF8,
  encodeBase64,
  decodeBase64
} = nacl.util;

const newNonce = () => nacl.randomBytes(nacl.box.nonceLength);
 const generateKeyPair = () => nacl.box.keyPair();

 async function getFile(file) {
  let data;
  try {
      data = await readFile(file);
  } catch (err) {
      console.log('Panna: ',err);
  }
  if (data === undefined) {
      return []
  } else {
      // data= JSON.parse(data);
      // console.log(data);
      return data
  }
}

 const encrypt = (
  secretOrSharedKey,
  json,
  key
) => {
  const nonce = newNonce();
  const messageUint8 = decodeUTF8(JSON.stringify(json));
  const encrypted = key
    ? box(messageUint8, nonce, key, secretOrSharedKey)
    : nacl.box.after(messageUint8, nonce, secretOrSharedKey);

  const fullMessage = new Uint8Array(nonce.length + encrypted.length);
  fullMessage.set(nonce);
  fullMessage.set(encrypted, nonce.length);

  const base64FullMessage = encodeBase64(fullMessage);
  return base64FullMessage;
};

 const decrypt = (
  secretOrSharedKey,
  messageWithNonce,
  key
) => {
  const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
  const nonce = messageWithNonceAsUint8Array.slice(0, nacl.box.nonceLength);
  const message = messageWithNonceAsUint8Array.slice(
    nacl.box.nonceLength,
    messageWithNonce.length
  );

  const decrypted = key
    ? nacl.box.open(message, nonce, key, secretOrSharedKey)
    : nacl.box.open.after(message, nonce, secretOrSharedKey);

  if (!decrypted) {
    throw new Error('Could not decrypt message');
  }

  const base64DecryptedMessage = encodeUTF8(decrypted);
  return JSON.parse(base64DecryptedMessage);
};
async function MainMethod() {
const obj = await getFile('testdata.medolo');
// console.log(obj);
// fs.writeFile(`./decrypted/sample.medolo`,obj, 'utf8', (data)=>{
//   console.log('file written', data)
// });
const pairA = generateKeyPair();
const pairB = generateKeyPair();
const sharedA = nacl.box.before(pairB.publicKey, pairA.secretKey);
const sharedB = nacl.box.before(pairA.publicKey, pairB.secretKey);
const encrypted = encrypt(sharedA, obj.toString('utf8'));
await fs.writeFile(`./encrypted/testdata.medolo`,encrypted, 'utf8', (data)=>{
});
const obj2 = await getFile('./encrypted/testdata.medolo');
// const decrypted =  await decrypt(sharedB, encrypted);
const decrypted =  await decrypt(sharedB, obj2.toString('utf8'));
// console.log(decrypted, typeof decrypted);
// console.log(obj2.toString(), typeof obj2.toString());
// decrypt = new Buffer(decrypted.data);
fs.writeFileSync(`./decrypted/testdata.medolo`,decrypted, 'utf8', (data)=>{});
console.log(obj, encrypted, decrypted);
}

MainMethod();




