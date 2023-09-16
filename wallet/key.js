import crypto from 'crypto';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
// import secret from './secret.json' assert { type: "json" };
import Mnemonic from 'bitcore-mnemonic';

// 블록체인 계산에는 정수만 씀.
// 범위가 무한함.
// 8비트 char 16비트 short 32비트 int 64비트 long
// 블록체인에선 256 bit(32 bytes) 사용
function createPrivateKey() {
    let privateKey;
    do {
        privateKey = crypto.randomBytes(32);
    } while (secp256k1.utils.isValidPrivateKey(privateKey) === false);
    return privateKey;
}

function createPublicKey(privateKey, compressed) {
    return secp256k1.getPublicKey(privateKey, compressed);
}

// keccak 압축 이후 이후 20Bytes 남은 해시 4Bytes로 체크섬 주소 생성
function toChecksumAddress (address) {
    address = address.toLowerCase().replace('0x', '');
    let hash = toHex(keccak_256(address));
    let ret = '0x';
  
    for (let i = 0; i < address.length; i++) {
      if (parseInt(hash[i], 16) >= 8) {
        ret += address[i].toUpperCase();
      } else {
        ret += address[i];
      }
    }
  
    return ret;
}

// 압축하지 않은 공개 키는 X좌표 32Bytes, Y좌표 32Bytes
// Hash에 0x를 붙이고 앞 12Bytes 를 잘라내어 20Bytes로 만듦
function createAddress(publicKey) {
    const hash = keccak_256(publicKey.slice(1));
    return '0x' + bytesToHex(hash.slice(12));
}

function createMnemonic() {
    return new Mnemonic(128);
} 

function mnemonicToPrivateKey(mnemonic) {
    const privateKey = mnemonic.toHDPrivateKey().derive("m/44'/60'/0'/0/0").privateKey;
    return Buffer.from(privateKey.toString(), 'hex');
} 

const mnemonic = createMnemonic();
// const privateKey = createPrivateKey();
// const privateKey = Buffer.from(secret.privateKey, 'hex');
const privateKey = mnemonicToPrivateKey(mnemonic);
const publicKey = createPublicKey(privateKey, false);
const address = createAddress(publicKey);

console.log('mnemonic: ', mnemonic.toString());
console.log('privateKey: ', bytesToHex(privateKey));
console.log('publicKey: ', bytesToHex(publicKey));
console.log('address: ', address)