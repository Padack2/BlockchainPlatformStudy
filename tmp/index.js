import { secp256k1 } from '@noble/curves';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { bech32 } from '@scure/base';

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

function hash256(buffer) {
    return sha256(sha256(buffer));
}

function hash160(buffer) {
    return ripemd160(sha256(buffer));
}

function bitcoin(buffer) {
    const hash = hash160(buffer);
    return 
}