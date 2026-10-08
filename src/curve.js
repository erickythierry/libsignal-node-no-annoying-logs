'use strict';
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPublicFromPrivateKey = getPublicFromPrivateKey;
exports.generateKeyPair = generateKeyPair;
exports.calculateAgreement = calculateAgreement;
exports.calculateSignature = calculateSignature;
exports.verifySignature = verifySignature;
exports.verifyNative = verifyNative;
const curveJs = __importStar(require("curve25519-js"));
const nodeCrypto = __importStar(require("crypto"));
// from: https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/lib/crypto.js
const PUBLIC_KEY_DER_PREFIX = Buffer.from([
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);
const PRIVATE_KEY_DER_PREFIX = Buffer.from([
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);
const KEY_BUNDLE_TYPE = Buffer.from([5]);
const prefixKeyInPublicKey = function (pubKey) {
    return Buffer.concat([KEY_BUNDLE_TYPE, pubKey]);
};
function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}
function scrubPubKeyFormat(pubKey) {
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key type: ${pubKey.constructor.name}`);
    }
    if (pubKey === undefined || ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength == 33) {
        return pubKey.slice(1);
    }
    else {
        // console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
        return pubKey;
    }
}
function unclampEd25519PrivateKey(clampedSk) {
    const unclampedSk = new Uint8Array(clampedSk);
    // Fix the first byte
    unclampedSk[0] |= 6; // Ensure last 3 bits match expected `110` pattern
    // Fix the last byte
    unclampedSk[31] |= 128; // Restore the highest bit
    unclampedSk[31] &= ~64; // Clear the second-highest bit
    return unclampedSk;
}
function getPublicFromPrivateKey(privKey) {
    const unclampedPK = unclampEd25519PrivateKey(privKey);
    const keyPair = curveJs.generateKeyPair(unclampedPK);
    return prefixKeyInPublicKey(Buffer.from(keyPair.public));
}
function generateKeyPair() {
    try {
        const { publicKey: publicDerBytes, privateKey: privateDerBytes } = nodeCrypto.generateKeyPairSync('x25519', {
            publicKeyEncoding: { format: 'der', type: 'spki' },
            privateKeyEncoding: { format: 'der', type: 'pkcs8' }
        });
        const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length, PUBLIC_KEY_DER_PREFIX.length + 32);
        const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);
        return {
            pubKey: prefixKeyInPublicKey(pubKey),
            privKey
        };
    }
    catch (e) {
        const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32));
        return {
            privKey: Buffer.from(keyPair.private),
            pubKey: prefixKeyInPublicKey(Buffer.from(keyPair.public)),
        };
    }
}
function calculateAgreement(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    if (typeof nodeCrypto.diffieHellman === 'function') {
        const nodePrivateKey = nodeCrypto.createPrivateKey({
            key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
            format: 'der',
            type: 'pkcs8'
        });
        const nodePublicKey = nodeCrypto.createPublicKey({
            key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
            format: 'der',
            type: 'spki'
        });
        return nodeCrypto.diffieHellman({
            privateKey: nodePrivateKey,
            publicKey: nodePublicKey,
        });
    }
    else {
        const secret = curveJs.sharedKey(privKey, pubKey);
        return Buffer.from(secret);
    }
}
function calculateSignature(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    // curve25519-js@0.0.4 declara opt_random como obrigatório no seu .d.ts upstream.
    // Passamos 64 bytes de aleatoriedade do crypto do Node (XEdDSA randomizado).
    // Sem isso, consumidores que compilam este .ts diretamente quebram com TS2554.
    return Buffer.from(curveJs.sign(privKey, message, nodeCrypto.randomBytes(64)));
}
function verifySignature(pubKey, msg, sig, isInit) {
    pubKey = scrubPubKeyFormat(pubKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    if (isInit) {
        return true;
    }
    // o nativo só confirma; se recusar ou lançar, a decisão é do curve25519-js (rejeição idêntica à de antes)
    return verifyNative(pubKey, msg, sig) || curveJs.verify(pubKey, msg, sig);
}
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
// BigInt() no lugar de literal 1n: o WSocket compila este arquivo com target ES2018
const B0 = BigInt(0);
const B1 = BigInt(1);
const B8 = BigInt(8);
const B255 = BigInt(255);
const BYTE = BigInt(0xff);
const FIELD_P = (B1 << B255) - BigInt(19);
const MAX_CACHED_ED_KEYS = 10000;
const edKeyCache = new Map();
function modPow(base, exp) {
    let result = B1;
    base %= FIELD_P;
    while (exp > B0) {
        if (exp & B1) {
            result = (result * base) % FIELD_P;
        }
        base = (base * base) % FIELD_P;
        exp >>= B1;
    }
    return result;
}
/** y de Edwards = (u - 1) / (u + 1) mod p, como o convertPublicKey do curve25519-js (inverso de 0 é 0) */
function montgomeryToEdwards(u) {
    let x = B0;
    for (let i = 31; i >= 0; i--) {
        x = (x << B8) | BigInt(u[i]);
    }
    x = (x & ((B1 << B255) - B1)) % FIELD_P;
    let y = (((x - B1 + FIELD_P) % FIELD_P) * modPow(x + B1, FIELD_P - BigInt(2))) % FIELD_P;
    const out = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
        out[i] = Number(y & BYTE);
        y >>= B8;
    }
    return out;
}
/**
 * XEdDSA com o Ed25519 nativo do Node: ~0,1 ms contra ~6 ms do curve25519-js em JS puro.
 * A chave Montgomery vira Edwards com o bit de sinal que vem em sig[63], o mesmo que o curve25519-js faz.
 */
function verifyNative(pubKey, msg, sig) {
    try {
        const signBit = sig[63] & 0x80;
        const cacheKey = pubKey.toString('base64') + signBit;
        let key = edKeyCache.get(cacheKey);
        if (!key) {
            const edPub = montgomeryToEdwards(pubKey);
            edPub[31] |= signBit;
            key = nodeCrypto.createPublicKey({
                key: Buffer.concat([ED25519_SPKI_PREFIX, edPub]),
                format: 'der',
                type: 'spki'
            });
            if (edKeyCache.size >= MAX_CACHED_ED_KEYS) {
                edKeyCache.clear();
            }
            edKeyCache.set(cacheKey, key);
        }
        const edSig = Buffer.from(sig);
        edSig[63] &= 0x7f;
        return nodeCrypto.verify(null, msg, key, edSig);
    }
    catch {
        return false;
    }
}
