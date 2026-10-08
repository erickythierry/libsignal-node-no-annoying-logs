import type { KeyPair } from './types';
export declare function getPublicFromPrivateKey(privKey: Buffer): Buffer;
export declare function generateKeyPair(): KeyPair;
export declare function calculateAgreement(pubKey: Buffer, privKey: Buffer): Buffer;
export declare function calculateSignature(privKey: Buffer, message: Buffer): Buffer;
export declare function verifySignature(pubKey: Buffer, msg: Buffer, sig: Buffer, isInit?: boolean): boolean;
/**
 * XEdDSA com o Ed25519 nativo do Node: ~0,1 ms contra ~6 ms do curve25519-js em JS puro.
 * A chave Montgomery vira Edwards com o bit de sinal que vem em sig[63], o mesmo que o curve25519-js faz.
 */
export declare function verifyNative(pubKey: Buffer, msg: Buffer, sig: Buffer): boolean;
