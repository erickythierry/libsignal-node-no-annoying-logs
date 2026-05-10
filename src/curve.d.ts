import type { KeyPair } from './types';
export declare function getPublicFromPrivateKey(privKey: Buffer): Buffer;
export declare function generateKeyPair(): KeyPair;
export declare function calculateAgreement(pubKey: Buffer, privKey: Buffer): Buffer;
export declare function calculateSignature(privKey: Buffer, message: Buffer): Buffer;
export declare function verifySignature(pubKey: Buffer, msg: Buffer, sig: Buffer, isInit?: boolean): boolean;
