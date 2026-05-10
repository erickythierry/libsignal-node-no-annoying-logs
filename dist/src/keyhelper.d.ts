import * as curve from './curve';
import type { KeyPair, PreKeyPair, SignedPreKeyPair } from './types';
export declare const generateIdentityKeyPair: typeof curve.generateKeyPair;
export declare function generateRegistrationId(): number;
export declare function generateSignedPreKey(identityKeyPair: KeyPair, signedKeyId: number): SignedPreKeyPair;
export declare function generatePreKey(keyId: number): PreKeyPair;
