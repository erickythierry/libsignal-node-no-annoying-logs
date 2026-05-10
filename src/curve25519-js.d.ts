declare module 'curve25519-js' {
    export function generateKeyPair(seed: Uint8Array | Buffer): { public: Uint8Array; private: Uint8Array };
    export function sharedKey(privKey: Uint8Array | Buffer, pubKey: Uint8Array | Buffer): Uint8Array;
    export function sign(privKey: Uint8Array | Buffer, message: Uint8Array | Buffer): Uint8Array;
    export function verify(pubKey: Uint8Array | Buffer, message: Uint8Array | Buffer, signature: Uint8Array | Buffer): boolean;
}
