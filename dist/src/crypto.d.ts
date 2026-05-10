export declare function encrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer;
export declare function decrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer;
export declare function calculateMAC(key: Buffer, data: Buffer): Buffer;
export declare function hash(data: Buffer): Buffer;
export declare function deriveSecrets(input: Buffer, salt: Buffer, info: Buffer, chunks?: number): Buffer[];
export declare function verifyMAC(data: Buffer, key: Buffer, mac: Buffer, length: number): void;
