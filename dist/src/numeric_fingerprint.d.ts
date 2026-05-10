export declare class FingerprintGenerator {
    iterations: number;
    constructor(iterations: number);
    createFor(localIdentifier: string, localIdentityKey: Buffer, remoteIdentifier: string, remoteIdentityKey: Buffer): Promise<string>;
}
