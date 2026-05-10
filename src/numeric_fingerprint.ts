
import * as crypto from './crypto';

const VERSION = 0;


async function iterateHash(data: Buffer, key: Buffer, count: number): Promise<Buffer> {
    const combined = Buffer.from((new Uint8Array(Buffer.concat([data, key]))).buffer);
    const result = crypto.hash(combined);
    if (--count === 0) {
        return result;
    } else {
        return iterateHash(result, key, count);
    }
}


function shortToArrayBuffer(num: number): ArrayBuffer {
    return new Uint16Array([num]).buffer;
}

function getEncodedChunk(hash: Uint8Array, offset: number): string {
    const chunk = ( hash[offset]   * Math.pow(2,32) +
                  hash[offset+1] * Math.pow(2,24) +
                  hash[offset+2] * Math.pow(2,16) +
                  hash[offset+3] * Math.pow(2,8) +
                  hash[offset+4] ) % 100000;
    let s = chunk.toString();
    while (s.length < 5) {
        s = '0' + s;
    }
    return s;
}

async function getDisplayStringFor(identifier: Buffer, key: Buffer, iterations: number): Promise<string> {
    const bytes = Buffer.concat([
        Buffer.from(shortToArrayBuffer(VERSION)),
        key,
        identifier
    ]);
    const arraybuf = Buffer.from((new Uint8Array(bytes)).buffer);
    const output = new Uint8Array(await iterateHash(arraybuf, key, iterations));
    return getEncodedChunk(output, 0) +
        getEncodedChunk(output, 5) +
        getEncodedChunk(output, 10) +
        getEncodedChunk(output, 15) +
        getEncodedChunk(output, 20) +
        getEncodedChunk(output, 25);
}

export class FingerprintGenerator {
    iterations: number;

    constructor(iterations: number) {
        this.iterations = iterations;
    }

    createFor(localIdentifier: string, localIdentityKey: Buffer,
              remoteIdentifier: string, remoteIdentityKey: Buffer): Promise<string> {
        if (typeof localIdentifier !== 'string' ||
            typeof remoteIdentifier !== 'string' ||
            !(localIdentityKey instanceof Buffer) ||
            !(remoteIdentityKey instanceof Buffer)) {
            throw new Error('Invalid arguments');
        }

        return Promise.all([
            getDisplayStringFor(Buffer.from(localIdentifier), localIdentityKey, this.iterations),
            getDisplayStringFor(Buffer.from(remoteIdentifier), remoteIdentityKey, this.iterations)
        ]).then(function(fingerprints) {
            return fingerprints.sort().join('');
        });
    }
}
