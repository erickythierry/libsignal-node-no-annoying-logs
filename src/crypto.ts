// vim: ts=4:sw=4

'use strict';

import * as nodeCrypto from 'crypto';
import assert from 'assert';


function assertBuffer(value: unknown): Buffer {
    if (!(value instanceof Buffer)) {
        const ctorName = (value as any)?.constructor?.name ?? typeof value;
        throw TypeError(`Expected Buffer instead of: ${ctorName}`);
    }
    return value;
}


export function encrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}


export function decrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
}


export function calculateMAC(key: Buffer, data: Buffer): Buffer {
    assertBuffer(key);
    assertBuffer(data);
    const hmac = nodeCrypto.createHmac('sha256', key);
    hmac.update(data);
    return Buffer.from(hmac.digest());
}


export function hash(data: Buffer): Buffer {
    assertBuffer(data);
    const sha512 = nodeCrypto.createHash('sha512');
    sha512.update(data);
    return sha512.digest();
}


// Salts always end up being 32 bytes
export function deriveSecrets(input: Buffer, salt: Buffer, info: Buffer, chunks?: number): Buffer[] {
    // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
    assertBuffer(input);
    assertBuffer(salt);
    assertBuffer(info);
    if (salt.byteLength != 32) {
        throw new Error("Got salt of incorrect length");
    }
    chunks = chunks || 3;
    assert(chunks >= 1 && chunks <= 3);
    const PRK = calculateMAC(salt, input);
    const infoArray = new Uint8Array(info.byteLength + 1 + 32);
    infoArray.set(info, 32);
    infoArray[infoArray.length - 1] = 1;
    // Views sobre o mesmo ArrayBuffer — evita cópias por chunk.
    // firstView ignora os 32 bytes iniciais (zerados) na primeira iteração;
    // fullView usa o buffer inteiro nas iterações seguintes (após sobrescrever
    // os 32 bytes iniciais com o hash anterior via infoArray.set).
    const firstView = Buffer.from(infoArray.buffer, infoArray.byteOffset + 32, infoArray.byteLength - 32);
    const fullView = Buffer.from(infoArray.buffer, infoArray.byteOffset, infoArray.byteLength);
    const signed: Buffer[] = [calculateMAC(PRK, firstView)];
    if (chunks > 1) {
        infoArray.set(signed[signed.length - 1]);
        infoArray[infoArray.length - 1] = 2;
        signed.push(calculateMAC(PRK, fullView));
    }
    if (chunks > 2) {
        infoArray.set(signed[signed.length - 1]);
        infoArray[infoArray.length - 1] = 3;
        signed.push(calculateMAC(PRK, fullView));
    }
    return signed;
}

export function verifyMAC(data: Buffer, key: Buffer, mac: Buffer, length: number): void {
    const calculatedMac = calculateMAC(key, data).slice(0, length);
    if (mac.length !== length || calculatedMac.length !== length) {
        throw new Error("Bad MAC length");
    }
    if (!nodeCrypto.timingSafeEqual(mac, calculatedMac)) {
        throw new Error("Bad MAC");
    }
}
