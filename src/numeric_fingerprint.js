"use strict";
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
exports.FingerprintGenerator = void 0;
const crypto = __importStar(require("./crypto"));
const VERSION = 0;
async function iterateHash(data, key, count) {
    let current = data;
    while (count > 0) {
        const combined = Buffer.from((new Uint8Array(Buffer.concat([current, key]))).buffer);
        current = crypto.hash(combined);
        count--;
    }
    return current;
}
function shortToArrayBuffer(num) {
    return new Uint16Array([num]).buffer;
}
function getEncodedChunk(hash, offset) {
    const chunk = (hash[offset] * Math.pow(2, 32) +
        hash[offset + 1] * Math.pow(2, 24) +
        hash[offset + 2] * Math.pow(2, 16) +
        hash[offset + 3] * Math.pow(2, 8) +
        hash[offset + 4]) % 100000;
    let s = chunk.toString();
    while (s.length < 5) {
        s = '0' + s;
    }
    return s;
}
async function getDisplayStringFor(identifier, key, iterations) {
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
class FingerprintGenerator {
    constructor(iterations) {
        this.iterations = iterations;
    }
    createFor(localIdentifier, localIdentityKey, remoteIdentifier, remoteIdentityKey) {
        if (typeof localIdentifier !== 'string' ||
            typeof remoteIdentifier !== 'string' ||
            !(localIdentityKey instanceof Buffer) ||
            !(remoteIdentityKey instanceof Buffer)) {
            throw new Error('Invalid arguments');
        }
        return Promise.all([
            getDisplayStringFor(Buffer.from(localIdentifier), localIdentityKey, this.iterations),
            getDisplayStringFor(Buffer.from(remoteIdentifier), remoteIdentityKey, this.iterations)
        ]).then(function (fingerprints) {
            return fingerprints.sort().join('');
        });
    }
}
exports.FingerprintGenerator = FingerprintGenerator;
