// vim: ts=4:sw=4:expandtab

import { ChainType } from './chain_type';
import ProtocolAddress from './protocol_address';
import SessionBuilder from './session_builder';
import SessionRecord = require('./session_record');
type SessionEntry = SessionRecord.Entry;
import * as crypto from './crypto';
import * as curve from './curve';
import * as errors from './errors';
import * as protobufs from './protobufs';
import queueJob from './queue_job';
import type { Chain, EncryptedMessage, KeyPair, SignalStorage } from './types';

const VERSION = 3;

// Constantes reutilizadas em encrypt/decrypt/fillMessageKeys/calculateRatchet.
// Como buffers nunca são mutados pelas APIs que os recebem aqui,
// é seguro compartilhar uma única instância por módulo (reduz GC).
const EMPTY_SALT_32 = Buffer.alloc(32);
const INFO_WHISPER_MSG_KEYS = Buffer.from("WhisperMessageKeys");
const INFO_WHISPER_RATCHET = Buffer.from("WhisperRatchet");
const MSG_KEY_SEED = Buffer.from([1]);
const CHAIN_KEY_SEED = Buffer.from([2]);

function assertBuffer(value: unknown): Buffer {
    if (!(value instanceof Buffer)) {
        const ctorName = (value as any)?.constructor?.name ?? typeof value;
        throw TypeError(`Expected Buffer instead of: ${ctorName}`);
    }
    return value;
}


class SessionCipher {

    addr: ProtocolAddress;
    storage: SignalStorage;

    constructor(storage: SignalStorage, protocolAddress: ProtocolAddress) {
        if (!(protocolAddress instanceof ProtocolAddress)) {
            throw new TypeError("protocolAddress must be a ProtocolAddress");
        }
        this.addr = protocolAddress;
        this.storage = storage;
    }

    _encodeTupleByte(number1: number, number2: number): number {
        if (number1 > 15 || number2 > 15) {
            throw TypeError("Numbers must be 4 bits or less");
        }
        return (number1 << 4) | number2;
    }

    _decodeTupleByte(byte: number): [number, number] {
        return [byte >> 4, byte & 0xf];
    }

    toString(): string {
        return `<SessionCipher(${this.addr.toString()})>`;
    }

    async getRecord(): Promise<SessionRecord | undefined> {
        const record = await this.storage.loadSession(this.addr.toString());
        if (record && !(record instanceof SessionRecord)) {
            throw new TypeError('SessionRecord type expected from loadSession');
        }
        return record as SessionRecord | undefined;
    }

    async storeRecord(record: SessionRecord): Promise<void> {
        record.removeOldSessions();
        await this.storage.storeSession(this.addr.toString(), record);
    }

    async queueJob<T>(awaitable: () => T | Promise<T>): Promise<T> {
        return await queueJob(this.addr.toString(), awaitable);
    }

    async encrypt(data: Buffer): Promise<EncryptedMessage> {
        assertBuffer(data);
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (!record) {
                throw new errors.SessionError("No sessions");
            }
            const session = record.getOpenSession();
            if (!session) {
                throw new errors.SessionError("No open session");
            }
            const remoteIdentityKey = session.indexInfo.remoteIdentityKey;
            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
            }
            const ourIdentityKey = await this.storage.getOurIdentity();
            const chain = session.getChain(session.currentRatchet.ephemeralKeyPair.pubKey);
            if (!chain) {
                throw new errors.SessionError("No chain for current ephemeral key");
            }
            if (chain.chainType === ChainType.RECEIVING) {
                throw new Error("Tried to encrypt on a receiving chain");
            }
            this.fillMessageKeys(chain, chain.chainKey.counter + 1);
            const keys = crypto.deriveSecrets(chain.messageKeys[chain.chainKey.counter],
                                              EMPTY_SALT_32, INFO_WHISPER_MSG_KEYS);
            delete chain.messageKeys[chain.chainKey.counter];
            const msg = protobufs.WhisperMessage.create();
            msg.ephemeralKey = session.currentRatchet.ephemeralKeyPair.pubKey;
            msg.counter = chain.chainKey.counter;
            msg.previousCounter = session.currentRatchet.previousCounter;
            msg.ciphertext = crypto.encrypt(keys[0], data, keys[2].slice(0, 16));
            const msgBuf = protobufs.WhisperMessage.encode(msg).finish();
            const macInput = Buffer.alloc(msgBuf.byteLength + (33 * 2) + 1);
            macInput.set(ourIdentityKey.pubKey);
            macInput.set(session.indexInfo.remoteIdentityKey, 33);
            macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION);
            macInput.set(msgBuf, (33 * 2) + 1);
            const mac = crypto.calculateMAC(keys[1], macInput);
            const result = Buffer.alloc(msgBuf.byteLength + 9);
            result[0] = this._encodeTupleByte(VERSION, VERSION);
            result.set(msgBuf, 1);
            result.set(mac.slice(0, 8), msgBuf.byteLength + 1);
            await this.storeRecord(record);
            let type: 1 | 3;
            let body: Buffer;
            if (session.pendingPreKey) {
                type = 3;  // prekey bundle
                const preKeyMsg = protobufs.PreKeyWhisperMessage.create({
                    identityKey: ourIdentityKey.pubKey,
                    registrationId: await this.storage.getOurRegistrationId(),
                    baseKey: session.pendingPreKey.baseKey,
                    signedPreKeyId: session.pendingPreKey.signedKeyId,
                    message: result
                });
                if (session.pendingPreKey.preKeyId) {
                    preKeyMsg.preKeyId = session.pendingPreKey.preKeyId;
                }
                body = Buffer.concat([
                    Buffer.from([this._encodeTupleByte(VERSION, VERSION)]),
                    Buffer.from(
                        protobufs.PreKeyWhisperMessage.encode(preKeyMsg).finish()
                    )
                ]);
            } else {
                type = 1;  // normal
                body = result;
            }
            return {
                type,
                body,
                registrationId: session.registrationId
            };
        });
    }

    async decryptWithSessions(data: Buffer, sessions: SessionEntry[], ourIdentityKey?: KeyPair): Promise<{ session: SessionEntry; plaintext: Buffer }> {
        // Iterate through the sessions, attempting to decrypt using each one.
        // Stop and return the result if we get a valid result.
        if (!sessions.length) {
            throw new errors.SessionError("No sessions available");
        }
        // Resolve identidade uma única vez para toda a iteração — antes era
        // buscada N vezes (uma por tentativa de sessão).
        const identity = ourIdentityKey ?? await this.storage.getOurIdentity();
        const errs: unknown[] = [];
        for (const session of sessions) {
            let plaintext: Buffer;
            try {
                plaintext = await this.doDecryptWhisperMessage(data, session, identity);
                session.indexInfo.used = Date.now();
                return {
                    session,
                    plaintext
                };
            } catch(e) {
                errs.push(e);
            }
        }
        // console.error("Failed to decrypt message with any known session...");
        for (const e of errs) {
            // console.error("Session error:" + e, e.stack);
            void e;
        }
        throw new errors.SessionError("No matching sessions found for message");
    }

    async decryptWhisperMessage(data: Buffer): Promise<Buffer> {
        assertBuffer(data);
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (!record) {
                throw new errors.SessionError("No session record");
            }
            const ourIdentityKey = await this.storage.getOurIdentity();
            const result = await this.decryptWithSessions(data, record.getSessions(), ourIdentityKey);
            const remoteIdentityKey = result.session.indexInfo.remoteIdentityKey;
            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
            }
            if (record.isClosed(result.session)) {
                // It's possible for this to happen when processing a backlog of messages.
                // The message was, hopefully, just sent back in a time when this session
                // was the most current.  Simply make a note of it and continue.  If our
                // actual open session is for reason invalid, that must be handled via
                // a full SessionError response.
                // console.warn("Decrypted message with closed session.");
            }
            await this.storeRecord(record);
            return result.plaintext;
        });
    }

    async decryptPreKeyWhisperMessage(data: Buffer): Promise<Buffer> {
        assertBuffer(data);
        const versions = this._decodeTupleByte(data[0]);
        if (versions[1] > 3 || versions[0] < 3) {  // min version > 3 or max version < 3
            throw new Error("Incompatible version number on PreKeyWhisperMessage");
        }
        return await this.queueJob(async () => {
            let record = await this.getRecord();
            const preKeyProto = protobufs.PreKeyWhisperMessage.decode(data.slice(1));
            if (!record) {
                if (preKeyProto.registrationId == null) {
                    throw new Error("No registrationId");
                }
                record = new SessionRecord();
            }
            const builder = new SessionBuilder(this.storage, this.addr);
            const preKeyId = await builder.initIncoming(record, preKeyProto);
            const session = record.getSession(preKeyProto.baseKey);
            if (!session) {
                throw new errors.SessionError("No session for baseKey after initIncoming");
            }
            const ourIdentityKey = await this.storage.getOurIdentity();
            const plaintext = await this.doDecryptWhisperMessage(preKeyProto.message, session, ourIdentityKey);
            await this.storeRecord(record);
            if (preKeyId) {
                await this.storage.removePreKey(preKeyId);
            }
            return plaintext;
        });
    }

    async doDecryptWhisperMessage(messageBuffer: Buffer, session: SessionEntry, ourIdentityKey?: KeyPair): Promise<Buffer> {
        assertBuffer(messageBuffer);
        if (!session) {
            throw new TypeError("session required");
        }
        const versions = this._decodeTupleByte(messageBuffer[0]);
        if (versions[1] > 3 || versions[0] < 3) {  // min version > 3 or max version < 3
            throw new Error("Incompatible version number on WhisperMessage");
        }
        const messageProto = messageBuffer.slice(1, -8);
        const message = protobufs.WhisperMessage.decode(messageProto);
        this.maybeStepRatchet(session, message.ephemeralKey, message.previousCounter);
        const chain = session.getChain(message.ephemeralKey);
        if (!chain) {
            throw new errors.SessionError("No chain for ephemeral key");
        }
        if (chain.chainType === ChainType.SENDING) {
            throw new Error("Tried to decrypt on a sending chain");
        }
        this.fillMessageKeys(chain, message.counter);
        if (!Object.prototype.hasOwnProperty.call(chain.messageKeys, message.counter)) {
            // Most likely the message was already decrypted and we are trying to process
            // twice.  This can happen if the user restarts before the server gets an ACK.
            throw new errors.MessageCounterError('Key used already or never filled');
        }
        const messageKey = chain.messageKeys[message.counter];
        delete chain.messageKeys[message.counter];
        const keys = crypto.deriveSecrets(messageKey, EMPTY_SALT_32, INFO_WHISPER_MSG_KEYS);
        // Compatibilidade: callers antigos que não passem o terceiro arg continuam funcionando.
        const identity = ourIdentityKey ?? await this.storage.getOurIdentity();
        const macInput = Buffer.alloc(messageProto.byteLength + (33 * 2) + 1);
        macInput.set(session.indexInfo.remoteIdentityKey);
        macInput.set(identity.pubKey, 33);
        macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION);
        macInput.set(messageProto, (33 * 2) + 1);
        // This is where we most likely fail if the session is not a match.
        // Don't misinterpret this as corruption.
        crypto.verifyMAC(macInput, keys[1], messageBuffer.slice(-8), 8);
        const plaintext = crypto.decrypt(keys[0], message.ciphertext, keys[2].slice(0, 16));
        delete session.pendingPreKey;
        return plaintext;
    }

    fillMessageKeys(chain: Chain, counter: number): void {
        if (counter - chain.chainKey.counter > 2000) {
            throw new errors.SessionError('Over 2000 messages into the future!');
        }
        while (chain.chainKey.counter < counter) {
            if (chain.chainKey.key === undefined) {
                throw new errors.SessionError('Chain closed');
            }
            const key = chain.chainKey.key;
            chain.messageKeys[chain.chainKey.counter + 1] = crypto.calculateMAC(key, MSG_KEY_SEED);
            chain.chainKey.key = crypto.calculateMAC(key, CHAIN_KEY_SEED);
            chain.chainKey.counter += 1;
        }
    }

    maybeStepRatchet(session: SessionEntry, remoteKey: Buffer, previousCounter: number): void {
        if (session.getChain(remoteKey)) {
            return;
        }
        const ratchet = session.currentRatchet;
        const previousRatchet = session.getChain(ratchet.lastRemoteEphemeralKey);
        if (previousRatchet) {
            this.fillMessageKeys(previousRatchet, previousCounter);
            delete previousRatchet.chainKey.key;  // Close
        }
        this.calculateRatchet(session, remoteKey, false);
        // Now swap the ephemeral key and calculate the new sending chain
        const prevCounter = session.getChain(ratchet.ephemeralKeyPair.pubKey);
        if (prevCounter) {
            ratchet.previousCounter = prevCounter.chainKey.counter;
            session.deleteChain(ratchet.ephemeralKeyPair.pubKey);
        }
        ratchet.ephemeralKeyPair = curve.generateKeyPair();
        this.calculateRatchet(session, remoteKey, true);
        ratchet.lastRemoteEphemeralKey = remoteKey;
    }

    calculateRatchet(session: SessionEntry, remoteKey: Buffer, sending: boolean): void {
        const ratchet = session.currentRatchet;
        const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey);
        const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey,
                                               INFO_WHISPER_RATCHET, /*chunks*/ 2);
        const chainKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;
        session.addChain(chainKey, {
            messageKeys: {},
            chainKey: {
                counter: -1,
                key: masterKey[1]
            },
            chainType: sending ? ChainType.SENDING : ChainType.RECEIVING
        });
        ratchet.rootKey = masterKey[0];
    }

    async hasOpenSession(): Promise<boolean> {
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (!record) {
                return false;
            }
            return record.haveOpenSession();
        });
    }

    async closeOpenSession(): Promise<void> {
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (record) {
                const openSession = record.getOpenSession();
                if (openSession) {
                    record.closeSession(openSession);
                    await this.storeRecord(record);
                }
            }
        });
    }
}

export = SessionCipher;
