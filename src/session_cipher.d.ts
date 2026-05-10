import ProtocolAddress from './protocol_address';
import SessionRecord = require('./session_record');
type SessionEntry = SessionRecord.Entry;
import type { Chain, EncryptedMessage, SignalStorage } from './types';
declare class SessionCipher {
    addr: ProtocolAddress;
    storage: SignalStorage;
    constructor(storage: SignalStorage, protocolAddress: ProtocolAddress);
    _encodeTupleByte(number1: number, number2: number): number;
    _decodeTupleByte(byte: number): [number, number];
    toString(): string;
    getRecord(): Promise<SessionRecord | undefined>;
    storeRecord(record: SessionRecord): Promise<void>;
    queueJob<T>(awaitable: () => T | Promise<T>): Promise<T>;
    encrypt(data: Buffer): Promise<EncryptedMessage>;
    decryptWithSessions(data: Buffer, sessions: SessionEntry[]): Promise<{
        session: SessionEntry;
        plaintext: Buffer;
    }>;
    decryptWhisperMessage(data: Buffer): Promise<Buffer>;
    decryptPreKeyWhisperMessage(data: Buffer): Promise<Buffer>;
    doDecryptWhisperMessage(messageBuffer: Buffer, session: SessionEntry): Promise<Buffer>;
    fillMessageKeys(chain: Chain, counter: number): void;
    maybeStepRatchet(session: SessionEntry, remoteKey: Buffer, previousCounter: number): void;
    calculateRatchet(session: SessionEntry, remoteKey: Buffer, sending: boolean): void;
    hasOpenSession(): Promise<boolean>;
    closeOpenSession(): Promise<void>;
}
export = SessionCipher;
