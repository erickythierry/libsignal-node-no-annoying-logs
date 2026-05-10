import type { BaseKeyTypeValue } from './base_key_type';
import type { ChainTypeValue } from './chain_type';

export interface KeyPair {
    pubKey: Buffer;
    privKey: Buffer;
}

export interface SignedPreKeyPair {
    keyId: number;
    keyPair: KeyPair;
    signature: Buffer;
}

export interface PreKeyPair {
    keyId: number;
    keyPair: KeyPair;
}

export interface PreKeyBundlePreKey {
    keyId: number;
    publicKey: Buffer;
}

export interface PreKeyBundleSignedPreKey {
    keyId: number;
    publicKey: Buffer;
    signature: Buffer;
}

export interface PreKeyBundle {
    identityKey: Buffer;
    registrationId: number;
    signedPreKey: PreKeyBundleSignedPreKey;
    preKey?: PreKeyBundlePreKey;
}

export interface SignalStorage {
    isTrustedIdentity(identifier: string, identityKey: Buffer): boolean | Promise<boolean>;
    loadPreKey(keyId: number | string): KeyPair | undefined | Promise<KeyPair | undefined>;
    removePreKey(keyId: number | string): void | Promise<void>;
    loadSignedPreKey(keyId: number | string): KeyPair | undefined | Promise<KeyPair | undefined>;
    loadSession(identifier: string): SessionRecordLike | undefined | Promise<SessionRecordLike | undefined>;
    storeSession(identifier: string, record: SessionRecordLike): void | Promise<void>;
    getOurIdentity(): KeyPair | Promise<KeyPair>;
    getOurRegistrationId(): number | Promise<number>;
    saveIdentity?(identifier: string, identityKey: Buffer): void | Promise<void>;
}

// Forward type used by SignalStorage. SessionRecord (class) implements this shape.
export interface SessionRecordLike {
    getOpenSession(): SessionEntryLike | undefined;
    getSession(key: Buffer): SessionEntryLike | undefined;
    setSession(session: SessionEntryLike): void;
    getSessions(): SessionEntryLike[];
    closeSession(session: SessionEntryLike): void;
    haveOpenSession(): boolean;
    isClosed(session: SessionEntryLike): boolean;
    removeOldSessions(): void;
    deleteAllSessions(): void;
    serialize(): unknown;
}

export interface MessageKeys {
    [counter: number]: Buffer;
}

export interface ChainKey {
    counter: number;
    key?: Buffer;
}

export interface Chain {
    chainKey: ChainKey;
    chainType: ChainTypeValue;
    messageKeys: MessageKeys;
}

export interface CurrentRatchet {
    ephemeralKeyPair: KeyPair;
    lastRemoteEphemeralKey: Buffer;
    previousCounter: number;
    rootKey: Buffer;
}

export interface IndexInfo {
    baseKey: Buffer;
    baseKeyType: BaseKeyTypeValue;
    closed: number;
    used: number;
    created: number;
    remoteIdentityKey: Buffer;
}

export interface PendingPreKey {
    signedKeyId: number;
    baseKey: Buffer;
    preKeyId?: number;
}

export interface SessionEntryLike {
    registrationId?: number;
    currentRatchet: CurrentRatchet;
    indexInfo: IndexInfo;
    pendingPreKey?: PendingPreKey;
    addChain(key: Buffer, value: Chain): void;
    getChain(key: Buffer): Chain | undefined;
    deleteChain(key: Buffer): void;
    chains(): IterableIterator<[Buffer, Chain]>;
    serialize(): unknown;
}

export type EncryptedMessageType = 1 | 3;

export interface EncryptedMessage {
    type: EncryptedMessageType;
    body: Buffer;
    registrationId?: number;
}
