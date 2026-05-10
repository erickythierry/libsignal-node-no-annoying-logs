// vim: ts=4:sw=4

import BaseKeyType from './base_key_type';
import type {
    Chain,
    CurrentRatchet,
    IndexInfo,
    PendingPreKey,
    SessionEntryLike,
    SessionRecordLike,
} from './types';

const CLOSED_SESSIONS_MAX = 40;
const SESSION_RECORD_VERSION = 'v1';

function assertBuffer(value: unknown): asserts value is Buffer {
    if (!Buffer.isBuffer(value)) {
        throw new TypeError("Buffer required");
    }
}


class SessionEntry implements SessionEntryLike {

    _chains: { [base64Key: string]: Chain };
    registrationId?: number;
    currentRatchet!: CurrentRatchet;
    indexInfo!: IndexInfo;
    pendingPreKey?: PendingPreKey;

    constructor() {
        this._chains = {};
    }

    toString(): string {
        const baseKey = this.indexInfo && this.indexInfo.baseKey &&
            this.indexInfo.baseKey.toString('base64');
        return `<SessionEntry [baseKey=${baseKey}]>`;
    }

    inspect(): string {
        return this.toString();
    }

    addChain(key: Buffer, value: Chain): void {
        assertBuffer(key);
        const id = key.toString('base64');
        if (Object.prototype.hasOwnProperty.call(this._chains, id)) {
            throw new Error("Overwrite attempt");
        }
        this._chains[id] = value;
    }

    getChain(key: Buffer): Chain | undefined {
        assertBuffer(key);
        return this._chains[key.toString('base64')];
    }

    deleteChain(key: Buffer): void {
        assertBuffer(key);
        const id = key.toString('base64');
        if (!Object.prototype.hasOwnProperty.call(this._chains, id)) {
            throw new ReferenceError("Not Found");
        }
        delete this._chains[id];
    }

    *chains(): IterableIterator<[Buffer, Chain]> {
        for (const [k, v] of Object.entries(this._chains)) {
            yield [Buffer.from(k, 'base64'), v];
        }
    }

    serialize(): any {
        const data: any = {
            registrationId: this.registrationId,
            currentRatchet: {
                ephemeralKeyPair: {
                    pubKey: this.currentRatchet.ephemeralKeyPair.pubKey.toString('base64'),
                    privKey: this.currentRatchet.ephemeralKeyPair.privKey.toString('base64')
                },
                lastRemoteEphemeralKey: this.currentRatchet.lastRemoteEphemeralKey.toString('base64'),
                previousCounter: this.currentRatchet.previousCounter,
                rootKey: this.currentRatchet.rootKey.toString('base64')
            },
            indexInfo: {
                baseKey: this.indexInfo.baseKey.toString('base64'),
                baseKeyType: this.indexInfo.baseKeyType,
                closed: this.indexInfo.closed,
                used: this.indexInfo.used,
                created: this.indexInfo.created,
                remoteIdentityKey: this.indexInfo.remoteIdentityKey.toString('base64')
            },
            _chains: this._serialize_chains(this._chains)
        };
        if (this.pendingPreKey) {
            data.pendingPreKey = Object.assign({}, this.pendingPreKey);
            data.pendingPreKey.baseKey = this.pendingPreKey.baseKey.toString('base64');
        }
        return data;
    }

    static deserialize(data: any): SessionEntry {
        const obj = new this();
        obj.registrationId = data.registrationId;
        obj.currentRatchet = {
            ephemeralKeyPair: {
                pubKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.pubKey, 'base64'),
                privKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.privKey, 'base64')
            },
            lastRemoteEphemeralKey: Buffer.from(data.currentRatchet.lastRemoteEphemeralKey, 'base64'),
            previousCounter: data.currentRatchet.previousCounter,
            rootKey: Buffer.from(data.currentRatchet.rootKey, 'base64')
        };
        obj.indexInfo = {
            baseKey: Buffer.from(data.indexInfo.baseKey, 'base64'),
            baseKeyType: data.indexInfo.baseKeyType,
            closed: data.indexInfo.closed,
            used: data.indexInfo.used,
            created: data.indexInfo.created,
            remoteIdentityKey: Buffer.from(data.indexInfo.remoteIdentityKey, 'base64')
        };
        obj._chains = this._deserialize_chains(data._chains);
        if (data.pendingPreKey) {
            obj.pendingPreKey = Object.assign({}, data.pendingPreKey);
            obj.pendingPreKey!.baseKey = Buffer.from(data.pendingPreKey.baseKey, 'base64');
        }
        return obj;
    }

    _serialize_chains(chains: { [k: string]: Chain }): any {
        const r: any = {};
        for (const key of Object.keys(chains)) {
            const c = chains[key];
            const messageKeys: { [k: string]: string } = {};
            for (const [idx, mk] of Object.entries(c.messageKeys)) {
                messageKeys[idx] = (mk as Buffer).toString('base64');
            }
            r[key] = {
                chainKey: {
                    counter: c.chainKey.counter,
                    key: c.chainKey.key && c.chainKey.key.toString('base64')
                },
                chainType: c.chainType,
                messageKeys: messageKeys
            };
        }
        return r;
    }

    static _deserialize_chains(chains_data: any): { [k: string]: Chain } {
        const r: { [k: string]: Chain } = {};
        for (const key of Object.keys(chains_data)) {
            const c = chains_data[key];
            const messageKeys: { [k: number]: Buffer } = {};
            for (const [idx, mk] of Object.entries(c.messageKeys)) {
                messageKeys[idx as unknown as number] = Buffer.from(mk as string, 'base64');
            }
            r[key] = {
                chainKey: {
                    counter: c.chainKey.counter,
                    key: c.chainKey.key && Buffer.from(c.chainKey.key, 'base64')
                },
                chainType: c.chainType,
                messageKeys: messageKeys
            };
        }
        return r;
    }

}


interface Migration {
    version: string;
    migrate: (data: any) => void;
}

const migrations: Migration[] = [{
    version: 'v1',
    migrate: function migrateV1(data: any) {
        const sessions = data._sessions;
        if (data.registrationId) {
            for (const key in sessions) {
                if (!sessions[key].registrationId) {
                    sessions[key].registrationId = data.registrationId;
                }
            }
        } else {
            for (const key in sessions) {
                if (sessions[key].indexInfo.closed === -1) {
                    // console.error('V1 session storage migration error: registrationId',
                    //               data.registrationId, 'for open session version',
                    //               data.version);
                }
            }
        }
    }
}];


class SessionRecord implements SessionRecordLike {

    sessions: { [base64BaseKey: string]: SessionEntry };
    version: string;

    static createEntry(): SessionEntry {
        return new SessionEntry();
    }

    static migrate(data: any): void {
        let run = (data.version === undefined);
        for (let i = 0; i < migrations.length; ++i) {
            if (run) {
                // console.info("Migrating session to:", migrations[i].version);
                migrations[i].migrate(data);
            } else if (migrations[i].version === data.version) {
                run = true;
            }
        }
        if (!run) {
            throw new Error("Error migrating SessionRecord");
        }
    }

    static deserialize(data: any): SessionRecord {
        if (data.version !== SESSION_RECORD_VERSION) {
            this.migrate(data);
        }
        const obj = new this();
        if (data._sessions) {
            for (const [key, entry] of Object.entries(data._sessions)) {
                obj.sessions[key] = SessionEntry.deserialize(entry);
            }
        }
        return obj;
    }

    constructor() {
        this.sessions = {};
        this.version = SESSION_RECORD_VERSION;
    }

    serialize(): any {
        const _sessions: { [k: string]: any } = {};
        for (const [key, entry] of Object.entries(this.sessions)) {
            _sessions[key] = entry.serialize();
        }
        return {
            _sessions,
            version: this.version
        };
    }

    haveOpenSession(): boolean {
        const openSession = this.getOpenSession();
        return (!!openSession && typeof openSession.registrationId === 'number');
    }

    getSession(key: Buffer): SessionEntry | undefined {
        assertBuffer(key);
        const session = this.sessions[key.toString('base64')];
        if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
            throw new Error("Tried to lookup a session using our basekey");
        }
        return session;
    }

    getOpenSession(): SessionEntry | undefined {
        for (const session of Object.values(this.sessions)) {
            if (!this.isClosed(session)) {
                return session;
            }
        }
        return undefined;
    }

    setSession(session: SessionEntry): void {
        this.sessions[session.indexInfo.baseKey.toString('base64')] = session;
    }

    getSessions(): SessionEntry[] {
        // Return sessions ordered with most recently used first.
        return Array.from(Object.values(this.sessions)).sort((a, b) => {
            const aUsed = a.indexInfo.used || 0;
            const bUsed = b.indexInfo.used || 0;
            return aUsed === bUsed ? 0 : aUsed < bUsed ? 1 : -1;
        });
    }

    closeSession(session: SessionEntry): void {
        if (this.isClosed(session)) {
            // console.warn("Session already closed", session);
            return;
        }
        // console.info("Closing session:", session);
        session.indexInfo.closed = Date.now();
    }

    openSession(session: SessionEntry): void {
        if (!this.isClosed(session)) {
            // console.warn("Session already open");
        }
        // console.info("Opening session:", session);
        session.indexInfo.closed = -1;
    }

    isClosed(session: SessionEntry): boolean {
        return session.indexInfo.closed !== -1;
    }

    removeOldSessions(): void {
        while (Object.keys(this.sessions).length > CLOSED_SESSIONS_MAX) {
            let oldestKey: string | undefined;
            let oldestSession: SessionEntry | undefined;
            for (const [key, session] of Object.entries(this.sessions)) {
                if (session.indexInfo.closed !== -1 &&
                    (!oldestSession || session.indexInfo.closed < oldestSession.indexInfo.closed)) {
                    oldestKey = key;
                    oldestSession = session;
                }
            }
            if (oldestKey) {
                delete this.sessions[oldestKey];
            } else {
                throw new Error('Corrupt sessions object');
            }
        }
    }

    deleteAllSessions(): void {
        for (const key of Object.keys(this.sessions)) {
            delete this.sessions[key];
        }
    }
}

namespace SessionRecord {
    export type Entry = SessionEntry;
}

(SessionRecord as any).SessionEntry = SessionEntry;

export = SessionRecord;
