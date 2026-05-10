import type { Chain, CurrentRatchet, IndexInfo, PendingPreKey, SessionEntryLike, SessionRecordLike } from './types';
declare class SessionEntry implements SessionEntryLike {
    _chains: {
        [base64Key: string]: Chain;
    };
    registrationId?: number;
    currentRatchet: CurrentRatchet;
    indexInfo: IndexInfo;
    pendingPreKey?: PendingPreKey;
    constructor();
    toString(): string;
    inspect(): string;
    addChain(key: Buffer, value: Chain): void;
    getChain(key: Buffer): Chain | undefined;
    deleteChain(key: Buffer): void;
    chains(): IterableIterator<[Buffer, Chain]>;
    serialize(): any;
    static deserialize(data: any): SessionEntry;
    _serialize_chains(chains: {
        [k: string]: Chain;
    }): any;
    static _deserialize_chains(chains_data: any): {
        [k: string]: Chain;
    };
}
declare class SessionRecord implements SessionRecordLike {
    sessions: {
        [base64BaseKey: string]: SessionEntry;
    };
    version: string;
    oldestKey?: string;
    oldestSession?: SessionEntry;
    static createEntry(): SessionEntry;
    static migrate(data: any): void;
    static deserialize(data: any): SessionRecord;
    constructor();
    serialize(): any;
    haveOpenSession(): boolean;
    getSession(key: Buffer): SessionEntry | undefined;
    getOpenSession(): SessionEntry | undefined;
    setSession(session: SessionEntry): void;
    getSessions(): SessionEntry[];
    closeSession(session: SessionEntry): void;
    openSession(session: SessionEntry): void;
    isClosed(session: SessionEntry): boolean;
    removeOldSessions(): void;
    deleteAllSessions(): void;
}
declare namespace SessionRecord {
    type Entry = SessionEntry;
}
export = SessionRecord;
