import SessionRecord = require("./session_record");
type SessionEntry = SessionRecord.Entry;
import ProtocolAddress from "./protocol_address";
import type { KeyPair, PreKeyBundle, SignalStorage } from "./types";
declare class SessionBuilder {
    addr: ProtocolAddress;
    storage: SignalStorage;
    constructor(storage: SignalStorage, protocolAddress: ProtocolAddress);
    initOutgoing(device: PreKeyBundle): Promise<void>;
    initIncoming(record: SessionRecord, message: any): Promise<number | undefined>;
    initSession(isInitiator: boolean, ourEphemeralKey: KeyPair | undefined, ourSignedKey: KeyPair | undefined, theirIdentityPubKey: Buffer, theirEphemeralPubKey: Buffer | undefined, theirSignedPubKey: Buffer | undefined, registrationId: number): Promise<SessionEntry>;
    calculateSendingRatchet(session: SessionEntry, remoteKey: Buffer): void;
}
export = SessionBuilder;
