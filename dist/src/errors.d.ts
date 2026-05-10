export declare class SignalError extends Error {
}
export declare class UntrustedIdentityKeyError extends SignalError {
    addr: string;
    identityKey: Buffer;
    constructor(addr: string, identityKey: Buffer);
}
export declare class SessionError extends SignalError {
    constructor(message?: string);
}
export declare class MessageCounterError extends SessionError {
    constructor(message?: string);
}
export declare class PreKeyError extends SessionError {
    constructor(message?: string);
}
