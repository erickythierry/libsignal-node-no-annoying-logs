type Awaitable<T> = () => T | Promise<T>;
declare function queueJob<T>(bucket: unknown, awaitable: Awaitable<T>): Promise<T>;
export = queueJob;
