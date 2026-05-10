export declare const BaseKeyType: {
    readonly OURS: 1;
    readonly THEIRS: 2;
};
export type BaseKeyTypeValue = typeof BaseKeyType[keyof typeof BaseKeyType];
export default BaseKeyType;
