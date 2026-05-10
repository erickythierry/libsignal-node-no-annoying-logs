
export const BaseKeyType = {
    OURS: 1,
    THEIRS: 2
} as const;

export type BaseKeyTypeValue = typeof BaseKeyType[keyof typeof BaseKeyType];

export default BaseKeyType;
