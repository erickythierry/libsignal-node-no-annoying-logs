export const ChainType = {
    SENDING: 1,
    RECEIVING: 2
} as const;

export type ChainTypeValue = typeof ChainType[keyof typeof ChainType];

export default ChainType;
