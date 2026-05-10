export declare const ChainType: {
    readonly SENDING: 1;
    readonly RECEIVING: 2;
};
export type ChainTypeValue = typeof ChainType[keyof typeof ChainType];
export default ChainType;
