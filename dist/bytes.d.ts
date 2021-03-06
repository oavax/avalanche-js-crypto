/**
 * @packageDocumentation
 * @module avalanche-crypto
 * @hidden
 */
export declare type Arrayish = string | ArrayLike<number>;
export interface Hexable {
    toHexString(): string;
}
export interface Signature {
    r: string;
    s: string;
    recoveryParam?: number;
    v?: number;
}
export declare function isHexable(value: any): value is Hexable;
export declare function isArrayish(value: any): value is Arrayish;
export declare function arrayify(value: Arrayish | Hexable): Uint8Array | null;
export declare function concat(objects: Arrayish[]): Uint8Array;
export declare function stripZeros(value: Arrayish): Uint8Array;
export declare function padZeros(value: Arrayish, length: number): Uint8Array;
export declare function isHexString(value: any, length?: number): boolean;
export declare function hexlify(value: Arrayish | Hexable | number): string;
export declare function hexDataLength(data: string): number;
export declare function hexDataSlice(data: string, offset: number, endOffset?: number): string;
export declare function hexStripZeros(value: string): string;
export declare function hexZeroPad(value: string, length: number): string;
export declare function bytesPadLeft(value: string, byteLength: number): string;
export declare function bytesPadRight(value: string, byteLength: number): string;
export declare function isSignature(value: any): value is Signature;
export declare function splitSignature(signature: Arrayish | Signature): Signature;
export declare function joinSignature(signature: Signature): string;
/**
 * hexToByteArray
 *
 * Convers a hex string to a Uint8Array
 *
 * @param {string} hex
 * @returns {Uint8Array}
 */
export declare const hexToByteArray: (hex: string) => Uint8Array;
/**
 * hexToIntArray
 *
 * @param {string} hex
 * @returns {number[]}
 */
export declare const hexToIntArray: (hex: string) => number[];
/**
 * isHex
 *
 * @param {string} str - string to be tested
 * @returns {boolean}
 */
export declare const isHex: (str: string) => boolean;
