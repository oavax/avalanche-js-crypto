/**
 * @packageDocumentation
 * @module avalanche-crypto
 * @hidden
 */
/// <reference types="node" />
export declare const bech32Encode: (hrp: string, data: Buffer) => string;
export declare const bech32Decode: (bechString: string) => {
    hrp: string;
    data: Buffer;
};
export declare const HRP = "avax";
export declare const tHRP = "tavax";
/**
 * convertBits
 *
 * groups buffers of a certain width to buffers of the desired width.
 *
 * For example, converts byte buffers to buffers of maximum 5 bit numbers,
 * padding those numbers as necessary. Necessary for encoding Ethereum-style
 * addresses as bech32 avaxs.
 *
 * @param {Buffer} data
 * @param {number} fromWidth
 * @param {number} toWidth
 * @param {boolean} pad
 * @returns {Buffer|null}
 */
export declare const convertBits: (data: Buffer, fromWidth: number, toWidth: number, pad?: boolean) => Buffer;
/**
 * toBech32Address
 *
 * bech32Encodes a canonical 20-byte Ethereum-style address as a bech32 Avalanche
 * address.
 *
 * The expected format is avax1<address><checksum> where address and checksum
 * are the result of bech32 encoding a Buffer containing the address bytes.
 *
 * @param {string} 20 byte canonical address
 * @returns {string} 38 char bech32 bech32Encoded Avalanche address
 */
export declare const toBech32: (address: string, useHRP?: string) => string;
/**
 * fromBech32Address
 *
 * @param {string} address - a valid Avalanche bech32 address
 * @returns {string} a canonical 20-byte Ethereum-style address
 */
export declare const fromBech32: (address: string, useHRP?: string) => string;
