/**
 * @packageDocumentation
 * @module avalanche-crypto
 */
/**
 * Uses JS-native CSPRNG to generate a specified number of bytes.
 * @NOTE
 * this method throws if no PRNG is available.
 * @param {Number} bytes bytes number to generate
 * @return {String} ramdom hex string
 */
export declare const randomBytes: (bytes: number) => string;
