/**
 * @packageDocumentation
 * @module avalanche-crypto
 */
import * as bytes from './bytes';
/**
 * @function generatePrivateKey
 * @description generatePrivate key using `eth-lib` settings
 * @return {string}
 */
export declare const generatePrivateKey: () => string;
/**
 * @function getPubkeyFromPrivateKey
 * @param  {string} privateKey - private key String
 * @return {string}
 */
export declare const getPubkeyFromPrivateKey: (privateKey: string) => string;
/**
 * @function getAddressFromPrivateKey
 * @param  {string} privateKey - private key string
 * @return {string} address with `length = 40`
 */
export declare const getAddressFromPrivateKey: (privateKey: string) => string;
export declare const getPublic: (privateKey: string, compress?: boolean) => string;
/**
 * @function getAddressFromPublicKey
 * @param  {string} publicKey - public key string
 * @return {string} address with `length = 40`
 */
export declare const getAddressFromPublicKey: (publicKey: string) => string;
/**
 * @function toChecksumAddress
 * @param  {string} address - raw address
 * @return {string} checksumed address
 */
export declare const toChecksumAddress: (address: string) => string;
export declare const sign: (digest: bytes.Arrayish | string, privateKey: string) => bytes.Signature;
export declare function getContractAddress(from: string, nonce: number): string;
export declare function verifySignature(digest: bytes.Arrayish, signature: bytes.Signature, publicKey: string): boolean;
export declare function recoverPublicKey(digest: bytes.Arrayish | string, signature: bytes.Signature | string): string;
export declare function recoverAddress(digest: bytes.Arrayish | string, signature: bytes.Signature | string): string;
/**
 * isValidChecksumAddress
 *
 * takes hex-encoded string and returns boolean if address is checksumed
 *
 * @param {string} address
 * @returns {boolean}
 */
export declare const isValidChecksumAddress: (address: string) => boolean;
export declare const validatePrivateKey: (privateKey: string) => boolean;
