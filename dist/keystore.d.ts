/**
 * @packageDocumentation
 * @module avalanche-crypto
 */
import { EncryptOptions, Keystore } from './types';
/**
 * This method will map the current Account object to V3Keystore object.
 *
 * @method encrypt
 *
 * @param {string} privateKey
 * @param {string} password
 * @param {object} options
 *
 * @return {{version, id, address, crypto}}
 */
export declare const encrypt: (privateKey: string, password: string, options?: EncryptOptions) => Promise<string>;
/**
 * @function decrypt
 * @param  {Keystore} keystore - Keystore file
 * @param  {string} password - password string
 * @return {string} privateKey
 */
export declare const decrypt: (keystore: Keystore, password: string) => Promise<string>;
/**
 * encrypt Phrase
 */
export declare const encryptPhrase: (phrase: string, password: string, options?: EncryptOptions) => Promise<string>;
/**
 * decrypt phrase
 */
export declare const decryptPhrase: (keystore: Keystore, password: string) => Promise<string>;
