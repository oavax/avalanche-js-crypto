/**
 * @packageDocumentation
 * @module avalanche-crypto
 */
/**
 * ### How to use it?
 *
 * ```
 * // Step 1: import the class
 * const { AvalancheAddress } = require('avalanche-js-crypto');
 *
 * // Step 2: call functions
 * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
 * const res = AvalancheAddress.isValidBech32(addr);
 * console.log(res);
 * ```
 */
export declare class AvalancheAddress {
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const res = AvalancheAddress.isValidBech32(addr);
     * console.log(res);
     * ```
     */
    static isValidBasic(str: string): boolean;
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const res = AvalancheAddress.isValidChecksum(addr);
     * console.log(res);
     * ```
     */
    static isValidChecksum(str: string): boolean;
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const res = AvalancheAddress.isValidBech32(addr);
     * console.log(res);
     * ```
     */
    static isValidBech32(str: string): boolean;
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const res = AvalancheAddress.isValidBech32TestNet(addr);
     * console.log(res);
     * ```
     */
    static isValidBech32TestNet(str: string): boolean;
    raw: string;
    basic: string;
    /**
     * get basicHex of the address
     *
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const instance = new AvalancheAddress(addr);
     * console.log(instance.basicHex);
     * ```
     */
    get basicHex(): string;
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const instance = new AvalancheAddress(addr);
     * console.log(instance.checksum);
     * ```
     */
    get checksum(): string;
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const instance = new AvalancheAddress(addr);
     * console.log(instance.bech32);
     * ```
     */
    get bech32(): string;
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const instance = new AvalancheAddress(addr);
     * console.log(instance.bech32TestNet);
     * ```
     */
    get bech32TestNet(): string;
    constructor(raw: string);
    /**
     * Check whether the address has an valid address format
     *
     * @param addr string, the address
     *
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const instance = new AvalancheAddress(addr);
     * const res = instance.getBasic(addr);
     * console.log(res)
     * ```
     */
    private getBasic;
}
/**
 * Using this function to get Avalanche format address
 *
 * @param address
 *
 * @example
 * ```javascript
 * const { Avalanche } = require('avalanche-js-core');
 * const { ChainID, ChainType } = require('avalanche-js-utils');
 * const { randomBytes } = require('avalanche-js-crypto')
 *
 * const hmy = new Avalanche(
 *   'http://localhost:9500',
 *   {
 *   chainType: ChainType.Avalanche,
 *   chainId: ChainID.HmyLocal,
 *   },
 * );
 *
 * const bytes = randomBytes(20);
 * const hAddress = hmy.crypto.getAddress(bytes);
 * console.log(hAddress)
 * ```
 */
export declare function getAddress(address: string): AvalancheAddress;
