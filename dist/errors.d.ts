/**
 # avalanche-js-crypto

This package provides a collection of apis related to address management, kestore, encoding, and encrypt/decrypt.

## Installation

```
npm install avalanche-js-crypto
```

## Usage

```javascript
* const {
*   encode,
*   decode,
*   randomBytes,
*   toBech32,
*   fromBech32,
*   AvalancheAddress,
*   generatePrivateKey,
*   getPubkeyFromPrivateKey,
*   getAddressFromPublicKey,
*   getAddressFromPrivateKey,
*   encryptPhrase,
*   decryptPhrase
* } = require('avalanche-js-crypto');
* const { isPrivateKey, isAddress, isPublicKey } = require('avalanche-js-utils');
```

Address apis
```javascript
const bytes = randomBytes(20);
const addr = new AvalancheAddress(bytes);

console.log(addr.checksum);
console.log(addr.bech32);

console.log(AvalancheAddress.isValidBech32(addr.bech32));
```

RLP apis
```javascript
const encoded = '0x89010101010101010101';
const decoded = '0x010101010101010101';
console.log(encode(decoded));
console.log(decode(encoded));
```

Keystore apis
```javascript
const prv = generatePrivateKey();
const pub = getPubkeyFromPrivateKey(prv);
const addr = getAddressFromPublicKey(pub);
const addrPrv = getAddressFromPrivateKey(prv);
console.log(isPrivateKey(prv));
console.log(isPublicKey(pub));
console.log(isAddress(addr));
console.log(isAddress(addrPrv));
```

Encrypt/decrypt apis
```javascript
* const { Wallet } = require('avalanche-js-account');

* const myPhrase = new Wallet().newMnemonic();
* console.log(myPhrase);
* const pwd = '1234';
* encryptPhrase(myPhrase, pwd).then((value) => {
*   console.log(value);
*   decryptPhrase(JSON.parse(value), pwd).then(value => {
*     console.log(value);
*   });
* });
```
 *
 * @packageDocumentation
 * @module avalanche-crypto
 */
/** @hidden */
export declare const UNKNOWN_ERROR = "UNKNOWN_ERROR";
/** @hidden */
export declare const NOT_IMPLEMENTED = "NOT_IMPLEMENTED";
/** @hidden */
export declare const MISSING_NEW = "MISSING_NEW";
/** @hidden */
export declare const CALL_EXCEPTION = "CALL_EXCEPTION";
/** @hidden */
export declare const INVALID_ARGUMENT = "INVALID_ARGUMENT";
/** @hidden */
export declare const MISSING_ARGUMENT = "MISSING_ARGUMENT";
/** @hidden */
export declare const UNEXPECTED_ARGUMENT = "UNEXPECTED_ARGUMENT";
/** @hidden */
export declare const NUMERIC_FAULT = "NUMERIC_FAULT";
/** @hidden */
export declare const INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS";
/** @hidden */
export declare const NONCE_EXPIRED = "NONCE_EXPIRED";
/** @hidden */
export declare const REPLACEMENT_UNDERPRICED = "REPLACEMENT_UNDERPRICED";
/** @hidden */
export declare const UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION";
/** @hidden */
export declare function throwError(message: string, code: string | null | undefined, params: any): never;
/** @hidden */
export declare function checkNew(self: any, kind: any): void;
/** @hidden */
export declare function checkArgumentCount(count: number, expectedCount: number, suffix?: string): void;
/** @hidden */
export declare function setCensorship(censorship: boolean, permanent?: boolean): void;
/** @hidden */
export declare function checkNormalize(): void;
/** @hidden */
export declare function setLogLevel(logLevel: string): void;
/** @hidden */
export declare function warn(...args: [any?, ...any[]]): void;
/** @hidden */
export declare function info(...args: [any?, ...any[]]): void;
