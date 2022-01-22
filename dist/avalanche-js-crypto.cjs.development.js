'use strict';

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var hdkey = _interopDefault(require('hdkey'));
var bip39 = _interopDefault(require('bip39'));
var bn_js = _interopDefault(require('bn.js'));
var elliptic = _interopDefault(require('elliptic'));
var sha3 = require('js-sha3');
var avalancheJsUtils = require('avalanche-js-utils');
var _regeneratorRuntime = _interopDefault(require('regenerator-runtime'));
var aes = _interopDefault(require('aes-js'));
var scrypt = _interopDefault(require('scrypt-shim'));
var pbkdf2 = require('pbkdf2');
var uuid = _interopDefault(require('uuid'));

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
var randomBytes = function randomBytes(bytes) {
  var randBz;

  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    randBz = window.crypto.getRandomValues(new Uint8Array(bytes));
  } else if (typeof require !== 'undefined') {
    randBz = require('crypto').randomBytes(bytes);
  } else {
    throw new Error('Unable to generate safe random numbers.');
  }

  var randStr = '';

  for (var i = 0; i < bytes; i += 1) {
    randStr += ("00" + randBz[i].toString(16)).slice(-2);
  }

  return randStr;
};

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
// This file is ported from ether.js/src.ts/errors.ts
// Unknown Error

/** @hidden */
var UNKNOWN_ERROR = 'UNKNOWN_ERROR'; // Not implemented

/** @hidden */

var NOT_IMPLEMENTED = 'NOT_IMPLEMENTED'; // Missing new operator to an object
//  - name: The name of the class

/** @hidden */

var MISSING_NEW = 'MISSING_NEW'; // Call exception
//  - transaction: the transaction
//  - address?: the contract address
//  - args?: The arguments passed into the function
//  - method?: The Solidity method signature
//  - errorSignature?: The EIP848 error signature
//  - errorArgs?: The EIP848 error parameters
//  - reason: The reason (only for EIP848 "Error(string)")

/** @hidden */

var CALL_EXCEPTION = 'CALL_EXCEPTION'; // Invalid argument (e.g. value is incompatible with type) to a function:
//   - argument: The argument name that was invalid
//   - value: The value of the argument

/** @hidden */

var INVALID_ARGUMENT = 'INVALID_ARGUMENT'; // Missing argument to a function:
//   - count: The number of arguments received
//   - expectedCount: The number of arguments expected

/** @hidden */

var MISSING_ARGUMENT = 'MISSING_ARGUMENT'; // Too many arguments
//   - count: The number of arguments received
//   - expectedCount: The number of arguments expected

/** @hidden */

var UNEXPECTED_ARGUMENT = 'UNEXPECTED_ARGUMENT'; // Numeric Fault
//   - operation: the operation being executed
//   - fault: the reason this faulted

/** @hidden */

var NUMERIC_FAULT = 'NUMERIC_FAULT'; // Insufficien funds (< value + gasLimit * gasPrice)
//   - transaction: the transaction attempted

/** @hidden */

var INSUFFICIENT_FUNDS = 'INSUFFICIENT_FUNDS'; // Nonce has already been used
//   - transaction: the transaction attempted

/** @hidden */

var NONCE_EXPIRED = 'NONCE_EXPIRED'; // The replacement fee for the transaction is too low
//   - transaction: the transaction attempted

/** @hidden */

var REPLACEMENT_UNDERPRICED = 'REPLACEMENT_UNDERPRICED'; // Unsupported operation
//   - operation

/** @hidden */

var UNSUPPORTED_OPERATION = 'UNSUPPORTED_OPERATION'; // tslint:disable-next-line: variable-name

/** @hidden */

var _permanentCensorErrors = false; // tslint:disable-next-line: variable-name

/** @hidden */

var _censorErrors = false; // @TODO: Enum

/** @hidden */

function throwError(message, code, params) {
  if (_censorErrors) {
    throw new Error('unknown error');
  }

  if (!code) {
    code = UNKNOWN_ERROR;
  }

  if (!params) {
    params = {};
  }

  var messageDetails = [];
  Object.keys(params).forEach(function (key) {
    try {
      messageDetails.push(key + '=' + JSON.stringify(params[key]));
    } catch (error) {
      messageDetails.push(key + '=' + JSON.stringify(params[key].toString()));
    }
  });
  messageDetails.push('version=' + '#version');
  var reason = message;

  if (messageDetails.length) {
    message += ' (' + messageDetails.join(', ') + ')';
  } // @TODO: Any??


  var error = new Error(message);
  error.reason = reason;
  error.code = code;
  Object.keys(params).forEach(function (key) {
    error[key] = params[key];
  });
  throw error;
}
/** @hidden */

function checkNew(self, kind) {
  if (!(self instanceof kind)) {
    throwError('missing new', MISSING_NEW, {
      name: kind.name
    });
  }
}
/** @hidden */

function checkArgumentCount(count, expectedCount, suffix) {
  if (!suffix) {
    suffix = '';
  }

  if (count < expectedCount) {
    throwError('missing argument' + suffix, MISSING_ARGUMENT, {
      count: count,
      expectedCount: expectedCount
    });
  }

  if (count > expectedCount) {
    throwError('too many arguments' + suffix, UNEXPECTED_ARGUMENT, {
      count: count,
      expectedCount: expectedCount
    });
  }
}
/** @hidden */

function setCensorship(censorship, permanent) {
  if (_permanentCensorErrors) {
    throwError('error censorship permanent', UNSUPPORTED_OPERATION, {
      operation: 'setCensorship'
    });
  }

  _censorErrors = !!censorship;
  _permanentCensorErrors = !!permanent;
}
/** @hidden */

function checkNormalize() {
  try {
    // Make sure all forms of normalization are supported
    ['NFD', 'NFC', 'NFKD', 'NFKC'].forEach(function (form) {
      try {
        'test'.normalize(form);
      } catch (error) {
        throw new Error('missing ' + form);
      }
    });

    if (String.fromCharCode(0xe9).normalize('NFD') !== String.fromCharCode(0x65, 0x0301)) {
      throw new Error('broken implementation');
    }
  } catch (error) {
    throwError('platform missing String.prototype.normalize', UNSUPPORTED_OPERATION, {
      operation: 'String.prototype.normalize',
      form: error.message
    });
  }
}
/** @hidden */

var LogLevels = {
  debug: 1,
  "default": 2,
  info: 2,
  warn: 3,
  error: 4,
  off: 5
};
/** @hidden */

var LogLevel = LogLevels["default"];
/** @hidden */

function setLogLevel(logLevel) {
  var level = LogLevels[logLevel];

  if (level == null) {
    warn('invliad log level - ' + logLevel);
    return;
  }

  LogLevel = level;
}
/** @hidden */

function log(logLevel, args) {
  if (LogLevel > LogLevels[logLevel]) {
    return;
  }

  console.log.apply(console, args);
}
/** @hidden */


function warn() {
  for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
    args[_key] = arguments[_key];
  }

  log('warn', args);
}
/** @hidden */

function info() {
  for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
    args[_key2] = arguments[_key2];
  }

  log('info', args);
}

/**
 * @packageDocumentation
 * @module avalanche-crypto
 * @hidden
 */

function isHexable(value) {
  return !!value.toHexString;
}

function addSlice(array) {
  if (typeof array === 'object' && typeof array.slice === 'function') {
    return array;
  } // tslint:disable-next-line: only-arrow-functions


  array.slice = function () {
    var args = Array.prototype.slice.call(arguments);
    return addSlice(new Uint8Array(Array.prototype.slice.apply(array, [args[0], args[1]])));
  };

  return array;
}

function isArrayish(value) {
  if (!value || // tslint:disable-next-line: radix
  parseInt(String(value.length)) !== value.length || typeof value === 'string') {
    return false;
  } // tslint:disable-next-line: prefer-for-of


  for (var i = 0; i < value.length; i++) {
    var v = value[i]; // tslint:disable-next-line: radix

    if (v < 0 || v >= 256 || parseInt(String(v)) !== v) {
      return false;
    }
  }

  return true;
}
function arrayify(value) {
  if (value == null) {
    throwError('cannot convert null value to array', INVALID_ARGUMENT, {
      arg: 'value',
      value: value
    });
  }

  if (isHexable(value)) {
    value = value.toHexString();
  }

  if (typeof value === 'string') {
    var match = value.match(/^(0x)?[0-9a-fA-F]*$/);

    if (!match) {
      throwError('invalid hexidecimal string', INVALID_ARGUMENT, {
        arg: 'value',
        value: value
      });
    }

    if (match !== null && match[1] !== '0x') {
      throwError('hex string must have 0x prefix', INVALID_ARGUMENT, {
        arg: 'value',
        value: value
      });
    }

    value = value.substring(2);

    if (value.length % 2) {
      value = '0' + value;
    }

    var result = [];

    for (var i = 0; i < value.length; i += 2) {
      result.push(parseInt(value.substr(i, 2), 16));
    }

    return addSlice(new Uint8Array(result));
  }

  if (isArrayish(value)) {
    return addSlice(new Uint8Array(value));
  }

  throwError('invalid arrayify value', null, {
    arg: 'value',
    value: value,
    type: typeof value
  });
  return null;
}
function concat(objects) {
  if (objects === null) {
    throw new Error("concat objects is null");
  }

  var arrays = [];
  var length = 0; // tslint:disable-next-line: prefer-for-of

  for (var i = 0; i < objects.length; i++) {
    var object = arrayify(objects[i]);

    if (object == null) {
      throw new Error('arrayify failed');
    }

    arrays.push(object);
    length += object.length;
  }

  var result = new Uint8Array(length);
  var offset = 0; // tslint:disable-next-line: prefer-for-of

  for (var _i = 0; _i < arrays.length; _i++) {
    result.set(arrays[_i], offset);
    offset += arrays[_i].length;
  }

  return addSlice(result);
}
function stripZeros(value) {
  var result = arrayify(value);

  if (result === null) {
    throw new Error('arrayify failed');
  }

  if (result.length === 0) {
    return result;
  } // Find the first non-zero entry


  var start = 0;

  while (result[start] === 0) {
    start++;
  } // If we started with zeros, strip them


  if (start) {
    result = result.slice(start);
  }

  return result;
}
function padZeros(value, length) {
  var arrayifyValue = arrayify(value);

  if (arrayifyValue === null) {
    throw new Error('arrayify failed');
  }

  if (length < arrayifyValue.length) {
    throw new Error('cannot pad');
  }

  var result = new Uint8Array(length);
  result.set(arrayifyValue, length - arrayifyValue.length);
  return addSlice(result);
}
function isHexString(value, length) {
  if (typeof value !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) {
    return false;
  }

  if (length && value.length !== 2 + 2 * length) {
    return false;
  }

  return true;
}
var HexCharacters = '0123456789abcdef';
function hexlify(value) {
  if (isHexable(value)) {
    return value.toHexString();
  }

  if (typeof value === 'number') {
    if (value < 0) {
      throwError('cannot hexlify negative value', INVALID_ARGUMENT, {
        arg: 'value',
        value: value
      });
    } // @TODO: Roll this into the above error as a numeric fault (overflow); next version, not backward compatible
    // We can about (value == MAX_INT) to as well, since that may indicate we underflowed already


    if (value >= 9007199254740991) {
      throwError('out-of-range', NUMERIC_FAULT, {
        operartion: 'hexlify',
        fault: 'out-of-safe-range'
      });
    }

    var hex = '';

    while (value) {
      hex = HexCharacters[value & 0x0f] + hex;
      value = Math.floor(value / 16);
    }

    if (hex.length) {
      if (hex.length % 2) {
        hex = '0' + hex;
      }

      return '0x' + hex;
    }

    return '0x00';
  }

  if (typeof value === 'string') {
    var match = value.match(/^(0x)?[0-9a-fA-F]*$/);

    if (!match) {
      throwError('invalid hexidecimal string', INVALID_ARGUMENT, {
        arg: 'value',
        value: value
      });
    }

    if (match !== null && match[1] !== '0x') {
      throwError('hex string must have 0x prefix', INVALID_ARGUMENT, {
        arg: 'value',
        value: value
      });
    }

    if (value.length % 2) {
      value = '0x0' + value.substring(2);
    }

    return value;
  }

  if (isArrayish(value)) {
    var result = []; // tslint:disable-next-line: prefer-for-of

    for (var i = 0; i < value.length; i++) {
      var v = value[i];
      result.push(HexCharacters[(v & 0xf0) >> 4] + HexCharacters[v & 0x0f]);
    }

    return '0x' + result.join('');
  }

  throwError('invalid hexlify value', null, {
    arg: 'value',
    value: value
  });
  return 'never';
}
function hexDataLength(data) {
  if (!isHexString(data) || data.length % 2 !== 0) {
    return null;
  }

  return (data.length - 2) / 2;
}
function hexDataSlice(data, offset, endOffset) {
  if (!isHexString(data)) {
    throwError('invalid hex data', INVALID_ARGUMENT, {
      arg: 'value',
      value: data
    });
  }

  if (data.length % 2 !== 0) {
    throwError('hex data length must be even', INVALID_ARGUMENT, {
      arg: 'value',
      value: data
    });
  }

  offset = 2 + 2 * offset;

  if (endOffset != null) {
    return '0x' + data.substring(offset, 2 + 2 * endOffset);
  }

  return '0x' + data.substring(offset);
}
function hexStripZeros(value) {
  if (!isHexString(value)) {
    throwError('invalid hex string', INVALID_ARGUMENT, {
      arg: 'value',
      value: value
    });
  }

  while (value.length > 3 && value.substring(0, 3) === '0x0') {
    value = '0x' + value.substring(3);
  }

  return value;
}
function hexZeroPad(value, length) {
  if (!isHexString(value)) {
    throwError('invalid hex string', INVALID_ARGUMENT, {
      arg: 'value',
      value: value
    });
  }

  while (value.length < 2 * length + 2) {
    value = '0x0' + value.substring(2);
  }

  return value;
}
function bytesPadLeft(value, byteLength) {
  if (!isHexString(value)) {
    throwError('invalid hex string', INVALID_ARGUMENT, {
      arg: 'value',
      value: value
    });
  }

  var striped = value.substring(2);

  if (striped.length > byteLength * 2) {
    throw new Error("hex string length = " + striped.length + " beyond byteLength=" + byteLength);
  }

  var padLength = byteLength * 2 - striped.length;
  var returnValue = '0x' + '0'.repeat(padLength) + striped;
  return returnValue;
}
function bytesPadRight(value, byteLength) {
  if (!isHexString(value)) {
    throwError('invalid hex string', INVALID_ARGUMENT, {
      arg: 'value',
      value: value
    });
  }

  var striped = value.substring(2);

  if (striped.length > byteLength * 2) {
    throw new Error("hex string length = " + striped.length + " beyond byteLength=" + byteLength);
  }

  var padLength = byteLength * 2 - striped.length;
  var returnValue = '0x' + striped + '0'.repeat(padLength);
  return returnValue;
}
function isSignature(value) {
  return value && value.r != null && value.s != null;
}
function splitSignature(signature) {
  if (signature !== undefined) {
    var v = 0;
    var r = '0x';
    var s = '0x';

    if (isSignature(signature)) {
      if (signature.v == null && signature.recoveryParam == null) {
        throwError('at least on of recoveryParam or v must be specified', INVALID_ARGUMENT, {
          argument: 'signature',
          value: signature
        });
      }

      r = hexZeroPad(signature.r, 32);
      s = hexZeroPad(signature.s, 32);
      v = signature.v || 0;

      if (typeof v === 'string') {
        v = parseInt(v, 16);
      }

      var recoveryParam = signature.recoveryParam || 0;

      if (recoveryParam == null && signature.v != null) {
        recoveryParam = 1 - v % 2;
      }

      v = 27 + recoveryParam;
    } else {
      var bytes = arrayify(signature) || new Uint8Array();

      if (bytes.length !== 65) {
        throw new Error('invalid signature');
      }

      r = hexlify(bytes.slice(0, 32));
      s = hexlify(bytes.slice(32, 64));
      v = bytes[64];

      if (v !== 27 && v !== 28) {
        v = 27 + v % 2;
      }
    }

    return {
      r: r,
      s: s,
      recoveryParam: v - 27,
      v: v
    };
  } else {
    throw new Error('signature is not found');
  }
}
function joinSignature(signature) {
  signature = splitSignature(signature);
  return hexlify(concat([signature.r, signature.s, signature.recoveryParam ? '0x1c' : '0x1b']));
}
/**
 * hexToByteArray
 *
 * Convers a hex string to a Uint8Array
 *
 * @param {string} hex
 * @returns {Uint8Array}
 */

var hexToByteArray = function hexToByteArray(hex) {
  var res = new Uint8Array(hex.length / 2);

  for (var i = 0; i < hex.length; i += 2) {
    res[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return res;
};
/**
 * hexToIntArray
 *
 * @param {string} hex
 * @returns {number[]}
 */

var hexToIntArray = function hexToIntArray(hex) {
  if (!hex || !isHex(hex)) {
    return [];
  }

  var res = [];

  for (var i = 0; i < hex.length; i++) {
    var c = hex.charCodeAt(i);
    var hi = c >> 8;
    var lo = c & 0xff;
    hi ? res.push(hi, lo) : res.push(lo);
  }

  return res;
};
/**
 * isHex
 *
 * @param {string} str - string to be tested
 * @returns {boolean}
 */

var isHex = function isHex(str) {
  var plain = str.replace('0x', '');
  return /[0-9a-f]*$/i.test(plain);
};

/**
 * @packageDocumentation
 * @module avalanche-crypto
 * @ignore
 */
function keccak256(data) {
  var arrayified = arrayify(data);

  if (arrayified) {
    return '0x' + sha3.keccak_256(arrayified);
  }

  throw new Error('arrayify failed');
} // export function sha3_256(data: Arrayish): string {
//   const arrayified = arrayify(data);
//   if (arrayified) {
//     return '0x' + sha3.sha3_256(arrayified);
//   }
//   throw new Error('arrayify failed');
// }

/**
 * @packageDocumentation
 * @module avalanche-crypto
 * @hidden
 */
// Copyright (c) 2017 Pieter Wuille
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
var GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

var polymod = function polymod(values) {
  var chk = 1; // tslint:disable-next-line

  for (var p = 0; p < values.length; ++p) {
    var top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ values[p];

    for (var i = 0; i < 5; ++i) {
      if (top >> i & 1) {
        chk ^= GENERATOR[i];
      }
    }
  }

  return chk;
};

var hrpExpand = function hrpExpand(hrp) {
  var ret = [];
  var p;

  for (p = 0; p < hrp.length; ++p) {
    ret.push(hrp.charCodeAt(p) >> 5);
  }

  ret.push(0);

  for (p = 0; p < hrp.length; ++p) {
    ret.push(hrp.charCodeAt(p) & 31);
  }

  return Buffer.from(ret);
};

function verifyChecksum(hrp, data) {
  return polymod(Buffer.concat([hrpExpand(hrp), data])) === 1;
}

function createChecksum(hrp, data) {
  var values = Buffer.concat([Buffer.from(hrpExpand(hrp)), data, Buffer.from([0, 0, 0, 0, 0, 0])]); // var values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);

  var mod = polymod(values) ^ 1;
  var ret = [];

  for (var p = 0; p < 6; ++p) {
    ret.push(mod >> 5 * (5 - p) & 31);
  }

  return Buffer.from(ret);
}

var bech32Encode = function bech32Encode(hrp, data) {
  var combined = Buffer.concat([data, createChecksum(hrp, data)]);
  var ret = hrp + '1'; // tslint:disable-next-line

  for (var p = 0; p < combined.length; ++p) {
    ret += CHARSET.charAt(combined[p]);
  }

  return ret;
};
var bech32Decode = function bech32Decode(bechString) {
  var p;
  var hasLower = false;
  var hasUpper = false;

  for (p = 0; p < bechString.length; ++p) {
    if (bechString.charCodeAt(p) < 33 || bechString.charCodeAt(p) > 126) {
      return null;
    }

    if (bechString.charCodeAt(p) >= 97 && bechString.charCodeAt(p) <= 122) {
      hasLower = true;
    }

    if (bechString.charCodeAt(p) >= 65 && bechString.charCodeAt(p) <= 90) {
      hasUpper = true;
    }
  }

  if (hasLower && hasUpper) {
    return null;
  }

  bechString = bechString.toLowerCase();
  var pos = bechString.lastIndexOf('1');

  if (pos < 1 || pos + 7 > bechString.length || bechString.length > 90) {
    return null;
  }

  var hrp = bechString.substring(0, pos);
  var data = [];

  for (p = pos + 1; p < bechString.length; ++p) {
    var d = CHARSET.indexOf(bechString.charAt(p));

    if (d === -1) {
      return null;
    }

    data.push(d);
  }

  if (!verifyChecksum(hrp, Buffer.from(data))) {
    return null;
  }

  return {
    hrp: hrp,
    data: Buffer.from(data.slice(0, data.length - 6))
  };
}; // HRP is the human-readable part of Avalanche bech32 addresses

var HRP = 'avax';
var tHRP = 'tavax';
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

var convertBits = function convertBits(data, fromWidth, toWidth, pad) {
  if (pad === void 0) {
    pad = true;
  }

  var acc = 0;
  var bits = 0;
  var ret = [];
  var maxv = (1 << toWidth) - 1; // tslint:disable-next-line

  for (var p = 0; p < data.length; ++p) {
    var value = data[p];

    if (value < 0 || value >> fromWidth !== 0) {
      return null;
    }

    acc = acc << fromWidth | value;
    bits += fromWidth;

    while (bits >= toWidth) {
      bits -= toWidth;
      ret.push(acc >> bits & maxv);
    }
  }

  if (pad) {
    if (bits > 0) {
      ret.push(acc << toWidth - bits & maxv);
    }
  } else if (bits >= fromWidth || acc << toWidth - bits & maxv) {
    return null;
  }

  return Buffer.from(ret);
};
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

var toBech32 = function toBech32(address, useHRP) {
  if (useHRP === void 0) {
    useHRP = HRP;
  }

  if (!avalancheJsUtils.isAddress(address)) {
    throw new Error('Invalid address format.');
  }

  var addrBz = convertBits(Buffer.from(address.replace('0x', ''), 'hex'), 8, 5);

  if (addrBz === null) {
    throw new Error('Could not convert byte Buffer to 5-bit Buffer');
  }

  return bech32Encode(useHRP, addrBz);
};
/**
 * fromBech32Address
 *
 * @param {string} address - a valid Avalanche bech32 address
 * @returns {string} a canonical 20-byte Ethereum-style address
 */

var fromBech32 = function fromBech32(address, useHRP) {
  if (useHRP === void 0) {
    useHRP = HRP;
  }

  var res = bech32Decode(address);

  if (res === null) {
    throw new Error('Invalid bech32 address');
  }

  var hrp = res.hrp,
      data = res.data;

  if (hrp !== useHRP) {
    throw new Error("Expected hrp to be " + useHRP + " but got " + hrp);
  }

  var buf = convertBits(data, 5, 8, false);

  if (buf === null) {
    throw new Error('Could not convert buffer to bytes');
  }

  return toChecksumAddress('0x' + buf.toString('hex'));
};

/**
 * @packageDocumentation
 * @module avalanche-crypto
 * @hidden
 */

function arrayifyInteger(value) {
  var result = [];

  while (value) {
    result.unshift(value & 0xff);
    value >>= 8;
  }

  return result;
}

function unarrayifyInteger(data, offset, length) {
  var result = 0;

  for (var i = 0; i < length; i++) {
    result = result * 256 + data[offset + i];
  }

  return result;
}

function _encode(object) {
  if (Array.isArray(object)) {
    var payload = [];
    object.forEach(function (child) {
      payload = payload.concat(_encode(child));
    });

    if (payload.length <= 55) {
      payload.unshift(0xc0 + payload.length);
      return payload;
    } // tslint:disable-next-line: no-shadowed-variable


    var _length = arrayifyInteger(payload.length);

    _length.unshift(0xf7 + _length.length);

    return _length.concat(payload);
  }

  var data = Array.prototype.slice.call(arrayify(object));

  if (data.length === 1 && data[0] <= 0x7f) {
    return data;
  } else if (data.length <= 55) {
    data.unshift(0x80 + data.length);
    return data;
  }

  var length = arrayifyInteger(data.length);
  length.unshift(0xb7 + length.length);
  return length.concat(data);
}

function encode(object) {
  return hexlify(_encode(object));
}

function _decodeChildren(data, offset, childOffset, length) {
  var result = [];

  while (childOffset < offset + 1 + length) {
    var decoded = _decode(data, childOffset);

    result.push(decoded.result);
    childOffset += decoded.consumed;

    if (childOffset > offset + 1 + length) {
      throw new Error('invalid rlp');
    }
  }

  return {
    consumed: 1 + length,
    result: result
  };
} // returns { consumed: number, result: Object }


function _decode(data, offset) {
  if (data.length === 0) {
    throw new Error('invalid rlp data');
  } // Array with extra length prefix


  if (data[offset] >= 0xf8) {
    var lengthLength = data[offset] - 0xf7;

    if (offset + 1 + lengthLength > data.length) {
      throw new Error('too short');
    }

    var length = unarrayifyInteger(data, offset + 1, lengthLength);

    if (offset + 1 + lengthLength + length > data.length) {
      throw new Error('to short');
    }

    return _decodeChildren(data, offset, offset + 1 + lengthLength, lengthLength + length);
  } else if (data[offset] >= 0xc0) {
    var _length2 = data[offset] - 0xc0;

    if (offset + 1 + _length2 > data.length) {
      throw new Error('invalid rlp data');
    }

    return _decodeChildren(data, offset, offset + 1, _length2);
  } else if (data[offset] >= 0xb8) {
    var _lengthLength = data[offset] - 0xb7;

    if (offset + 1 + _lengthLength > data.length) {
      throw new Error('invalid rlp data');
    }

    var _length3 = unarrayifyInteger(data, offset + 1, _lengthLength);

    if (offset + 1 + _lengthLength + _length3 > data.length) {
      throw new Error('invalid rlp data');
    }

    var result = hexlify(data.slice(offset + 1 + _lengthLength, offset + 1 + _lengthLength + _length3));
    return {
      consumed: 1 + _lengthLength + _length3,
      result: result
    };
  } else if (data[offset] >= 0x80) {
    var _length4 = data[offset] - 0x80;

    if (offset + 1 + _length4 > data.length) {
      throw new Error('invlaid rlp data');
    }

    var _result = hexlify(data.slice(offset + 1, offset + 1 + _length4));

    return {
      consumed: 1 + _length4,
      result: _result
    };
  }

  return {
    consumed: 1,
    result: hexlify(data[offset])
  };
}

function decode(data) {
  var bytes = arrayify(data) || new Uint8Array();

  var decoded = _decode(bytes, 0);

  if (decoded.consumed !== bytes.length) {
    throw new Error('invalid rlp data');
  }

  return decoded.result;
}

/**
 * @packageDocumentation
 * @module avalanche-crypto
 */
var secp256k1 = /*#__PURE__*/elliptic.ec('secp256k1');
/**
 * @function generatePrivateKey
 * @description generatePrivate key using `eth-lib` settings
 * @return {string}
 */

var generatePrivateKey = function generatePrivateKey() {
  var entropy = '0x' + randomBytes(16);
  var innerHex = keccak256(concat(['0x' + randomBytes(32), entropy || '0x' + randomBytes(32)]));
  var middleHex = concat([concat(['0x' + randomBytes(32), innerHex]), '0x' + randomBytes(32)]);
  var outerHex = keccak256(middleHex);
  return outerHex;
};
/**
 * @function getPubkeyFromPrivateKey
 * @param  {string} privateKey - private key String
 * @return {string}
 */

var getPubkeyFromPrivateKey = function getPubkeyFromPrivateKey(privateKey) {
  return '0x' + getPublic(privateKey, true);
};
/**
 * @function getAddressFromPrivateKey
 * @param  {string} privateKey - private key string
 * @return {string} address with `length = 40`
 */

var getAddressFromPrivateKey = function getAddressFromPrivateKey(privateKey) {
  var publicHash = '0x' + getPublic(privateKey).slice(2);
  var publicKey = keccak256(publicHash);
  var address = '0x' + publicKey.slice(-40);
  return address;
};
var getPublic = function getPublic(privateKey, compress) {
  if (!avalancheJsUtils.isPrivateKey(privateKey) || !validatePrivateKey(privateKey)) {
    throw new Error(privateKey + " is not PrivateKey");
  }

  var ecKey = secp256k1.keyFromPrivate(avalancheJsUtils.strip0x(privateKey), 'hex');
  return ecKey.getPublic(compress || false, 'hex');
};
/**
 * @function getAddressFromPublicKey
 * @param  {string} publicKey - public key string
 * @return {string} address with `length = 40`
 */

var getAddressFromPublicKey = function getAddressFromPublicKey(publicKey) {
  var ecKey = secp256k1.keyFromPublic(publicKey.slice(2), 'hex');
  var publicHash = ecKey.getPublic(false, 'hex');
  var address = '0x' + keccak256('0x' + publicHash.slice(2)).slice(-40);
  return address;
};
/**
 * @function toChecksumAddress
 * @param  {string} address - raw address
 * @return {string} checksumed address
 */

var toChecksumAddress = function toChecksumAddress(address) {
  if (typeof address === 'string' && avalancheJsUtils.isBech32Address(address)) {
    address = fromBech32(address);
  }

  if (typeof address !== 'string' || !address.match(/^0x[0-9A-Fa-f]{40}$/)) {
    throwError('invalid address', INVALID_ARGUMENT, {
      arg: 'address',
      value: address
    });
  }

  address = address.toLowerCase();
  var chars = address.substring(2).split('');
  var hashed = new Uint8Array(40);

  for (var i = 0; i < 40; i++) {
    hashed[i] = chars[i].charCodeAt(0);
  }

  hashed = arrayify(keccak256(hashed)) || hashed;

  for (var _i = 0; _i < 40; _i += 2) {
    if (hashed[_i >> 1] >> 4 >= 8) {
      chars[_i] = chars[_i].toUpperCase();
    }

    if ((hashed[_i >> 1] & 0x0f) >= 8) {
      chars[_i + 1] = chars[_i + 1].toUpperCase();
    }
  }

  return '0x' + chars.join('');
};
var sign = function sign(digest, privateKey) {
  if (!avalancheJsUtils.isPrivateKey(privateKey)) {
    throw new Error(privateKey + " is not PrivateKey");
  }

  var keyPair = secp256k1.keyFromPrivate(avalancheJsUtils.strip0x(privateKey), 'hex');
  var signature = keyPair.sign(arrayify(digest), {
    canonical: true
  });
  var publicKey = '0x' + keyPair.getPublic(true, 'hex');
  var result = {
    recoveryParam: signature.recoveryParam,
    r: hexZeroPad('0x' + signature.r.toString(16), 32),
    s: hexZeroPad('0x' + signature.s.toString(16), 32),
    v: 27 + signature.recoveryParam
  };

  if (verifySignature(digest, result, publicKey)) {
    return result;
  } else {
    throw new Error('signing process failed');
  }
};
function getContractAddress(from, nonce) {
  if (!from) {
    throw new Error('missing from address');
  }

  var addr = keccak256(encode([from, stripZeros(hexlify(nonce))]));
  return '0x' + addr.substring(26);
}
function verifySignature(digest, signature, publicKey) {
  return recoverPublicKey(digest, signature) === publicKey;
}
function recoverPublicKey(digest, signature) {
  var sig = splitSignature(signature);
  var rs = {
    r: arrayify(sig.r),
    s: arrayify(sig.s)
  }; ////

  var recovered = secp256k1.recoverPubKey(arrayify(digest), rs, sig.recoveryParam);
  var key = recovered.encode('hex', false);
  var ecKey = secp256k1.keyFromPublic(key, 'hex');
  var publicKey = '0x' + ecKey.getPublic(true, 'hex'); ///

  return publicKey;
}
function recoverAddress(digest, signature) {
  return getAddressFromPublicKey(recoverPublicKey(arrayify(digest) || new Uint8Array(), signature));
}
/**
 * isValidChecksumAddress
 *
 * takes hex-encoded string and returns boolean if address is checksumed
 *
 * @param {string} address
 * @returns {boolean}
 */

var isValidChecksumAddress = function isValidChecksumAddress(address) {
  return avalancheJsUtils.isAddress(address.replace('0x', '')) && toChecksumAddress(address) === address;
};
var validatePrivateKey = function validatePrivateKey(privateKey) {
  var ecKey = secp256k1.keyFromPrivate(avalancheJsUtils.strip0x(privateKey), 'hex');

  var _ecKey$validate = ecKey.validate(),
      result = _ecKey$validate.result;

  return result;
};

function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) {
  try {
    var info = gen[key](arg);
    var value = info.value;
  } catch (error) {
    reject(error);
    return;
  }

  if (info.done) {
    resolve(value);
  } else {
    Promise.resolve(value).then(_next, _throw);
  }
}

function _asyncToGenerator(fn) {
  return function () {
    var self = this,
        args = arguments;
    return new Promise(function (resolve, reject) {
      var gen = fn.apply(self, args);

      function _next(value) {
        asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value);
      }

      function _throw(err) {
        asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err);
      }

      _next(undefined);
    });
  };
}

function _defineProperties(target, props) {
  for (var i = 0; i < props.length; i++) {
    var descriptor = props[i];
    descriptor.enumerable = descriptor.enumerable || false;
    descriptor.configurable = true;
    if ("value" in descriptor) descriptor.writable = true;
    Object.defineProperty(target, descriptor.key, descriptor);
  }
}

function _createClass(Constructor, protoProps, staticProps) {
  if (protoProps) _defineProperties(Constructor.prototype, protoProps);
  if (staticProps) _defineProperties(Constructor, staticProps);
  Object.defineProperty(Constructor, "prototype", {
    writable: false
  });
  return Constructor;
}

/** @hidden */

var DEFAULT_ALGORITHM = 'aes-128-ctr';
/**
 * getDerivedKey
 *
 * NOTE: only scrypt and pbkdf2 are supported.
 *
 * @param {Buffer} key - the passphrase
 * @param {KDF} kdf - the key derivation function to be used
 * @param {KDFParams} params - params for the kdf
 *
 * @returns {Promise<Buffer>}
 */

function getDerivedKey(_x, _x2, _x3) {
  return _getDerivedKey.apply(this, arguments);
}
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


function _getDerivedKey() {
  _getDerivedKey = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime.mark(function _callee5(key, kdf, params) {
    var salt, c, dklen, n, r, p, _dklen;

    return _regeneratorRuntime.wrap(function _callee5$(_context5) {
      while (1) {
        switch (_context5.prev = _context5.next) {
          case 0:
            salt = Buffer.from(params.salt, 'hex');

            if (!(kdf === 'pbkdf2')) {
              _context5.next = 4;
              break;
            }

            c = params.c, dklen = params.dklen;
            return _context5.abrupt("return", pbkdf2.pbkdf2Sync(key, salt, c, dklen, 'sha256'));

          case 4:
            if (!(kdf === 'scrypt')) {
              _context5.next = 7;
              break;
            }

            n = params.n, r = params.r, p = params.p, _dklen = params.dklen;
            return _context5.abrupt("return", scrypt(key, salt, n, r, p, _dklen));

          case 7:
            throw new Error('Only pbkdf2 and scrypt are supported');

          case 8:
          case "end":
            return _context5.stop();
        }
      }
    }, _callee5);
  }));
  return _getDerivedKey.apply(this, arguments);
}

var encrypt = /*#__PURE__*/function () {
  var _ref = /*#__PURE__*/_asyncToGenerator( /*#__PURE__*/_regeneratorRuntime.mark(function _callee(privateKey, password, options) {
    var address, salt, iv, kdf, level, uuidRandom, n, kdfparams, derivedKey, cipher, ciphertext, mac;
    return _regeneratorRuntime.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            if (avalancheJsUtils.isPrivateKey(privateKey)) {
              _context.next = 2;
              break;
            }

            throw new Error('privateKey is not correct');

          case 2:
            if (!(typeof password !== 'string')) {
              _context.next = 4;
              break;
            }

            throw new Error('password is not found');

          case 4:
            address = getAddressFromPrivateKey(privateKey);
            salt = randomBytes(32);
            iv = Buffer.from(randomBytes(16), 'hex');
            kdf = options !== undefined ? options.kdf ? options.kdf : 'scrypt' : 'scrypt';
            level = options !== undefined ? options.level ? options.level : 8192 : 8192;
            uuidRandom = options !== undefined ? options.uuid : undefined;
            n = kdf === 'pbkdf2' ? 262144 : level;
            kdfparams = {
              salt: salt,
              n: n,
              r: 8,
              p: 1,
              dklen: 32
            };
            _context.next = 14;
            return getDerivedKey(Buffer.from(password), kdf, kdfparams);

          case 14:
            derivedKey = _context.sent;
            cipher = new aes.ModeOfOperation.ctr(derivedKey.slice(0, 16), new aes.Counter(iv));

            if (cipher) {
              _context.next = 18;
              break;
            }

            throw new Error('Unsupported cipher');

          case 18:
            ciphertext = Buffer.from(cipher.encrypt(Buffer.from(privateKey.replace('0x', ''), 'hex')));
            mac = keccak256(concat([derivedKey.slice(16, 32), ciphertext]));
            return _context.abrupt("return", JSON.stringify({
              version: 3,
              id: uuid.v4({
                random: uuidRandom || hexToIntArray(randomBytes(16))
              }),
              address: address.toLowerCase().replace('0x', ''),
              crypto: {
                ciphertext: ciphertext.toString('hex'),
                cipherparams: {
                  iv: iv.toString('hex')
                },
                cipher: DEFAULT_ALGORITHM,
                kdf: kdf,
                kdfparams: kdfparams,
                mac: mac.replace('0x', '')
              }
            }));

          case 21:
          case "end":
            return _context.stop();
        }
      }
    }, _callee);
  }));

  return function encrypt(_x4, _x5, _x6) {
    return _ref.apply(this, arguments);
  };
}();
/**
 * @function decrypt
 * @param  {Keystore} keystore - Keystore file
 * @param  {string} password - password string
 * @return {string} privateKey
 */

var decrypt = /*#__PURE__*/function () {
  var _ref2 = /*#__PURE__*/_asyncToGenerator( /*#__PURE__*/_regeneratorRuntime.mark(function _callee2(keystore, password) {
    var ciphertext, iv, kdfparams, derivedKey, mac, CTR, cipher, decrypted;
    return _regeneratorRuntime.wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            ciphertext = Buffer.from(keystore.crypto.ciphertext, 'hex');
            iv = Buffer.from(keystore.crypto.cipherparams.iv, 'hex');
            kdfparams = keystore.crypto.kdfparams;
            _context2.next = 5;
            return getDerivedKey(Buffer.from(password), keystore.crypto.kdf, kdfparams);

          case 5:
            derivedKey = _context2.sent;
            mac = keccak256(concat([derivedKey.slice(16, 32), ciphertext])).replace('0x', '');

            if (!(mac.toUpperCase() !== keystore.crypto.mac.toUpperCase())) {
              _context2.next = 9;
              break;
            }

            return _context2.abrupt("return", Promise.reject(new Error('Failed to decrypt.')));

          case 9:
            CTR = aes.ModeOfOperation.ctr;
            cipher = new CTR(derivedKey.slice(0, 16), new aes.Counter(iv));
            decrypted = '0x' + Buffer.from(cipher.decrypt(ciphertext)).toString('hex');
            return _context2.abrupt("return", decrypted);

          case 13:
          case "end":
            return _context2.stop();
        }
      }
    }, _callee2);
  }));

  return function decrypt(_x7, _x8) {
    return _ref2.apply(this, arguments);
  };
}();
/**
 * encrypt Phrase
 */

var encryptPhrase = /*#__PURE__*/function () {
  var _ref3 = /*#__PURE__*/_asyncToGenerator( /*#__PURE__*/_regeneratorRuntime.mark(function _callee3(phrase, password, options) {
    var salt, iv, kdf, level, uuidRandom, n, kdfparams, derivedKey, cipher, ciphertext, mac;
    return _regeneratorRuntime.wrap(function _callee3$(_context3) {
      while (1) {
        switch (_context3.prev = _context3.next) {
          case 0:
            if (!(typeof password !== 'string')) {
              _context3.next = 2;
              break;
            }

            throw new Error('password is not found');

          case 2:
            salt = randomBytes(32);
            iv = Buffer.from(randomBytes(16), 'hex');
            kdf = options !== undefined ? options.kdf ? options.kdf : 'scrypt' : 'scrypt';
            level = options !== undefined ? options.level ? options.level : 8192 : 8192;
            uuidRandom = options !== undefined ? options.uuid : undefined;
            n = kdf === 'pbkdf2' ? 262144 : level;
            kdfparams = {
              salt: salt,
              n: n,
              r: 8,
              p: 1,
              dklen: 32
            };
            _context3.next = 11;
            return getDerivedKey(Buffer.from(password), kdf, kdfparams);

          case 11:
            derivedKey = _context3.sent;
            cipher = new aes.ModeOfOperation.ctr(derivedKey.slice(0, 16), new aes.Counter(iv));

            if (cipher) {
              _context3.next = 15;
              break;
            }

            throw new Error('Unsupported cipher');

          case 15:
            ciphertext = Buffer.from(cipher.encrypt(Buffer.from(phrase)));
            mac = keccak256(concat([derivedKey.slice(16, 32), ciphertext]));
            return _context3.abrupt("return", JSON.stringify({
              version: 3,
              id: uuid.v4({
                random: uuidRandom || hexToIntArray(randomBytes(16))
              }),
              crypto: {
                ciphertext: ciphertext.toString('hex'),
                cipherparams: {
                  iv: iv.toString('hex')
                },
                cipher: DEFAULT_ALGORITHM,
                kdf: kdf,
                kdfparams: kdfparams,
                mac: mac.replace('0x', '')
              }
            }));

          case 18:
          case "end":
            return _context3.stop();
        }
      }
    }, _callee3);
  }));

  return function encryptPhrase(_x9, _x10, _x11) {
    return _ref3.apply(this, arguments);
  };
}();
/**
 * decrypt phrase
 */

var decryptPhrase = /*#__PURE__*/function () {
  var _ref4 = /*#__PURE__*/_asyncToGenerator( /*#__PURE__*/_regeneratorRuntime.mark(function _callee4(keystore, password) {
    var result;
    return _regeneratorRuntime.wrap(function _callee4$(_context4) {
      while (1) {
        switch (_context4.prev = _context4.next) {
          case 0:
            _context4.next = 2;
            return decrypt(keystore, password);

          case 2:
            result = _context4.sent;
            return _context4.abrupt("return", Buffer.from(result.replace('0x', ''), 'hex').toString());

          case 4:
          case "end":
            return _context4.stop();
        }
      }
    }, _callee4);
  }));

  return function decryptPhrase(_x12, _x13) {
    return _ref4.apply(this, arguments);
  };
}();

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

var AvalancheAddress = /*#__PURE__*/function () {
  function AvalancheAddress(raw) {
    this.raw = raw;
    this.basic = this.getBasic(this.raw);
  }
  /**
   * @example
   * ```
   * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
   * const res = AvalancheAddress.isValidBech32(addr);
   * console.log(res);
   * ```
   */


  AvalancheAddress.isValidBasic = function isValidBasic(str) {
    var toTest = new AvalancheAddress(str);
    return toTest.raw === toTest.basic;
  }
  /**
   * @example
   * ```
   * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
   * const res = AvalancheAddress.isValidChecksum(addr);
   * console.log(res);
   * ```
   */
  ;

  AvalancheAddress.isValidChecksum = function isValidChecksum(str) {
    var toTest = new AvalancheAddress(str);
    return toTest.raw === toTest.checksum;
  }
  /**
   * @example
   * ```
   * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
   * const res = AvalancheAddress.isValidBech32(addr);
   * console.log(res);
   * ```
   */
  ;

  AvalancheAddress.isValidBech32 = function isValidBech32(str) {
    var toTest = new AvalancheAddress(str);
    return toTest.raw === toTest.bech32;
  }
  /**
   * @example
   * ```
   * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
   * const res = AvalancheAddress.isValidBech32TestNet(addr);
   * console.log(res);
   * ```
   */
  ;

  AvalancheAddress.isValidBech32TestNet = function isValidBech32TestNet(str) {
    var toTest = new AvalancheAddress(str);
    return toTest.raw === toTest.bech32TestNet;
  }
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
  ;

  var _proto = AvalancheAddress.prototype;

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
  _proto.getBasic = function getBasic(addr) {
    var basicBool = avalancheJsUtils.isAddress(addr);
    var bech32Bool = avalancheJsUtils.isBech32Address(addr);
    var bech32TestNetBool = avalancheJsUtils.isBech32TestNetAddress(addr);

    if (basicBool) {
      return addr.replace('0x', '').toLowerCase();
    }

    if (bech32Bool) {
      var fromB32 = fromBech32(addr, HRP);
      return fromB32.replace('0x', '').toLowerCase();
    }

    if (bech32TestNetBool) {
      var fromB32TestNet = fromBech32(addr, tHRP);
      return fromB32TestNet.replace('0x', '').toLowerCase();
    }

    throw new Error("\"" + addr + "\" is an invalid address format");
  };

  _createClass(AvalancheAddress, [{
    key: "basicHex",
    get: function get() {
      return "0x" + this.basic;
    }
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const instance = new AvalancheAddress(addr);
     * console.log(instance.checksum);
     * ```
     */

  }, {
    key: "checksum",
    get: function get() {
      return toChecksumAddress("0x" + this.basic);
    }
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const instance = new AvalancheAddress(addr);
     * console.log(instance.bech32);
     * ```
     */

  }, {
    key: "bech32",
    get: function get() {
      return toBech32(this.basic, HRP);
    }
    /**
     * @example
     * ```
     * const addr = 'avax103q7qe5t2505lypvltkqtddaef5tzfxwsse4z7'
     * const instance = new AvalancheAddress(addr);
     * console.log(instance.bech32TestNet);
     * ```
     */

  }, {
    key: "bech32TestNet",
    get: function get() {
      return toBech32(this.basic, tHRP);
    }
  }]);

  return AvalancheAddress;
}();
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

function getAddress(address) {
  try {
    return new AvalancheAddress(address);
  } catch (error) {
    throw error;
  }
}

exports.hdkey = hdkey;
exports.bip39 = bip39;
exports.BN = bn_js;
exports.AvalancheAddress = AvalancheAddress;
exports.CALL_EXCEPTION = CALL_EXCEPTION;
exports.HRP = HRP;
exports.INSUFFICIENT_FUNDS = INSUFFICIENT_FUNDS;
exports.INVALID_ARGUMENT = INVALID_ARGUMENT;
exports.MISSING_ARGUMENT = MISSING_ARGUMENT;
exports.MISSING_NEW = MISSING_NEW;
exports.NONCE_EXPIRED = NONCE_EXPIRED;
exports.NOT_IMPLEMENTED = NOT_IMPLEMENTED;
exports.NUMERIC_FAULT = NUMERIC_FAULT;
exports.REPLACEMENT_UNDERPRICED = REPLACEMENT_UNDERPRICED;
exports.UNEXPECTED_ARGUMENT = UNEXPECTED_ARGUMENT;
exports.UNKNOWN_ERROR = UNKNOWN_ERROR;
exports.UNSUPPORTED_OPERATION = UNSUPPORTED_OPERATION;
exports.arrayify = arrayify;
exports.bech32Decode = bech32Decode;
exports.bech32Encode = bech32Encode;
exports.bytesPadLeft = bytesPadLeft;
exports.bytesPadRight = bytesPadRight;
exports.checkArgumentCount = checkArgumentCount;
exports.checkNew = checkNew;
exports.checkNormalize = checkNormalize;
exports.concat = concat;
exports.convertBits = convertBits;
exports.decode = decode;
exports.decrypt = decrypt;
exports.decryptPhrase = decryptPhrase;
exports.encode = encode;
exports.encrypt = encrypt;
exports.encryptPhrase = encryptPhrase;
exports.fromBech32 = fromBech32;
exports.generatePrivateKey = generatePrivateKey;
exports.getAddress = getAddress;
exports.getAddressFromPrivateKey = getAddressFromPrivateKey;
exports.getAddressFromPublicKey = getAddressFromPublicKey;
exports.getContractAddress = getContractAddress;
exports.getPubkeyFromPrivateKey = getPubkeyFromPrivateKey;
exports.getPublic = getPublic;
exports.hexDataLength = hexDataLength;
exports.hexDataSlice = hexDataSlice;
exports.hexStripZeros = hexStripZeros;
exports.hexToByteArray = hexToByteArray;
exports.hexToIntArray = hexToIntArray;
exports.hexZeroPad = hexZeroPad;
exports.hexlify = hexlify;
exports.info = info;
exports.isArrayish = isArrayish;
exports.isHex = isHex;
exports.isHexString = isHexString;
exports.isHexable = isHexable;
exports.isSignature = isSignature;
exports.isValidChecksumAddress = isValidChecksumAddress;
exports.joinSignature = joinSignature;
exports.keccak256 = keccak256;
exports.padZeros = padZeros;
exports.randomBytes = randomBytes;
exports.recoverAddress = recoverAddress;
exports.recoverPublicKey = recoverPublicKey;
exports.setCensorship = setCensorship;
exports.setLogLevel = setLogLevel;
exports.sign = sign;
exports.splitSignature = splitSignature;
exports.stripZeros = stripZeros;
exports.tHRP = tHRP;
exports.throwError = throwError;
exports.toBech32 = toBech32;
exports.toChecksumAddress = toChecksumAddress;
exports.validatePrivateKey = validatePrivateKey;
exports.verifySignature = verifySignature;
exports.warn = warn;
//# sourceMappingURL=avalanche-js-crypto.cjs.development.js.map
