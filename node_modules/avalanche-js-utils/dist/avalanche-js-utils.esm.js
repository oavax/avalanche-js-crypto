import BN from 'bn.js';

/**
 * @packageDocumentation
 * @module avalanche-utils
 */
var isKeyString = function isKeyString(keyString, lengh) {
  return !!keyString.replace('0x', '').match("^[0-9a-fA-F]{" + lengh + "}$");
};
isKeyString.validator = 'isKeyString';
var isAddress = function isAddress(address) {
  return isKeyString(address, 40);
};
isAddress.validator = 'isAddress';
var isPrivateKey = function isPrivateKey(privateKey) {
  return isKeyString(privateKey, 64);
};
isPrivateKey.validator = 'isPrivateKey';
var isPublicKey = function isPublicKey(publicKey) {
  return isKeyString(publicKey, 66);
};
isPublicKey.validator = 'isPublicKey';
var isHash = function isHash(hash) {
  return isKeyString(hash, 64);
};
isHash.validator = 'isHash';
/**
 * [isNumber verify param is a Number]
 * @param  {any}  obj [value]
 * @return {Boolean}     [boolean]
 */

var isNumber = function isNumber(obj) {
  return obj === +obj;
};
isNumber.validator = 'isNumber';
/**
 * [isNumber verify param is a Number]
 * @param  {any}  obj [value]
 * @return {boolean}     [boolean]
 */

var isInt = function isInt(obj) {
  return isNumber(obj) && Number.isInteger(obj);
};
isInt.validator = 'isInt';
/**
 * [isString verify param is a String]
 * @param  {any}  obj [value]
 * @return {Boolean}     [boolean]
 */

var isString = function isString(obj) {
  return obj === "" + obj;
};
isString.validator = 'isString';
/**
 * [isBoolean verify param is a Boolean]
 * @param  {any}  obj [value]
 * @return {Boolean}     [boolean]
 */

var isBoolean = function isBoolean(obj) {
  return obj === !!obj;
};
isBoolean.validator = 'isBoolean';
/**
 * [isArray verify param input is an Array]
 * @param  {any}  obj [value]
 * @return {Boolean}     [boolean]
 */

var isArray = function isArray(obj) {
  return Array.isArray(obj);
};
isArray.validator = 'isArray';
/**
 * [isJson verify param input is a Json]
 * @param  {any}  obj [value]
 * @return {Boolean}     [boolean]
 */

var isJsonString = function isJsonString(obj) {
  try {
    return !!JSON.parse(obj) && isObject(JSON.parse(obj));
  } catch (e) {
    return false;
  }
};
isJsonString.validator = 'isJsonString';
/**
 * [isObject verify param is an Object]
 * @param  {any}  obj [value]
 * @return {Boolean}     [boolean]
 */

var isObject = function isObject(obj) {
  return obj !== null && !Array.isArray(obj) && typeof obj === 'object';
};
isObject.validator = 'isObject';
/**
 * [isFunction verify param is a Function]
 * @param  {any}  obj [value]
 * @return {Boolean}     [description]
 */

var isFunction = function isFunction(obj) {
  return typeof obj === 'function';
};
isFunction.validator = 'isFunction';
var isHex = function isHex(obj) {
  if (!isString(obj)) {
    throw new Error(obj + " is not string");
  }

  return (obj.startsWith('0x') || obj.startsWith('-0x')) && isNumber(Number.parseInt(("" + obj).toLowerCase().replace('0x', ''), 16));
};
isHex.validator = 'isHex';
var isHttp = function isHttp(obj) {
  if (!isString(obj)) {
    throw new Error(obj + " is not valid url");
  } else {
    return obj.startsWith('http://') || obj.startsWith('https://');
  }
};
isHttp.validator = 'isHttp';
var isWs = function isWs(obj) {
  if (!isString(obj)) {
    throw new Error(obj + " is not valid url");
  } else {
    return obj.startsWith('ws://') || obj.startsWith('wss://');
  }
};
isWs.validator = 'isWs';
var DefaultBlockParams;

(function (DefaultBlockParams) {
  DefaultBlockParams["earliest"] = "earliest";
  DefaultBlockParams["pending"] = "pending";
  DefaultBlockParams["latest"] = "latest";
})(DefaultBlockParams || (DefaultBlockParams = {}));

var isBlockNumber = function isBlockNumber(obj) {
  var blockParams = [DefaultBlockParams.earliest, DefaultBlockParams.pending, DefaultBlockParams.latest];

  if (!isString(obj)) {
    throw new Error(obj + " is not valid blockNumber");
  }

  return isHex(obj) || blockParams.some(function (val) {
    return val === obj;
  });
};
isBlockNumber.validator = 'isBlockNumber';
var isBech32Address = function isBech32Address(raw) {
  return !!raw.match(/^avax1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}/);
};
isBech32Address.validator = 'isBech32Address';
var isBech32TestNetAddress = function isBech32TestNetAddress(raw) {
  return !!raw.match(/^tavax1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}/);
};
isBech32TestNetAddress.validator = 'isBech32TestNetAddress';
var isValidAddress = function isValidAddress(address) {
  if (!isString(address)) {
    throw new Error(address + " is not string");
  }

  if (isAddress(address) || isBech32Address(address) || isBech32TestNetAddress(address)) {
    return true;
  } else {
    return false;
  }
};
isValidAddress.validator = 'isValidAddress';

/**
 * @packageDocumentation
 * @module avalanche-utils
 */
var Units;

(function (Units) {
  Units["wei"] = "wei";
  Units["Kwei"] = "Kwei";
  Units["Mwei"] = "Mwei";
  Units["Gwei"] = "Gwei";
  Units["szabo"] = "szabo";
  Units["finney"] = "finney";
  Units["ether"] = "ether";
  Units["avax"] = "avax";
  Units["Kether"] = "Kether";
  Units["Mether"] = "Mether";
  Units["Gether"] = "Gether";
  Units["Tether"] = "Tether";
})(Units || (Units = {}));
/** @hidden */


var unitMap = /*#__PURE__*/new Map([[Units.wei, '1'], [Units.Kwei, '1000'], [Units.Mwei, '1000000'], [Units.Gwei, '1000000000'], [Units.szabo, '1000000000000'], [Units.finney, '1000000000000000'], [Units.ether, '1000000000000000000'], [Units.avax, '1000000000000000000'], [Units.Kether, '1000000000000000000000'], [Units.Mether, '1000000000000000000000000'], [Units.Gether, '1000000000000000000000000000'], [Units.Tether, '1000000000000000000000000000000']]);
/** @hidden */

var DEFAULT_OPTIONS = {
  pad: false
};
/**
 * Convert Number to String
 */

var numberToString = function numberToString(obj, radix) {
  if (radix === void 0) {
    radix = 10;
  }

  if (BN.isBN(obj)) {
    return obj.toString(radix);
  } else if (isNumber(obj)) {
    return new BN(obj).toString(radix);
  } else if (isString(obj) && isNumber(Number(obj))) {
    return new BN(obj).toString(radix);
  } else {
    throw new Error("cannot parse number:" + obj + " to string");
  }
};
/**
 * Convert Number to String
 */

var numToStr = function numToStr(input) {
  if (typeof input === 'string') {
    if (!input.match(/^-?[0-9.]+$/)) {
      throw new Error("while converting number to string, invalid number value '" + input + "', should be a number matching (^-?[0-9.]+).");
    }

    return input;
  } else if (typeof input === 'number') {
    return String(input);
  } else if (BN.isBN(input)) {
    return input.toString(10);
  }

  throw new Error("while converting number to string, invalid number value '" + input + "' type " + typeof input + ".");
};
var add0xToString = function add0xToString(obj) {
  if (isString(obj) && !obj.startsWith('-')) {
    return '0x' + obj.replace('0x', '');
  } else if (isString(obj) && obj.startsWith('-')) {
    return '-0x' + obj.replace('-', '');
  } else {
    throw new Error(obj + " is not String");
  }
};
var strip0x = function strip0x(obj) {
  return obj.toLowerCase().replace('0x', '');
};
/**
 * Convert number to hex
 */

var numberToHex = function numberToHex(obj) {
  try {
    return add0xToString(numberToString(obj, 16));
  } catch (error) {
    throw error;
  }
};
/**
 * Convert hex to Decimal number
 */

var hexToNumber = function hexToNumber(hex) {
  if (isHex(hex) && hex[0] !== '-') {
    return new BN(strip0x(hex), 'hex').toString();
  } else if (isHex(hex) && hex[0] === '-') {
    var result = new BN(hex.substring(3), 16);
    return result.mul(new BN(-1)).toString();
  } else {
    throw new Error(hex + " is not hex number");
  }
};
/**
 * Convert hex to Big Number
 */

var hexToBN = function hexToBN(hex) {
  if (isHex(hex) && hex[0] !== '-') {
    return new BN(strip0x(hex), 'hex');
  } else if (isHex(hex) && hex[0] === '-') {
    var result = new BN(hex.substring(3), 16);
    return result.mul(new BN(-1));
  } else {
    throw new Error(hex + " is not hex number");
  }
};
/**
 * Converts any AVAX value into wei
 */

var toWei = function toWei(input, unit) {
  try {
    var inputStr = numToStr(input);
    var baseStr = unitMap.get(unit);

    if (!baseStr) {
      throw new Error("No unit of type " + unit + " exists.");
    }

    var baseNumDecimals = baseStr.length - 1;
    var base = new BN(baseStr, 10); // Is it negative?

    var isNegative = inputStr.substring(0, 1) === '-';

    if (isNegative) {
      inputStr = inputStr.substring(1);
    }

    if (inputStr === '.') {
      throw new Error("Cannot convert " + inputStr + " to wei.");
    } // Split it into a whole and fractional part


    var comps = inputStr.split('.'); // eslint-disable-line

    if (comps.length > 2) {
      throw new Error("Cannot convert " + inputStr + " to wei.");
    }

    var whole = comps[0],
        fraction = comps[1];

    if (!whole) {
      whole = '0';
    }

    if (!fraction) {
      fraction = '0';
    }

    if (fraction.length > baseNumDecimals) {
      throw new Error("Cannot convert " + inputStr + " to wei.");
    }

    while (fraction.length < baseNumDecimals) {
      fraction += '0';
    }

    var wholeBN = new BN(whole);
    var fractionBN = new BN(fraction);
    var wei = wholeBN.mul(base).add(fractionBN);

    if (isNegative) {
      wei = wei.neg();
    }

    return new BN(wei.toString(10), 10);
  } catch (error) {
    throw error;
  }
};
/**
 * Converts any wei value into a AVAX value.
 */

var fromWei = function fromWei(wei, unit, options) {
  if (options === void 0) {
    options = DEFAULT_OPTIONS;
  }

  try {
    var weiBN = !BN.isBN(wei) ? new BN(wei) : wei;

    if (unit === 'wei') {
      return weiBN.toString(10);
    }

    var baseStr = unitMap.get(unit);

    if (!baseStr) {
      throw new Error("No unit of type " + unit + " exists.");
    }

    var base = new BN(baseStr, 10);
    var baseNumDecimals = baseStr.length - 1;
    var fraction = weiBN.abs().mod(base).toString(10); // prepend 0s to the fraction half

    while (fraction.length < baseNumDecimals) {
      fraction = "0" + fraction;
    }

    if (!options.pad) {
      /* eslint-disable prefer-destructuring */
      var matchFraction = fraction.match(/^([0-9]*[1-9]|0)(0*)/);
      fraction = matchFraction ? matchFraction[1] : '0';
    }

    var whole = weiBN.div(base).toString(10);
    return fraction === '0' ? "" + whole : whole + "." + fraction;
  } catch (error) {
    throw error;
  }
};
var Unit = /*#__PURE__*/function () {
  function Unit(str) {
    if (!BN.isBN(str) && typeof str !== 'number' && isHex(str)) {
      this.unit = hexToNumber(str);
    } else if (!BN.isBN(str) && typeof str === 'number') {
      this.unit = str.toString();
    } else if (str === '0x') {
      this.unit = hexToNumber('0x0');
    } else {
      this.unit = str;
    }

    this.wei = new BN(this.unit);
  }

  Unit.from = function from(str) {
    return new Unit(str);
  };

  Unit.Wei = function Wei(str) {
    return new Unit(str).asWei();
  };

  Unit.Kwei = function Kwei(str) {
    return new Unit(str).asKwei();
  };

  Unit.Mwei = function Mwei(str) {
    return new Unit(str).asMwei();
  };

  Unit.Gwei = function Gwei(str) {
    return new Unit(str).asGwei();
  };

  Unit.Szabo = function Szabo(str) {
    return new Unit(str).asSzabo();
  };

  Unit.Finney = function Finney(str) {
    return new Unit(str).asFinney();
  };

  Unit.Ether = function Ether(str) {
    return new Unit(str).asEther();
  };

  Unit.AVAX = function AVAX(str) {
    return new Unit(str).asAVAX();
  };

  Unit.Kether = function Kether(str) {
    return new Unit(str).asKether();
  };

  Unit.Mether = function Mether(str) {
    return new Unit(str).asMether();
  };

  Unit.Gether = function Gether(str) {
    return new Unit(str).asGether();
  };

  Unit.Tether = function Tether(str) {
    return new Unit(str).asTether();
  };

  var _proto = Unit.prototype;

  _proto.asWei = function asWei() {
    this.wei = new BN(this.unit);
    return this;
  };

  _proto.asKwei = function asKwei() {
    this.wei = toWei(this.unit, Units.Kwei);
    return this;
  };

  _proto.asMwei = function asMwei() {
    this.wei = toWei(this.unit, Units.Mwei);
    return this;
  };

  _proto.asGwei = function asGwei() {
    this.wei = toWei(this.unit, Units.Gwei);
    return this;
  };

  _proto.asSzabo = function asSzabo() {
    this.wei = toWei(this.unit, Units.szabo);
    return this;
  };

  _proto.asFinney = function asFinney() {
    this.wei = toWei(this.unit, Units.finney);
    return this;
  };

  _proto.asEther = function asEther() {
    this.wei = toWei(this.unit, Units.ether);
    return this;
  };

  _proto.asAVAX = function asAVAX() {
    this.wei = toWei(this.unit, Units.avax);
    return this;
  };

  _proto.asKether = function asKether() {
    this.wei = toWei(this.unit, Units.Kether);
    return this;
  };

  _proto.asMether = function asMether() {
    this.wei = toWei(this.unit, Units.Mether);
    return this;
  };

  _proto.asGether = function asGether() {
    this.wei = toWei(this.unit, Units.Gether);
    return this;
  };

  _proto.asTether = function asTether() {
    this.wei = toWei(this.unit, Units.Tether);
    return this;
  };

  _proto.toWei = function toWei() {
    if (this.wei) {
      return this.wei;
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toKwei = function toKwei() {
    if (this.wei) {
      return fromWei(this.wei, Units.Kwei);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toGwei = function toGwei() {
    if (this.wei) {
      return fromWei(this.wei, Units.Gwei);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toMwei = function toMwei() {
    if (this.wei) {
      return fromWei(this.wei, Units.Mwei);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toSzabo = function toSzabo() {
    if (this.wei) {
      return fromWei(this.wei, Units.szabo);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toFinney = function toFinney() {
    if (this.wei) {
      return fromWei(this.wei, Units.finney);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toEther = function toEther() {
    if (this.wei) {
      return fromWei(this.wei, Units.ether);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toAVAX = function toAVAX() {
    if (this.wei) {
      return fromWei(this.wei, Units.avax);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toKether = function toKether() {
    if (this.wei) {
      return fromWei(this.wei, Units.Kether);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toMether = function toMether() {
    if (this.wei) {
      return fromWei(this.wei, Units.Mether);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toGether = function toGether() {
    if (this.wei) {
      return fromWei(this.wei, Units.Gether);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toTether = function toTether() {
    if (this.wei) {
      return fromWei(this.wei, Units.Tether);
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toWeiString = function toWeiString() {
    if (this.wei) {
      return this.wei.toString();
    } else {
      throw new Error('error transforming');
    }
  };

  _proto.toHex = function toHex() {
    if (this.wei) {
      return numberToHex(this.wei);
    } else {
      throw new Error('error transforming');
    }
  };

  return Unit;
}();

/**
 * @packageDocumentation
 * @module avalanche-utils
 */
/** @hidden */

var AssertType;

(function (AssertType) {
  AssertType["required"] = "required";
  AssertType["optional"] = "optional";
})(AssertType || (AssertType = {}));
/** @hidden */


var validatorArray = {
  isNumber: [isNumber],
  isString: [isString],
  isBoolean: [isBoolean],
  isArray: [isArray],
  isJsonString: [isJsonString],
  isObject: [isObject],
  isFunction: [isFunction],
  isHex: [isHex],
  isPublicKey: [isPublicKey],
  isPrivateKey: [isPrivateKey],
  isAddress: [isAddress],
  isHash: [isHash],
  isBlockNumber: [isBlockNumber],
  isBech32Address: [isBech32Address],
  isBech32TestNetAddress: [isBech32TestNetAddress],
  isValidAddress: [isValidAddress]
};
function validateArgs(args, requiredArgs, optionalArgs) {
  for (var key in requiredArgs) {
    if (args[key] !== undefined) {
      // tslint:disable-next-line: prefer-for-of
      for (var i = 0; i < requiredArgs[key].length; i += 1) {
        if (typeof requiredArgs[key][i] !== 'function') {
          throw new Error('Validator is not a function');
        }

        if (!requiredArgs[key][i](args[key])) {
          throw new Error("Validation failed for " + key + ",should be validated by " + requiredArgs[key][i].validator);
        }
      }
    } else {
      throw new Error("Key not found: " + key);
    }
  }

  for (var _key in optionalArgs) {
    if (args[_key]) {
      // tslint:disable-next-line: prefer-for-of
      for (var _i = 0; _i < optionalArgs[_key].length; _i += 1) {
        if (typeof optionalArgs[_key][_i] !== 'function') {
          throw new Error('Validator is not a function');
        }

        if (!optionalArgs[_key][_i](args[_key])) {
          throw new Error("Validation failed for " + _key + ",should be validated by " + optionalArgs[_key][_i].validator);
        }
      }
    }
  }

  return true;
}
function generateValidateObjects(validatorObject) {
  var requiredArgs = {};
  var optionalArgs = {};

  for (var index in validatorObject) {
    if (index !== undefined) {
      var newObjectKey = index;
      var newObjectValid = validatorObject[index][0];
      var isRequired = validatorObject[index][1];

      if (isRequired === AssertType.required) {
        requiredArgs[newObjectKey] = validatorArray[newObjectValid];
      } else {
        optionalArgs[newObjectKey] = validatorArray[newObjectValid];
      }
    }
  }

  return {
    requiredArgs: requiredArgs,
    optionalArgs: optionalArgs
  };
}

var assertObject = function assertObject(input) {
  return function (target, key, descriptor) {
    var _generateValidateObje = generateValidateObjects(input),
        requiredArgs = _generateValidateObje.requiredArgs,
        optionalArgs = _generateValidateObje.optionalArgs;

    var original = descriptor.value;

    function interceptor() {
      for (var _len = arguments.length, args = new Array(_len), _key2 = 0; _key2 < _len; _key2++) {
        args[_key2] = arguments[_key2];
      }

      validateArgs(args[0], requiredArgs, optionalArgs);
      return original.apply(this, args);
    }

    descriptor.value = interceptor;
    return descriptor;
  };
};

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

/**
 # avalanche-js-utils

This package provides a collection of utility apis for unit conversions like `fromWei`, `toWei`, `hexToNumber`, `numberToHex`, `isAddress`, etc.

## Installation

```
npm install avalanche-js-utils
```

## Usage

Available units
```
const { Units } = require('avalanche-js-utils');

[Units.wei, '1'], // 1 wei
[Units.Kwei, '1000'], // 1e3 wei
[Units.Mwei, '1000000'], // 1e6 wei
[Units.Gwei, '1000000000'], // 1e9 wei
[Units.szabo, '1000000000000'], // 1e12 wei
[Units.finney, '1000000000000000'], // 1e15 wei
[Units.ether, '1000000000000000000'], // 1e18 wei
[Units.avax, '1000000000000000000'], // 1e18 wei
[Units.Kether, '1000000000000000000000'], // 1e21 wei
[Units.Mether, '1000000000000000000000000'], // 1e24 wei
[Units.Gether, '1000000000000000000000000000'], // 1e27 wei
[Units.Tether, '1000000000000000000000000000000'], // 1e30 wei
```

Converting between different units
```javascript
const { Units, Unit, numberToString, add0xToString, fromWei, toWei, numToStr} = require('avalanche-js-utils');
const { BN } = require('avalanche-js-crypto');

const avax = new Unit('1').asAVAX();
const avaxToGwei = avax.toGwei();
console.log(avaxToGwei);

// numberToString
const num = 123;
const str = numberToString(num)
console.log(str);

// add0xToString
const str = '12345';
const expected = add0xToString(str)
console.log(expected);

// fromWei
const Wei = new BN('1000000000000000000');
const expected = fromWei(Wei, Units.avax);
console.log(expected);

// toWei
const avax = new BN('1');
const expected = toWei(avax, hmy.utils.Units.avax);
const num = numToStr(expected);
console.log(num);
```
 *
 * @packageDocumentation
 * @module avalanche-utils
 */
var ChainType;

(function (ChainType) {
  ChainType["Avalanche"] = "hmy";
  ChainType["Ethereum"] = "eth";
})(ChainType || (ChainType = {}));

var ChainID;

(function (ChainID) {
  ChainID[ChainID["Default"] = 0] = "Default";
  ChainID[ChainID["EthMainnet"] = 1] = "EthMainnet";
  ChainID[ChainID["Morden"] = 2] = "Morden";
  ChainID[ChainID["Ropsten"] = 3] = "Ropsten";
  ChainID[ChainID["Rinkeby"] = 4] = "Rinkeby";
  ChainID[ChainID["RootstockMainnet"] = 30] = "RootstockMainnet";
  ChainID[ChainID["RootstockTestnet"] = 31] = "RootstockTestnet";
  ChainID[ChainID["Kovan"] = 42] = "Kovan";
  ChainID[ChainID["EtcMainnet"] = 61] = "EtcMainnet";
  ChainID[ChainID["EtcTestnet"] = 62] = "EtcTestnet";
  ChainID[ChainID["Geth"] = 1337] = "Geth";
  ChainID[ChainID["Ganache"] = 0] = "Ganache";
  ChainID[ChainID["HmyMainnet"] = 1] = "HmyMainnet";
  ChainID[ChainID["HmyTestnet"] = 2] = "HmyTestnet";
  ChainID[ChainID["HmyLocal"] = 2] = "HmyLocal";
  ChainID[ChainID["HmyPangaea"] = 3] = "HmyPangaea";
})(ChainID || (ChainID = {}));
/** @hidden */


var defaultConfig = {
  Default: {
    Chain_ID: ChainID.HmyLocal,
    Chain_Type: ChainType.Avalanche,
    Chain_URL: 'http://localhost:9500',
    Network_ID: 'Local'
  },
  DefaultWS: {
    Chain_ID: ChainID.HmyLocal,
    Chain_Type: ChainType.Avalanche,
    Chain_URL: 'ws://localhost:9800',
    Network_ID: 'LocalWS'
  }
};
/** @hidden */

var AvalancheCore = /*#__PURE__*/function () {
  function AvalancheCore(chainType, chainId) {
    if (chainId === void 0) {
      chainId = defaultConfig.Default.Chain_ID;
    }

    this.chainType = chainType;
    this.chainId = chainId;
  }

  var _proto = AvalancheCore.prototype;

  _proto.setChainId = function setChainId(chainId) {
    this.chainId = chainId;
  };

  _proto.setChainType = function setChainType(chainType) {
    this.chainType = chainType;
  };

  _createClass(AvalancheCore, [{
    key: "chainPrefix",
    get: function get() {
      switch (this.chainType) {
        case ChainType.Ethereum:
          {
            return 'eth';
          }

        case ChainType.Avalanche:
          {
            return 'hmy';
          }

        default:
          {
            return 'hmy';
          }
      }
    }
  }, {
    key: "getChainId",
    get: function get() {
      return this.chainId;
    }
  }]);

  return AvalancheCore;
}();
/** @hidden */

var HDPath = "m/44'/1023'/0'/0/";
/** @hidden */

var AddressSuffix = '-';

/**
 * @packageDocumentation
 * @module avalanche-utils
 * @hidden
 */
function defineReadOnly(object, name, value) {
  Object.defineProperty(object, name, {
    enumerable: true,
    value: value,
    writable: false
  });
}

export { AddressSuffix, AssertType, AvalancheCore, ChainID, ChainType, DefaultBlockParams, HDPath, Unit, Units, add0xToString, assertObject, defaultConfig, defineReadOnly, fromWei, generateValidateObjects, hexToBN, hexToNumber, isAddress, isArray, isBech32Address, isBech32TestNetAddress, isBlockNumber, isBoolean, isFunction, isHash, isHex, isHttp, isInt, isJsonString, isKeyString, isNumber, isObject, isPrivateKey, isPublicKey, isString, isValidAddress, isWs, numToStr, numberToHex, numberToString, strip0x, toWei, unitMap, validateArgs, validatorArray };
//# sourceMappingURL=avalanche-js-utils.esm.js.map
