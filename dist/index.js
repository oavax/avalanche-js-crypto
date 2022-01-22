
'use strict'

if (process.env.NODE_ENV === 'production') {
  module.exports = require('./avalanche-js-crypto.cjs.production.min.js')
} else {
  module.exports = require('./avalanche-js-crypto.cjs.development.js')
}
