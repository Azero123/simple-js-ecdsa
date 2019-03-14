const bigInt = require('big-integer')
const crypto = require('crypto')
const Wallet = require('./wallet.js')
const secp256k1 = require('./secp256k1.js')

class ECDSA {
  constructor(curve = secp256k1) {
    this.curve = curve
  }
  newKey() {
    return Wallet.from(bigInt.fromArray([...crypto.randomBytes(64)]).toString(16), curve)
  }
}

module.exports = ECDSA