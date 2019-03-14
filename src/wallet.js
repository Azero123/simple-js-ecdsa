const bigInt = require('big-integer')
const base58 = require('bs58')
const crypto = require('crypto')
const secp256k1 = require('./secp256k1.js')

let hex = { '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, a: 10, b: 11, c: 12, d: 13, e: 14, f: 15 }

const sha256 = require('./sha256.js')
const ripemd160 = data => crypto.createHash('ripemd160').update(data, 'hex').digest('hex').toString()

const hexStringToBinaryString = s => {
  s = s.toLowerCase()
  const len = s.length;
  var data = [];
  for (let i = 0; i < len; i += 2) {
    data[i / 2] = String.fromCharCode((hex[s[i]] << 4) + (hex[s[i + 1]]));
  }
  return data.join('');
}

const binSha256 = data => sha256(hexStringToBinaryString(data))
const binRipemd160 = data => ripemd160(data)

class Wallet {
  static fromKey(key, curve = secp256k1) {
    const wallet = new Wallet()
    wallet.curve = curve
    wallet.key = key
    return wallet
  }
  static fromWif(wif, curve = secp256k1) {
    const wallet = new Wallet()
    wallet.curve = curve
    const hexWif = base58.decode(wif).toString('hex')
    wallet.key = hexWif.substring(2, hexWif.length - 8)
    if (wallet.wif !== wif) {
      throw 'invalid wif'
    }
    return wallet
  }
  sign(message) {

  }
  static fromAddress(address, curve = secp256k1) {
    const wallet = new Wallet()
    wallet.curve = curve
    wallet._address = address
    return wallet
  }
  get wif() {
    if (this._wif) {
      return this._wif
    }
    const formatted = `80${this.key}`
    const checksum = binSha256(binSha256(formatted)).substr(0, 8)
    return this._wif = base58.encode(Buffer.from(`${formatted}${checksum}`, 'hex'))
  }
  get pubPoint() {
    if (this._pubPoint) {
      return this._pubPoint
    }
    return this._pubPoint = this.curve.multiply(this.curve.g, bigInt(this.key, 16))
  }
  get sec1Compressed() {
    if (this._sec1Compressed) {
      return this._sec1Compressed
    }
    let xStr = bigInt(this.pubPoint.x).toString(16)
    while (xStr.length < 64) {
      xStr = '0' + xStr
    }
    return this._sec1Compressed = `${bigInt(this.pubPoint.y).isOdd() ? '03' : '02'}${xStr}`
  }
  get sec1Uncompressed() {
    if (this._sec1Uncompressed) {
      return this._sec1Uncompressed
    }
    let yStr = bigInt(this.pubPoint.y).toString(16)
    while (yStr.length < 64) {
      yStr = '0' + yStr
    }
    let xStr = bigInt(this.pubPoint.x).toString(16)
    while (xStr.length < 64) {
      xStr = '0' + xStr
    }
    return this._sec1Uncompressed = `04${xStr}${yStr}`
  }
  get address() {
    if (this._address) {
      return this._address
    }
    const formatted = `00${binRipemd160(binSha256(this.sec1Uncompressed))}`
    const checksum = binSha256(binSha256(formatted)).substr(0, 8)
    return this._address = base58.encode(Buffer.from(`${formatted}${checksum}`, 'hex'))
  }
  get compressAddress() {
    if (this._compressAddress) {
      return this._compressAddress
    }
    const formatted = `00${binRipemd160(binSha256(this.sec1Compressed))}`
    const checksum = binSha256(binSha256(formatted)).substr(0, 8)
    return this._compressAddress = base58.encode(Buffer.from(`${formatted}${checksum}`, 'hex'))
  }
}
module.exports = Wallet