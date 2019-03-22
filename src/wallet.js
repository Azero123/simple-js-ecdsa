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
  static new(curve = secp256k1) {
    return Wallet.fromKey(curve.modSet.random(), curve)
  }
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
  sign(message, k = this.curve.modSet.random()) {
    k = bigInt(k, 16)
    const e = bigInt(sha256(message), 16)
    
    const da = bigInt(this.key, 16) // private key

    const r = this.curve.multiply(this.curve.g, k)

    const s1 = da.multiply(r.x).add(e)
    const s = s1.multiply(k.modInv(this.curve.n)).mod(this.curve.n)

    return {
      r: bigInt(r.x).toString(16),
      s: s.toString(16)
    }
  }

  bip66Sign(message, k = this.curve.modSet.random()) {
    let signature = this.sign(message, k)
    const r = Buffer.from(signature.r, 'hex')
    const s = Buffer.from(signature.s, 'hex')
    const rl = r.length
    const sl = s.length
    signature = Buffer.allocUnsafe(6 + rl + sl)
    signature[0] = 0x30
    signature[1] = signature.length - 2
    signature[2] = 0x02
    signature[3] = rl
    r.copy(signature, 4)
    signature[4+rl] = 0x02
    signature[5+rl] = sl
    s.copy(signature, rl + 6)
    return signature.toString('hex')
  }

  verify(message, signature) {
    const e = bigInt(sha256(message), 16)
    const r = bigInt(signature.r, 16)
    const s = bigInt(signature.s, 16)
    const w = bigInt(s).modInv(this.curve.n)
    const u1 = bigInt(e).multiply(w).mod(this.curve.n)
    const u2 = r.multiply(w).mod(this.curve.n)
    const p = this.curve.add(this.curve.multiply(this.curve.g, u1), this.curve.multiply(this.publicPoint, u2))
    return p.x == r
  }

  verifyBip66(message, signature) {
    signature = Buffer.from(signature, 'hex')
    const lr = signature[3]

    return this.verify(message, {
      r: signature.slice(4, 4 + lr).toString('hex'),
      s: signature.slice(6 + lr).toString('hex')
    })
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
  get publicPoint() {
    if (this._publicPoint) {
      return this._publicPoint
    }
    return this._publicPoint = this.curve.multiply(this.curve.g, bigInt(this.key, 16))
  }
  get sec1Compressed() {
    if (this._sec1Compressed) {
      return this._sec1Compressed
    }
    let xStr = bigInt(this.publicPoint.x).toString(16)
    while (xStr.length < 64) {
      xStr = '0' + xStr
    }
    return this._sec1Compressed = `${bigInt(this.publicPoint.y).isOdd() ? '03' : '02'}${xStr}`
  }
  get sec1Uncompressed() {
    if (this._sec1Uncompressed) {
      return this._sec1Uncompressed
    }
    let yStr = bigInt(this.publicPoint.y).toString(16)
    while (yStr.length < 64) {
      yStr = '0' + yStr
    }
    let xStr = bigInt(this.publicPoint.x).toString(16)
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