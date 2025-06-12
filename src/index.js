const base58 = require('bs58')
const secp256k1 = require('simple-js-secp256k1')
const ModPoint = require('simple-js-ec-math').ModPoint
const ripemd160 = require('simple-js-ripemd160')

let hex = { '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, a: 10, b: 11, c: 12, d: 13, e: 14, f: 15 }

const sha256 = require('simple-js-sha2-256')

function modInv(a, n) {
  if (typeof a !== 'bigint') {
    throw new Error(`modInv: a is not BigInt: ${a} (type: ${typeof a})`)
  }
  if (typeof n !== 'bigint') {
    throw new Error(`modInv: n is not BigInt: ${n} (type: ${typeof n})`)
  }
  let t = 0n, newT = 1n
  let r = n, newR = a % n

  while (newR !== 0n) {
    const quotient = r / newR
    ;[t, newT] = [newT, t - quotient * newT]
    ;[r, newR] = [newR, r - quotient * newR]
  }

  if (r > 1n) throw new Error('a is not invertible')
  if (t < 0n) t += n

  return t
}

function bigintToBaseArray(value, base = 256) {
  const result = [];
  const bigBase = BigInt(base);
  let num = value;

  while (num > 0) {
    result.unshift(Number(num % bigBase));
    num = num / bigBase;
  }

  return result;
}

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

class Identity {
  static new(curve = secp256k1) {
    return Identity.fromKey(curve.modSet.random(), curve)
  }

  static fromKey(key, curve = secp256k1) {
    let _key = BigInt('0x' + key)
    const wallet = new Identity()
    wallet.curve = curve
    wallet.key = key
    wallet._key = _key
    return wallet
  }

  static fromWif(wif, curve = secp256k1) {
    const hexWif = base58.decode(wif).toString('hex')
    const key = hexWif.substring(2, hexWif.length - 8)
    const wallet = Identity.fromKey(key, curve)
    if (wallet.wif !== wif) {
      throw 'invalid wif'
    }
    return wallet
  }

  static fromSec1(sec1, curve = secp256k1) {
    const identity = new Identity()
    identity.curve = curve
    identity._publicPoint = ModPoint.fromSec1(sec1, curve)
    if (
      !secp256k1.verify(identity.publicPoint)
    ) {
      throw 'invalid address' + (mode === '03' || mode === '02') ? ' compressed addresses not yet supported' : ''
    }
    return identity
  }

  static fromPublicPoint(publicPoint, curve = secp256k1) {
    const wallet = new Identity()
    wallet.curve = curve
    wallet._publicPoint = publicPoint
    return wallet
  }
  
  sign(message, k = this.curve.modSet.random()) {
    if (typeof k === 'string') {
      k = BigInt('0x' + k)
    } else if (typeof k === 'number') {
      k = BigInt(k)
    }
    if (typeof k !== 'bigint') {
      throw new Error(`k is not BigInt: ${k} (type: ${typeof k})`)
    }
    const e = BigInt('0x' + sha256(message))
    const r = this.curve.multiply(this.curve.g, k)

    const s1 = (this._key * r.x) + e
    const s = (s1 * modInv(BigInt('0x'+k.toString(16)), this.curve.n)) % this.curve.n

    return {
      r: r.x.toString(16),
      s: s.toString(16)
    }
  }

  static validateAddress(address) {
    if (address.length !== 34) {
      throw 'invalid address'
    }
    address = base58.decode(address).toString('hex')
    const addressChecksum = binSha256(binSha256(address.substr(0,42))).substr(0, 8)
    const checksum = address.substr(42,50)
    return addressChecksum === checksum
  }

  signBip66(message, k = this.curve.modSet.random()) {
    let signature = this.sign(message, k)
    const arrayR = bigintToBaseArray(BigInt('0x' + signature.r))
    const arrayS = bigintToBaseArray(BigInt('0x' + signature.s))
    const r = Buffer.from(arrayR)
    const s = Buffer.from(arrayS)
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
    const e = BigInt('0x' + sha256(message))
    const r = BigInt('0x' + signature.r)
    const s = BigInt('0x' + signature.s)
    const w = modInv(s, this.curve.n)
    const u1 = e * w % this.curve.n
    const u2 = r * w % this.curve.n
    const p = this.curve.add(this.curve.multiply(this.curve.g, u1), this.curve.multiply(this.publicPoint, u2))
    return p.x.toString(16) == r.toString(16)
  }

  verifyBip66(message, signature) {
    signature = Buffer.from(signature, 'hex')
    const lr = signature[3]
    return this.verify(message, {
      r: signature.slice(4, 4 + lr).toString('hex'),
      s: signature.slice(6 + lr).toString('hex')
    })
  }

  keyExchange(identity) {
    const pub = this.diffieHellman(identity)
    const sharedIdentity = Identity.fromPublicPoint(pub, this.curve)
    const tempSecretPublicKey = sharedIdentity.publicPoint.toJSON()
    return tempSecretPublicKey.x
  }

  diffieHellman(identity) {
    if (this.key) {
      return this.curve.multiply(identity.publicPoint, this._key)
    }
    throw 'diffie-hellman key exchanges requires a private key instantiated identity'
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
    return this._publicPoint = this.curve.multiply(this.curve.g, this._key)
  }

  get sec1Compressed() {
    return this.publicPoint.sec1Compressed
  }

  get sec1Uncompressed() {
    return this.publicPoint.sec1Uncompressed
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
module.exports = Identity