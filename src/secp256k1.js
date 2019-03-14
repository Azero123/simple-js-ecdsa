const bigInt = require('big-integer')
const elliptic = require('simple-js-ec-math')
const ModPoint = elliptic.ModPoint
const Curve = elliptic.Curve

const g = new ModPoint(
  bigInt('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16),
  bigInt('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16)
)
const secp256k1 = new Curve(
  bigInt('0'),
  bigInt('7'),
  bigInt('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16),
  bigInt('2').pow('256').minus(bigInt('2').pow('32')).minus('977'),
  g,
)
module.exports = secp256k1