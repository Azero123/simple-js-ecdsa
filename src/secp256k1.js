const bigInt = require('big-integer')
const elliptic = require('simple-js-ec-math')
const fs = require('fs')
const ModPoint = elliptic.ModPoint
const Curve = elliptic.Curve

let preprocessing = {}
let previousPoint
const points = JSON.parse(fs.readFileSync('./secp256k1-preprocessing.json'))
const first = ModPoint.fromJSON(points[0])
preprocessing[first.toString()] = {}
for (let point of points) {
  point = ModPoint.fromJSON(point)
  if (previousPoint) {
    preprocessing[first.toString()][previousPoint.toString()] = point
  }
  previousPoint = point
}

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
  preprocessing
)
module.exports = secp256k1