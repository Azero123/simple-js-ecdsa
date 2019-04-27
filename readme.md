# simple-js-ecdsa

this project is intended as an easy to use ecdsa

creating a new identity
```
const identity = Identity.new()
```
if you would like to use a curve besides secp256k1
```
const ECMath = require('simple-js-ec-math')
const g = new ECMath.ModPoint(x,y)
const curve = new ECMath.Curve(<a>, <b>, <n>, <p>, g, <preprocessing>)
const identity = Identity.new(curve)
```

opening an existing identity using a private key
```
Identity.fromKey(<private number>, <curve?>)
```

opening a identity using a wif
```
Identity.fromWif(<private wif>, <curve?>)
```

opening a identity using sec1
```
Identity.fromSec1(<private wif>, <curve?>)
```

retrievable items in a identity
```
identity.key
identity.sec1Compressed
identity.sec1Uncompressed
identity.wif
identity.address
identity.compressAddress
```

signing a message
```
const signature = identity.sign(<message>)
```

verify a signature
```
identity.verify(<message>, <signature>)
```

signing in bip66 format
```
const signature = identity.bip66Sign(<message>)
```

verify bip66 signature
```
identity.verifyBip66(<message>, <signature>)
```

verify address
```
identity.validateAddress(<address>)
```

get public point
```
identity.publicPoint
```

# contribute

bitcoin address: 1KKiniL7QnMPZZLjgGB2Kq1d7zsjUr6TnS 

ethereum address: 0x177b258bD53A8F7d8C609A9277A60A51d1e7e0e0