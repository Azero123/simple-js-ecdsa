# simple-js-ecdsa

this project is intended as an easy to use ecdsa

creating a new wallet
```
let wallet = Wallet.new()
```

opening an existing wallet using a private key
```
Wallet.fromKey(<private number>)
```

opening a wallet using a wif
```
Wallet.fromWif(<private wif>)
```

retrievable items in a wallet
```
wallet.key
wallet.sec1Compressed
wallet.sec1Uncompressed
wallet.wif
wallet.address
wallet.compressAddress
```

signing a message
```
const signature = wallet.sign(message)
```

verify a signature
```
wallet.verify(message, signature)
```

signing in bip66 format
```
const signature = wallet.bip66Sign(message)
```

verify bip66 signature
```
wallet.verifyBip66(message, signature)
```

# contribute

bitcoin address: 1KKiniL7QnMPZZLjgGB2Kq1d7zsjUr6TnS 