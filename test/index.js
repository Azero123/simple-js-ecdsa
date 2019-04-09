try {
  const bigInt = require('big-integer')
  const Identity = require('../src/index.js')
  ;(() => {
    const privateToPublic = {
      '7': {
        pub: '025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc',
      },
      [bigInt('123').toString(16)]: {
        pub: '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5',
      },
      [bigInt('999').toString(16)]: {
        pub: '029680241112d370b56da22eb535745d9e314380e568229e09f7241066003bc471',
      },
      [bigInt('1485').toString(16)]: {
        pub: '03c982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda',
      },
      [bigInt('42424242').toString(16)]: {
        pub: '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e',
      },
      [bigInt('999').pow('3').toString(16)]: {
        pub: '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5',
      },
      [bigInt('2').pow('128').toString(16)]: {
        pub: '028f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da',
      },
      [bigInt('2').pow('240').add(bigInt('2').pow('31')).toString(16)]: {
        pub: '039577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116',
      },
      '2103febe2a97e31d277195d1595f61439b83e63dc0168997bb919d94fecbd08a': {
        pub: '03fe973c43d29ce39f940d3186a5a57c98231d59c7cedaa2387d07734777efed80',
      }
    }

    for (privateKey in privateToPublic) {
      const identity = Identity.fromKey(privateKey)
      if (privateToPublic[privateKey].pub !== identity.sec1Compressed) {
        throw `private key failed to make public ${privateKey} ${privateToPublic[privateKey].pub} ${identity.sec1Compressed}`
      }
    }
    console.log('✅ retrieving identity from private key passed')
  })()

  ;(()=>{
    const privateToPublic = {
      '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf':'1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm',
      '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreJQmdp3Y':'1KFLggHezq3kiAtpaKMeQPcnoWsXuZHRyn',
      '5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V':'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM',
      '5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh':'1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a'
    }
    for (const private of Object.keys(privateToPublic)) {
      let identity = Identity.fromWif(private)
      // console.log('key', identity.key)
      // console.log('sec1 (compressed)',identity.sec1Compressed)
      // console.log('sec1 (uncompressed)',identity.sec1Uncompressed)
      // console.log('wif',identity.wif)
      // console.log('address',identity.address)
      // console.log('compressAddress',identity.compressAddress)
      if (identity.address !== privateToPublic[private]) {
        throw 'invalid public key generation '+privateToPublic[private]
      }
    }
    console.log('✅ retrieving identity from wif passed')
  })()

  ;(() => {
    const identity = Identity.fromKey('82ef796afbce6e67bcb6bc44d922e5d2e664ebe118c0ed5b6ce3b481a638ec90')
    const signature = identity.sign('test', bigInt('2900c9abe4a9d00b2a4aa6663d8f4989c8cac35f4fe9b2c5b66e07a3903e1c3', 16))
    const bip66Sig = identity.bip66Sign('test')
    if (signature.r.toString(16) !== '85a44b824bda975b15ac77a3256c5d6f21c19b0412eb19333844fc2dbd25dbba') {
      throw 'invalid signature r value'
    }
    // console.log('bip66',bip66.encode(new Buffer(signature.r.toString(16), 'hex'), new Buffer(signature.s.toString(16), 'hex')))
    // if (signature.s.toString(16) !== '79a1e1e6c94d3cc0388d8659cf7e7fbc6d6e03a1a19446258d19b82071b95c7d') {
    //   throw 'invalid signature s value'
    // }
    if (identity.verify('test', signature) !== true) {
      throw 'signing or verification failure'
    }
    if (identity.verifyBip66('test', bip66Sig) !== true) {
      throw 'bip 66 signing or verification failure'
    }
    if (identity.verifyBip66(`${Math.random()}`, bip66Sig) !== false) {
      throw 'falsifiable bip 66 identity verification'
    }
    if (identity.verify(`${Math.random()}`, signature) !== false) {
      throw 'falsifiable verification'
    }
    if (Identity.new().verify('test', signature) !== false) {
      throw 'falsifiable identity verification'
    }
  })()

  ;(()=>{
    let i = 0
    while (i < 2) {
      const message = `${Math.random()}`
      const identity = Identity.new()
      const signature = identity.sign(message)
      const bip66Sig = identity.bip66Sign(message)
      if (identity.verify(message, signature) !== true) {
        throw 'signing or verification failure'
      }
      if (identity.verifyBip66(message, bip66Sig) !== true) {
        throw 'bip 66 signing or verification failure'
      }
      if (identity.verifyBip66(`${Math.random()}`, bip66Sig) !== false) {
        throw 'falsifiable bip 66 identity verification'
      }
      if (identity.verify(`${Math.random()}`, signature) !== false) {
        throw 'falsifiable verification'
      }
      if (Identity.new().verify(message, signature) !== false) {
        throw 'falsifiable identity verification'
      }
      i++
    }
    console.log('✅ signing and verification passed')
  })()
}
catch (e) {
  console.log('⚠️ failed to test identities', e)
  throw e
}