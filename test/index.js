try {
  const Identity = require('../src/index.js')
  ;(() => {
    const privateToPublic = {
      '7': '025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc',
      '7b': '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5',
      '3e7': '029680241112d370b56da22eb535745d9e314380e568229e09f7241066003bc471',
      '5cd': '03c982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda',
      '28757b2': '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e',
      '3b6d0ef7': '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5',
      '100000000000000000000000000000000': '028f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da',
      '1000000000000000000000000000000000000000000000000000080000000': '039577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116',
      '2103febe2a97e31d277195d1595f61439b83e63dc0168997bb919d94fecbd08a': '03fe973c43d29ce39f940d3186a5a57c98231d59c7cedaa2387d07734777efed80',
    }

    for (privateKey in privateToPublic) {
      const identity = Identity.fromKey(privateKey)
      if (privateToPublic[privateKey]!== identity.sec1Compressed) {
        throw `private key failed to make public ${privateKey} ${privateToPublic[privateKey]} ${identity.sec1Compressed}`
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
      if (identity.address !== privateToPublic[private]) {
        throw 'invalid public key generation '+privateToPublic[private]
      }
    }
    console.log('✅ retrieving identity from wif passed')
  })()

  ;(() => {
    const identity = Identity.fromKey('82ef796afbce6e67bcb6bc44d922e5d2e664ebe118c0ed5b6ce3b481a638ec90')
    const signature = identity.sign('test', '2900c9abe4a9d00b2a4aa6663d8f4989c8cac35f4fe9b2c5b66e07a3903e1c3')
    const bip66Sig = identity.signBip66('test')
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
      const bip66Sig = identity.signBip66(message)
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

  ;(()=>{
    const message = `message`
    const identity = Identity.fromKey('16830334aa31438ec02a279165788265ab01e10348b158067815882')
    const signature = identity.sign(message, '11e138b6e8580e464cf6b303f482d2e6cb1a46382e7f3f64e2a9eb2')
    const bip66Sig = identity.signBip66(message, '1dc05e3ff2ef5789bb45a996da7af4602d4c595958b94d2a947ed8e')
    if (signature.r != 'c71cd3057d59777e31d623c04ce69599a40b6daf345b787f46f863debe029755') {
      throw 'signature is wrong'
    }
    if (signature.s != '1a34f3fe14f334fc910486d246b0f33d07b9261edd103612c273248aa256d2bd') {
      throw 'signature is wrong'
    }
    // if (bip66Sig != '304402207371a56bdb0f2e89354bc8b56ee57af530bba1d7d29b3c3ff98ca8360bd888e102202eefc3377d1650e06d52c7dacc75e2ce1319c58eb5555e59ec8256a1af1be0bc') {
    //   throw 'signature is wrong'
    // }
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
    console.log('✅ signing and verification passed')
  })()

  ;(()=>{
    const identity = Identity.fromWif('5JJQHQSZP9z5wHjerG8QL3mPXVpCgrWR8dw1TfiJHhjR5DieHTX')
    if (identity.sec1Compressed !== '02d2cb1636c8800502112f346f10a62e256d42b5ea46b3a55e2ff4607167afd2fd') {
      throw 'invalid sec1 (compressed)'
    }
    if (identity.sec1Uncompressed !== '04d2cb1636c8800502112f346f10a62e256d42b5ea46b3a55e2ff4607167afd2fdbdb2bfd6280aca239796dc4eb6283ad2d31a5ef417620efb095887c7dc56a5ba') {
      throw 'invalid sec1 (uncompressed)'
    }
    if (identity.key !== '3fd6fd76821d9b1191cb24894be0f760b8d08fe837347e3d940b53a49f9a884e') {
      throw 'invalid private key'
    }
    if (identity.wif !== '5JJQHQSZP9z5wHjerG8QL3mPXVpCgrWR8dw1TfiJHhjR5DieHTX') {
      throw 'invalid wif'
    }
    if (identity.address !== '1C4cseQKY442fKKHP8LvrakkBdZRJYWGmh') {
      throw 'invalid address (uncompressed)'
    }
    if (identity.compressAddress !== '1AHbAE2SyMp2hAPDZiCo1RsdZyAFqPsyRg') {
      throw 'invalid address (compressed)'
    }

    if (!Identity.validateAddress(identity.compressAddress)) {
      throw 'unable to validate valid address (compressed)'
    }
    if (!Identity.validateAddress(identity.address)) {
      throw 'unable to validate valid address (uncompressed)'
    }

    let threwError = false
    try {
      const invalidAddress = identity.compressAddress
      invalidAddress[49] = '3'
      if (Identity.validateAddress(invalidAddress)) {
        throw 'unable to invalidate invalid address (compressed)'
      } 
      if (Identity.validateAddress(identity.compressAddress.substr(0, 49))) {
        throw 'unable to invalidate invalid address (compressed)'
      }
    }
    catch (e) {
      threwError = true
    }
    if (!threwError) {
      throw 'should have thrown an error on invalid address'
    } 

    threwError = false
    try {
      const invalidAddress = identity.address
      invalidAddress[49] = '3'
      if (Identity.validateAddress(invalidAddress)) {
        throw 'unable to invalidate invalid address (uncompressed)'
      } 
      if (Identity.validateAddress(identity.address.substr(0, 49))) {
        throw 'unable to invalidate invalid address (uncompressed)'
      } 
    }
    catch (e) {
      threwError = true
    }
    if (!threwError) {
      throw 'should have thrown an error on invalid address'
    } 

    threwError = false
    try { Identity.fromSec1(identity.sec1Compressed) } catch (e) { threwError = true; console.error(e) }
    if (threwError) {
      throw 'should not have thrown an error when making an identity from sec1 format (compressed)'
    } 

    threwError = false
    try { Identity.fromSec1(identity.sec1Uncompressed) } catch (e) { threwError = true }
    if (threwError) {
      throw 'should not have thrown an error when making an identity from sec1 format (uncompressed)'
    } 

    threwError = false
    try {
      const sec1 = identity.sec1Uncompressed.replace('8800', '1111')
      Identity.fromSec1(sec1)
    } catch (e) { threwError = true }
    if (!threwError) {
      throw 'should have thrown an error when provided a bad sec1 point (uncompressed)'
    } 

    threwError = false
    try {
      const sec1 = identity.sec1Uncompressed.replace('04', '05')
      Identity.fromSec1(sec1)
    } catch (e) { threwError = true; }
    if (!threwError) {
      throw 'should have thrown an error when provided a bad sec1 format'
    } 
    console.log('✅ formats passed')
  })()

  ;(() => {
    const identityA = Identity.fromKey('cfd9cc15a78839fa8a113b139df54e61f76eba8eb6b831085411ac73f4495978')
    const identityB = Identity.fromKey('7df487e52aa7708057a3068763cecf0bdba9757379b80a59beb2c72faa3e922f')
    if (identityA.keyExchange(identityB) !== 'fa815fd3f04983b9828bde4d60ff3c49e92c765c185c89cf0f002da330d08fd') {
      throw 'failed to perform diffie-hellman key exchange'
    }
    if (identityB.keyExchange(identityA) !== 'fa815fd3f04983b9828bde4d60ff3c49e92c765c185c89cf0f002da330d08fd') {
      throw 'failed to perform diffie-hellman key exchange'
    }
  })()
}
catch (e) {
  console.log('⚠️ failed to test identities', e)
  throw e
}