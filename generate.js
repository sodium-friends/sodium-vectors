var assert = require('assert')
  var isFalse = function (value) { assert.equal(value, false) }
  var isTrue = function (value) { assert.equal(value, true) }

function toBase64(b) {
  return b.toString('base64')
}

function Z(n) {
  var b = new Buffer(n)
  b.fill(0)
  return b
}

function flip (buffer) {
  var b = new Buffer(buffer)
  b[0] = b[0] ^ 1
  return b
}

module.exports = function (ref) {
  var types = {}
  var values = {}
  for(var k in ref) {
    types[k] = typeof ref[k]
    if('function' !== typeof ref[k])
      values[k] = ref[k]
  }

  //crypto_sign_seed_keypair
  //crypto_sign_detached
  //crypto_sign_verify_detached
  //crypto_scalarmult
  //crypto_sign_ed25519_pk_to_curve25519
  //crypto_sign_ed25519_sk_to_curve25519
  //crypto_secretbox_easy
  //crypto_secretbox_open_easy
  //crypto_secretbox_detached
  //crypto_secretbox_open_detached
  //crypto_auth
  //crypto_auth_open
  //crypto_hash_sha256

  var msgs = [
    //Ronald Regan's favorite russian proverb
    new Buffer('trust but verify'),
    //sun tzu, art of war
    new Buffer(
      'Military tactics are like unto water; '
    + 'for water in its natural course runs '
    + 'away from high places and hastens downwards. '
    + 'So in war, the way is to avoid what is strong '
    + 'and to strike at what is weak. '
    ),
    //Witfield Diffie, New Directions in Cryptography
    new Buffer(
      'The last characteristic which we note in the history '
    + 'of cryptography is the division between amateur and '
    + 'professional cryptographers. Skill in production '
    + 'cryptanalysis has always been heavily on the side '
    + 'of the professionals, but innovation, particularly '
    + 'in the design of new types of cryptographic systems, '
    + 'has come primarily from the amateurs.'
    )
  ]

  var tests = []
  function wrap (name, fn) {
    return function () {
      var args = [].slice.call(arguments)
      var _args = args.map(toBase64)
      var ret = fn.apply(null, args)
      tests.push([name, _args, ret, args.map(toBase64)])
      return ret
    }
  }
  var target = {}
  for(var k in ref)
    target[k] = wrap(k, ref[k])


  var seed = Z(32)
  target.crypto_hash_sha256(seed, new Buffer('deterministic tests are good'))
  var seed = Z(32)
  target.crypto_hash_sha256(seed, new Buffer('easily portable to other languages'))
  var key = Z(32)
  target.crypto_hash_sha256(key, new Buffer('trustno1'))

  var pk = Z(32), sk = Z(64)
  target.crypto_sign_seed_keypair(pk, sk, seed)
  var pk2 = Z(32), sk2 = Z(64)
  target.crypto_sign_seed_keypair(pk2, sk2, seed)

  var n = Z(32), _n = Z(32)
  //don't put this in the test vector. there are already standard
  //hash vectors.
  ref.crypto_hash_sha256(n, new Buffer('number, used once'))
  function nonce () {
    ref.crypto_hash_sha256(_n, n)
    var n2 = n
    n = _n
    _n = n2
    return n.slice(0, 24)
  }

  var cpk = Z(32), csk = Z(64)
  target.crypto_sign_ed25519_pk_to_curve25519(cpk, pk)
  target.crypto_sign_ed25519_sk_to_curve25519(csk, sk)

  var cpk2 = Z(32), csk2 = Z(64)
  target.crypto_sign_ed25519_pk_to_curve25519(cpk2, pk2)
  target.crypto_sign_ed25519_sk_to_curve25519(csk2, sk2)

  var secret1 = Z(32), secret2 = Z(32)
  target.crypto_scalarmult(secret1, cpk, csk2)
  target.crypto_scalarmult(secret2, cpk2, csk)
  assert.deepEqual(secret1, secret2)

  msgs.forEach(function (msg) {
    var signed = Z(msg.length+64)
    target.crypto_sign(signed, msg, sk)
    isTrue(target.crypto_sign_open(Z(msg.length), signed, pk))

    //flip one bit: this should now fail
    isFalse(target.crypto_sign_open(Z(msg.length), flip(signed), pk))
    isFalse(target.crypto_sign_open(Z(msg.length), signed, flip(pk)))
  })

  msgs.forEach(function (msg) {
    var sig = Z(64)
    target.crypto_sign_detached(sig, msg, sk)
    isTrue(target.crypto_sign_verify_detached(sig, msg, pk))

    //flip this should now fail
    isFalse(target.crypto_sign_verify_detached(flip(sig), msg, pk))
    isFalse(target.crypto_sign_verify_detached(sig, flip(msg), pk))
    isFalse(target.crypto_sign_verify_detached(sig, flip(msg), flip(pk)))
  })

  msgs.forEach(function (msg) {
    var boxed = Z(msg.length+16)
    var n = nonce()
    target.crypto_secretbox_easy(boxed, msg, n, key)
    isTrue(target.crypto_secretbox_open_easy(Z(msg.length), boxed, n, key))

    isFalse(target.crypto_secretbox_open_easy(Z(msg.length), flip(boxed), n, key))
    isFalse(target.crypto_secretbox_open_easy(Z(msg.length), boxed, flip(n), key))
    isFalse(target.crypto_secretbox_open_easy(Z(msg.length), boxed, n, flip(key)))
  })

  msgs.forEach(function (msg) {
    var mac = Z(16), boxed = Z(msg.length)
    var n = nonce()
    target.crypto_secretbox_detached(boxed, mac, msg, n, key)
    isTrue(target.crypto_secretbox_open_detached(Z(msg.length), boxed, mac, n, key))

    isFalse(target.crypto_secretbox_open_detached(Z(msg.length), flip(boxed), mac, n, key))
    isFalse(target.crypto_secretbox_open_detached(Z(msg.length), boxed, flip(mac), n, key))
    isFalse(target.crypto_secretbox_open_detached(Z(msg.length), boxed, mac, flip(n), key))
    isFalse(target.crypto_secretbox_open_detached(Z(msg.length), boxed, mac, n, flip(key)))
  })

  msgs.forEach(function (msg) {

    var auth = Z(32)
    target.crypto_auth(auth, msg, key)
    isTrue(target.crypto_auth_verify(auth, msg, key))

    isFalse(target.crypto_auth_verify(flip(auth), msg, key))
    isFalse(target.crypto_auth_verify(auth, flip(msg), key))
    isFalse(target.crypto_auth_verify(auth, msg, flip(key)))

  })

  console.log(JSON.stringify({types: types, values: values, tests: tests}, null, 2))
}

if(!module.parent)
  module.exports(require('sodium-native'))

