var tape = require('tape')
var data = require('./data.json')
function fromBase64 (s) {
  return new Buffer(s, 'base64')
}

module.exports = function (ref) {
  data.tests.forEach(function (test, i) {
    tape('test:'+test[0]+' ' + i, function (t) {
      var args = test[1].map(fromBase64)
      var ret = test[2] == null ? undefined : test[2]
      t.equal(ref[test[0]].apply(null, args), ret) //check return value
      t.deepEqual(args, test[3].map(fromBase64))
      t.end()
    })
  })
}
