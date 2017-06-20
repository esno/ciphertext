function _encrypt(key, data) {
  window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: window.crypto.getRandomValues(new Uint8Array(12)),
      tagLength: 128
    },
    key,
    new TextEncoder('utf-8').encode(data)
  )
  .then(function(e) {
    var b = btoa(
      String.fromCharCode.apply(
        null,
        new Uint8Array(e)
      )
    );
    h = '-----BEGIN CIPHERTEXT-----';
    f = '------END CIPHERTEXT------';
    b = h + "\n" + b + "\n" + f;

    return _exitLog(b);
  })
  .catch(function(e) {
    return _exitLog(e);
  });
}

function _exitLog(msg) {
  var output = document.getElementById('output');
  output.value = msg;
  return false;
}

function compute() {
  var token = document.getElementById('token').value;
  var input = document.getElementById('input').value;
  var ret = false;

  if(token.length == 0) {
    return _exitLog('no token!');
  }

  if(input.length == 0) {
    return _exitLog('no (cipher)text!');
  }

  crypto.subtle.digest(
    { name: 'SHA-256' },
    new TextEncoder('utf-8').encode(token)
  )
  .then(function(d) {
    window.crypto.subtle.importKey(
      'raw',
      d,
      { name: 'AES-GCM' },
      false,
      [ 'encrypt', 'decrypt' ]
    )
    .then(function(k) {
      ret = _encrypt(k, input);
    })
    .catch(function(e) {
      ret =  _exitLog(e);
    });
  })
  .catch(function(e) {
    return _exitLog(e);
  });

  return ret;
}
