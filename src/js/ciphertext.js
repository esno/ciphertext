function _decrypt(key, data) {
  var a = data
    .replace('-----BEGIN CIPHERTEXT-----', '')
    .replace('------END CIPHERTEXT------', '')
    .trim();
  var b = atob(a);

  var buf = new Uint8Array(b.length);
  Array.prototype.forEach.call(b, function(byte, i) {
    buf[i] = byte.charCodeAt(0);
  });

  var iv = new Uint8Array(12);
  var enc = new Uint8Array(buf.length - 12);
  Array.prototype.forEach.call(buf, function(byte, i) {
    if (i < 12) {
      iv[i] = byte;
    } else {
      enc[i - 12] = byte;
    }
  });

  window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128
    },
    key,
    enc
  )
  .then(function(e) {
    return _exitLog(new TextDecoder('utf-8').decode(e));
  })
  .catch(function(e) {
    return _exitLog('wrong token!');
  });
}

function _encrypt(key, data) {
  var iv = window.crypto.getRandomValues(new Uint8Array(12));

  window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128
    },
    key,
    new TextEncoder('utf-8').encode(data)
  )
  .then(function(e) {
    var enc = new Uint8Array(e);
    var buf = new Uint8Array(iv.length + enc.length);
    Array.prototype.forEach.call(iv, function(byte, i) {
      buf[i] = byte;
    });
    Array.prototype.forEach.call(enc, function(byte, i) {
      buf[12 + i] = byte;
    });

    var a = btoa(
      String.fromCharCode.apply(
        null,
        buf
      )
    );

    var h = '-----BEGIN CIPHERTEXT-----';
    var f = '------END CIPHERTEXT------';
    var ct = h + "\n" + a + "\n" + f;

    return _exitLog(ct);
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

function _isEncrypted(input) {
  if(input.startsWith('-----BEGIN CIPHERTEXT-----') && input.endsWith('------END CIPHERTEXT------')) {
    return true;
  } else {
    return false;
  }
}

function compute() {
  var token = document.getElementById('token').value;
  var input = document.getElementById('input').value.trim();
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
      if(_isEncrypted(input)) {
        ret = _decrypt(k, input);
      } else {
        ret = _encrypt(k, input);
      }
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
