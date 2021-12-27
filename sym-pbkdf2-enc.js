function randomSalt() {
  var salt = document.getElementById("salt");
  var e = document.getElementById("algorithm");
  var algorithm = e.options[e.selectedIndex].text;
  var e = document.getElementById("keyLength");
  var keyLength = e.options[e.selectedIndex].text;
  if (algorithm === "DES" || algorithm === "3DES") {
    salt.value = forge.util.bytesToHex(forge.random.getBytesSync(8));
  } else if (algorithm === "AES") {
    salt.value = forge.util.bytesToHex(forge.random.getBytesSync(16));
  }
}

function PBKDF2() {
  var pass = document.getElementById("pass").value;
  var salt = document.getElementById("salt").value;
  var it = document.getElementById("iteration").value;
  var key = document.getElementById("key");
  var iv = document.getElementById("iv");

  var e = document.getElementById("algorithm");
  var algorithm = e.options[e.selectedIndex].text;
  var e = document.getElementById("keyLength");
  var keyLength = e.options[e.selectedIndex].text;
  var e = document.getElementById("mode");
  var mode = e.options[e.selectedIndex].text;

  if (algorithm === "DES") {
    key.value = forge.util.bytesToHex(forge.pkcs5.pbkdf2(pass, salt, it, 8));
    if (mode === "CBC") {
      iv.value = forge.util.bytesToHex(forge.random.getBytesSync(8));
    } else {
      iv.value = "";
    }
  } else if (algorithm === "3DES") {
    key.value = forge.util.bytesToHex(forge.pkcs5.pbkdf2(pass, salt, it, 24));
    if (mode === "CBC") {
      iv.value = forge.util.bytesToHex(forge.random.getBytesSync(8));
    } else {
      iv.value = "";
    }
  } else if (algorithm === "AES" && keyLength === "128") {
    key.value = forge.util.bytesToHex(forge.pkcs5.pbkdf2(pass, salt, it, 16));
    if (mode === "CBC") {
      iv.value = forge.util.bytesToHex(forge.random.getBytesSync(16));
    } else {
      iv.value = "";
    }
  } else if (algorithm === "AES" && keyLength === "192") {
    key.value = forge.util.bytesToHex(forge.pkcs5.pbkdf2(pass, salt, it, 24));
    if (mode === "CBC") {
      iv.value = forge.util.bytesToHex(forge.random.getBytesSync(16));
    } else {
      iv.value = "";
    }
  } else if (algorithm === "AES" && keyLength === "256") {
    key.value = forge.util.bytesToHex(forge.pkcs5.pbkdf2(pass, salt, it, 32));
    if (mode === "CBC") {
      iv.value = forge.util.bytesToHex(forge.random.getBytesSync(16));
    } else {
      iv.value = "";
    }
  }
}

function encrypt() {
  var key = forge.util.hexToBytes(document.getElementById("key").value);
  var msg = document.getElementById("message").value;
  var plaintextUtf8 = forge.util.encodeUtf8(msg);
  var encrypted = document.getElementById("encrypted");
  var iv = forge.util.hexToBytes(document.getElementById("iv").value);

  var e = document.getElementById("algorithm");
  var algorithm = e.options[e.selectedIndex].text;
  var e = document.getElementById("mode");
  var mode = e.options[e.selectedIndex].text;
  var cipher;

  if (algorithm === "DES" && mode === "ECB") {
    // DES-ECB
    cipher = forge.cipher.createCipher("DES-ECB", key);
    cipher.start();
  } else if (algorithm === "3DES" && mode === "ECB") {
    // 3DES-ECB
    cipher = forge.cipher.createCipher("3DES-ECB", key);
    cipher.start();
  } else if (algorithm === "AES" && mode === "ECB") {
    // AES-ECB
    cipher = forge.cipher.createCipher("AES-ECB", key);
    cipher.start();
  } else if (algorithm === "DES" && mode === "CBC") {
    // DES-CBC
    cipher = forge.cipher.createCipher("DES-CBC", key);
    cipher.start({ iv: iv });
  } else if (algorithm === "3DES" && mode === "CBC") {
    // 3DES-CBC
    cipher = forge.cipher.createCipher("3DES-CBC", key);
    cipher.start({ iv: iv });
  } else if (algorithm === "AES" && mode === "CBC") {
    // AES-CBC
    cipher = forge.cipher.createCipher("AES-CBC", key);
    cipher.start({ iv: iv });
  }
  cipher.update(forge.util.createBuffer(plaintextUtf8, "binary"));
  cipher.finish();
  encrypted.value = forge.util.bytesToHex(cipher.output);
}

function decrypt() {
  var key = forge.util.hexToBytes(document.getElementById("key").value);
  var encryptedBytes = forge.util.hexToBytes(
    document.getElementById("encrypted").value
  );
  var decrypted = document.getElementById("decrypted");
  var iv = forge.util.hexToBytes(document.getElementById("iv").value);
  var decipher;

  var e = document.getElementById("algorithm");
  var algorithm = e.options[e.selectedIndex].text;
  var e = document.getElementById("mode");
  var mode = e.options[e.selectedIndex].text;

  if (algorithm === "DES" && mode === "ECB") {
    // DES-ECB
    decipher = forge.cipher.createDecipher("DES-ECB", key);
    decipher.start();
  } else if (algorithm === "3DES" && mode === "ECB") {
    // 3DES-ECB
    decipher = forge.cipher.createDecipher("3DES-ECB", key);
    decipher.start();
  } else if (algorithm === "AES" && mode === "ECB") {
    // AES-ECB
    decipher = forge.cipher.createDecipher("AES-ECB", key);
    decipher.start();
  } else if (algorithm === "DES" && mode === "CBC") {
    // DES-CBC
    decipher = forge.cipher.createDecipher("DES-CBC", key);
    decipher.start({ iv: iv });
  } else if (algorithm === "3DES" && mode === "CBC") {
    // 3DES-CBC
    decipher = forge.cipher.createDecipher("3DES-CBC", key);
    decipher.start({ iv: iv });
  } else if (algorithm === "AES" && mode === "CBC") {
    // AES-CBC
    decipher = forge.cipher.createDecipher("AES-CBC", key);
    decipher.start({ iv: iv });
  }
  decipher.update(forge.util.createBuffer(encryptedBytes, "binary"));
  decipher.finish();
  decrypted.value = decipher.output;
}
