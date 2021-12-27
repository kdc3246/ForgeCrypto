// function randomKey () {

const randomKey = () => {
  var key = document.getElementById("key");
  var iv = document.getElementById("iv");
  var algo;
  var keySize, ivSize;

  var e = document.getElementById("algorithm");
  var algorithm = e.options[e.selectedIndex].text;
  var e = document.getElementById("mode");
  var mode = e.options[e.selectedIndex].text;
  var e = document.getElementById("keyLength");
  var keyLength = e.options[e.selectedIndex].text;

  if (algorithm === "DES" && mode == "ECB") {
    // DES-ECB
    algo = "DES-ECB";
    keySize = 64;
    key.value = forge.util.bytesToHex(forge.random.getBytesSync(keySize / 8));
    iv.value = "";
  } else if (algorithm === "DES" && mode == "CBC") {
    // DES-CBC
    algo = "DES-CBC";
    keySize = 64;
    ivSize = 64;
    key.value = forge.util.bytesToHex(forge.random.getBytesSync(keySize / 8));
    iv.value = forge.util.bytesToHex(forge.random.getBytesSync(ivSize / 8));
  } else if (algorithm === "3DES" && mode == "ECB") {
    // 3DES-ECB
    algo = "3DES-ECB";
    keySize = 192;
    key.value = forge.util.bytesToHex(forge.random.getBytesSync(keySize / 8));
    iv.value = "";
  } else if (algorithm === "3DES" && mode == "CBC") {
    // 3DES-CBC
    algo = "3DES-CBC";
    keySize = 192;
    ivSize = 64;
    key.value = forge.util.bytesToHex(forge.random.getBytesSync(keySize / 8));
    iv.value = forge.util.bytesToHex(forge.random.getBytesSync(ivSize / 8));
  } else if (algorithm === "AES" && mode == "ECB") {
    // AES-ECB
    algo = "AES-ECB";
    keySize = keyLength;
    key.value = forge.util.bytesToHex(forge.random.getBytesSync(keySize / 8));
    iv.value = "";
  } else if (algorithm === "AES" && mode == "CBC") {
    // AES-CBC
    algo = "AES-CBC";
    keySize = keyLength;
    ivSize = 128;
    key.value = forge.util.bytesToHex(forge.random.getBytesSync(keySize / 8));
    iv.value = forge.util.bytesToHex(forge.random.getBytesSync(ivSize / 8));
  }
};

const encrypt = () => {
  var e = document.getElementById("algorithm");
  var algorithm = e.options[e.selectedIndex].text;
  var e = document.getElementById("mode");
  var mode = e.options[e.selectedIndex].text;

  var key = forge.util.hexToBytes(document.getElementById("key").value);
  var iv = forge.util.hexToBytes(document.getElementById("iv").value);
  var msg = document.getElementById("message").value;
  var plaintextUtf8 = forge.util.encodeUtf8(msg);
  var encrypted = document.getElementById("encrypted");
  var cipher;

  if (algorithm === "DES" && mode === "ECB") {
    // DES-ECB
    cipher = forge.cipher.createCipher("DES-ECB", key);
    cipher.start();
  } else if (algorithm === "DES" && mode === "CBC") {
    // DES-CBC
    cipher = forge.cipher.createCipher("DES-CBC", key);
    cipher.start({ iv: iv });
  } else if (algorithm === "3DES" && mode === "ECB") {
    // 3DES-ECB
    cipher = forge.cipher.createCipher("3DES-ECB", key);
    cipher.start();
  } else if (algorithm === "3DES" && mode === "CBC") {
    // 3DES-CBC
    cipher = forge.cipher.createCipher("3DES-CBC", key);
    cipher.start({ iv: iv });
  } else if (algorithm === "AES" && mode === "ECB") {
    // AES-ECB
    cipher = forge.cipher.createCipher("AES-ECB", key);
    cipher.start();
  } else if (algorithm === "AES" && mode === "CBC") {
    // AES-CBC
    cipher = forge.cipher.createCipher("AES-CBC", key);
    cipher.start({ iv: iv });
  }
  cipher.update(forge.util.createBuffer(plaintextUtf8, "binary"));
  cipher.finish();
  encrypted.value = forge.util.bytesToHex(cipher.output);
};

const decrypt = () => {
  var e = document.getElementById("algorithm");
  var algorithm = e.options[e.selectedIndex].text;
  var e = document.getElementById("mode");
  var mode = e.options[e.selectedIndex].text;

  var key = forge.util.hexToBytes(document.getElementById("key").value);
  var iv = forge.util.hexToBytes(document.getElementById("iv").value);
  var encryptedBytes = forge.util.hexToBytes(
    document.getElementById("encrypted").value
  );
  var decrypted = document.getElementById("decrypted");

  var decipher;

  if (algorithm === "DES" && mode === "ECB") {
    // DES-ECB
    decipher = forge.cipher.createDecipher("DES-ECB", key);
    decipher.start();
  } else if (algorithm === "DES" && mode === "CBC") {
    // DES-CBC
    decipher = forge.cipher.createDecipher("DES-CBC", key);
    decipher.start({ iv: iv });
  } else if (algorithm === "3DES" && mode === "ECB") {
    // 3DES-ECB
    decipher = forge.cipher.createDecipher("3DES-ECB", key);
    decipher.start();
  } else if (algorithm === "3DES" && mode === "CBC") {
    // 3DES-CBC
    decipher = forge.cipher.createDecipher("3DES-CBC", key);
    decipher.start({ iv: iv });
  } else if (algorithm === "AES" && mode === "ECB") {
    // AES-ECB
    decipher = forge.cipher.createDecipher("AES-ECB", key);
    decipher.start();
  } else if (algorithm === "AES" && mode === "CBC") {
    // AES-CBC
    decipher = forge.cipher.createDecipher("AES-CBC", key);
    decipher.start({ iv: iv });
  }
  decipher.update(forge.util.createBuffer(encryptedBytes, "binary"));
  decipher.finish();
  decrypted.value = decipher.output;
};
