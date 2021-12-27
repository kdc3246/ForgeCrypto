function keyGeneration() {
  var pubKey = document.getElementById("pubKey");
  var privKey = document.getElementById("privKey");
  var keyn = document.getElementById("keyn");
  var keyp = document.getElementById("keyp");
  var keyq = document.getElementById("keyq");
  var keye = document.getElementById("keye");
  var keyd = document.getElementById("keyd");
  var rsa = forge.pki.rsa;
  var select = document.getElementById("keyLength");
  var option_value = select.options[select.selectedIndex].value;
  var keySize;
  if (option_value == 1) {
    // 1024
    keySize = 1024;
  } else if (option_value == 2) {
    // 2048
    keySize = 2048;
  } else if (option_value == 3) {
    // 3072
    keySize = 3072;
  } else if (option_value == 4) {
    // 4096
    keySize = 4096;
  }
  var keypair = rsa.generateKeyPair(keySize);
  var publicKey = keypair.publicKey;
  var privateKey = keypair.privateKey;
  var publicKeyPem = forge.pki.publicKeyToPem(publicKey);
  var privateKeyPem = forge.pki.privateKeyToPem(privateKey);

  pubKey.value = publicKeyPem;
  privKey.value = privateKeyPem;
  keyn.value = publicKey.n;
  keyp.value = privateKey.p;
  keyq.value = privateKey.q;
  keye.value = publicKey.e;
  keyd.value = privateKey.d;
}

function encrypt() {
  var pubKey = document.getElementById("pubKey");
  var publicKey = forge.pki.publicKeyFromPem(pubKey.value);
  var plaintext = document.getElementById("plaintext").value;
  var bytes = forge.util.encodeUtf8(plaintext);
  var encrypted = document.getElementById("encrypted");
  encrypted.value = forge.util.bytesToHex(publicKey.encrypt(bytes));
}

function decrypt() {
  var privKey = document.getElementById("privKey");
  var privateKey = forge.pki.privateKeyFromPem(privKey.value);
  var encrypted = document.getElementById("encrypted");
  var encryptedBytes = forge.util.hexToBytes(encrypted.value);
  var decrypted = document.getElementById("decrypted");
  var decryptedBytes = privateKey.decrypt(encryptedBytes);
  decrypted.value = forge.util.decodeUtf8(decryptedBytes);
}
