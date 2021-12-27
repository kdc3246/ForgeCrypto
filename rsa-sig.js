function keyGeneration() {
  var pubKey = document.getElementById("pubKey");
  var privKey = document.getElementById("privKey");
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
}

function sign() {
  var privKey = document.getElementById("privKey");
  var privateKey = forge.pki.privateKeyFromPem(privKey.value);
  var plaintext = document.getElementById("plaintext").value;
  var md = forge.md.sha1.create();
  md.update(plaintext, "utf8");
  var sig = privateKey.sign(md);
  var signature = document.getElementById("signature");
  signature.value = forge.util.bytesToHex(sig);
}

function verify() {
  var pubKey = document.getElementById("pubKey");
  var publicKey = forge.pki.publicKeyFromPem(pubKey.value);
  var signature = document.getElementById("signature");
  var signatureBytes = forge.util.hexToBytes(signature.value);
  var plaintext = document.getElementById("plaintext").value;
  var verified = document.getElementById("verified");
  var md = forge.md.sha1.create();
  md.update(plaintext, "utf8");
  verified.value = publicKey.verify(md.digest().bytes(), signatureBytes);
}
