function randomSalt() {
  var salt = document.getElementById("salt");
  var bytes = forge.random.getBytesSync(32);
  salt.value = forge.util.bytesToHex(bytes);
}

function PBKDF2() {
  var salt = document.getElementById("salt").value;
  var it = document.getElementById("iteration").value;
  var pass = document.getElementById("pass").value;
  var length = document.getElementById("keySize").value;
  var result = document.getElementById("result");
  var keyBytes = forge.pkcs5.pbkdf2(pass, salt, it, length);
  result.value = forge.util.bytesToHex(keyBytes);
}
