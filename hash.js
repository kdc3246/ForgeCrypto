function hash() {
  var message = document.getElementById("message").value;
  var result = document.getElementById("result");
  var select = document.getElementById("item");
  var option_value = select.options[select.selectedIndex].value;

  if (option_value == 1) {
    // MD5
    var md = forge.md.md5.create();
    md.update(message);
    result.value = md.digest().toHex();
  }
  if (option_value == 2) {
    // SHA1
    var md = forge.md.sha1.create();
    md.update(message);
    result.value = md.digest().toHex();
  }
  if (option_value == 3) {
    // SHA256
    var md = forge.md.sha256.create();
    md.update(message);
    result.value = md.digest().toHex();
  }
  if (option_value == 4) {
    // SHA384
    var md = forge.md.sha384.create();
    md.update(message);
    result.value = md.digest().toHex();
  }
  if (option_value == 5) {
    // SHA512
    var md = forge.md.sha512.create();
    md.update(message);
    result.value = md.digest().toHex();
  }
}
