var caPublicKey;
var caPrivatekey;
var caCert;
var userPublicKey;
var userPrivatekey;
var userCert;

function caKeyGeneration() {
  var rsa = forge.pki.rsa;
  var select = document.getElementById("caKeyLength");
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
  var caKeypair = rsa.generateKeyPair(keySize);
  this.caPublicKey = caKeypair.publicKey;
  this.caPrivateKey = caKeypair.privateKey;
  document.getElementById("caPubKey").value = forge.pki.publicKeyToPem(
    this.caPublicKey
  );
  document.getElementById("caPrivKey").value = forge.pki.privateKeyToPem(
    this.caPrivateKey
  );
}

function genCaCert() {
  var cert = forge.pki.createCertificate();
  cert.publicKey = this.caPublicKey;
  cert.serialNumber = document.getElementById("serialNumber_ca").value;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  var caAttrs = [
    {
      name: "commonName",
      value: document.getElementById("commonName_ca").value,
    },
    {
      name: "countryName",
      value: document.getElementById("countryName_ca").value,
    },
    {
      shortName: "ST",
      value: document.getElementById("ST_ca").value,
    },
    {
      name: "localityName",
      value: document.getElementById("localityName_ca").value,
    },
    {
      name: "organizationName",
      value: document.getElementById("organizationName_ca").value,
    },
    {
      shortName: "OU",
      value: document.getElementById("OU_ca").value,
    },
  ];
  cert.setSubject(caAttrs);
  cert.setIssuer(caAttrs);
  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: true,
    },
    {
      name: "keyUsage",
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
    {
      name: "extKeyUsage",
      serverAuth: true,
      clientAuth: true,
      codeSigning: true,
      emailProtection: true,
      timeStamping: true,
    },
    {
      name: "nsCertType",
      client: true,
      server: true,
      email: true,
      objsign: true,
      sslCA: true,
      emailCA: true,
      objCA: true,
    },
    {
      name: "subjectAltName",
      altNames: [
        {
          type: 6, // URI
          value: "http://example.org/webid#me",
        },
        {
          type: 7, // IP
          ip: "127.0.0.1",
        },
      ],
    },
    {
      name: "subjectKeyIdentifier",
    },
  ]);

  // self-sign certificate
  cert.sign(this.caPrivateKey);

  // convert a Forge certificate to PEM
  this.caCert = cert;
  document.getElementById("caCert").value = forge.pki.certificateToPem(cert);
  document.getElementById("caVerified").value = cert.verify(cert);
}

// Issuing User certificate

function userKeyGeneration() {
  var rsa = forge.pki.rsa;
  var select = document.getElementById("userKeyLength");
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
  var userKeypair = rsa.generateKeyPair(keySize);
  this.userPublicKey = userKeypair.publicKey;
  this.userPrivateKey = userKeypair.privateKey;
  document.getElementById("userPubKey").value = forge.pki.publicKeyToPem(
    this.userPublicKey
  );
  document.getElementById("userPrivKey").value = forge.pki.privateKeyToPem(
    this.userPrivateKey
  );
}

function genUserCert() {
  var cert = forge.pki.createCertificate();
  cert.publicKey = this.userPublicKey;
  cert.serialNumber = document.getElementById("serialNumber_user").value;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  var userAttrs = [
    {
      name: "commonName",
      value: document.getElementById("commonName_user").value,
    },
    {
      name: "countryName",
      value: document.getElementById("countryName_user").value,
    },
    {
      shortName: "ST",
      value: document.getElementById("ST_user").value,
    },
    {
      name: "localityName",
      value: document.getElementById("localityName_user").value,
    },
    {
      name: "organizationName",
      value: document.getElementById("organizationName_user").value,
    },
    {
      shortName: "OU",
      value: document.getElementById("OU_user").value,
    },
  ];

  var caAttrs = [
    {
      name: "commonName",
      value: this.caCert.subject.getField("CN").value,
      // value: document.getElementById("commonName_ca").value,
    },
    {
      name: "countryName",
      value: this.caCert.subject.getField("C").value,
      // value: document.getElementById("countryName_ca").value,
    },
    {
      shortName: "ST",
      value: this.caCert.subject.getField("ST").value,
      // value: document.getElementById("ST_ca").value,
    },
    {
      name: "localityName",
      value: this.caCert.subject.getField("L").value,
      // value: document.getElementById("localityName_ca").value,
    },
    {
      name: "organizationName",
      value: this.caCert.subject.getField("O").value,
      // value: document.getElementById("organizationName_ca").value,
    },
    {
      shortName: "OU",
      value: this.caCert.subject.getField("OU").value,
      // value: document.getElementById("OU_ca").value,
    },
  ];
  cert.setSubject(userAttrs);
  cert.setIssuer(caAttrs);
  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: true,
    },
    {
      name: "keyUsage",
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
    {
      name: "extKeyUsage",
      serverAuth: true,
      clientAuth: true,
      codeSigning: true,
      emailProtection: true,
      timeStamping: true,
    },
    {
      name: "nsCertType",
      client: true,
      server: true,
      email: true,
      objsign: true,
      sslCA: true,
      emailCA: true,
      objCA: true,
    },
    {
      name: "subjectAltName",
      altNames: [
        {
          type: 6, // URI
          value: "http://example.org/webid#me",
        },
        {
          type: 7, // IP
          ip: "127.0.0.1",
        },
      ],
    },
    {
      name: "subjectKeyIdentifier",
    },
  ]);

  // self-sign certificate
  cert.sign(caPrivateKey);

  // convert a Forge certificate to PEM
  this.userCert = cert;
  document.getElementById("userCert").value = forge.pki.certificateToPem(cert);
  document.getElementById("userVerified").value = this.caCert.verify(cert);
}
