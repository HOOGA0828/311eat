function createPemPublicKey(publicKey) {
  return "-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----";
}

function createPemPrivateKey(privateKey) {
  return "-----BEGIN PRIVATE KEY-----\n" + privateKey + "\n-----END PRIVATE KEY-----";
}

function extractPemPublicKey(pemPublicKey) {
  var regex = /-----BEGIN PUBLIC KEY----- ?\n?([\s\S]+?)\n?-----END PUBLIC KEY-----/;
  return regex.exec(pemPublicKey)[1];
}

function extractPemPrivateKey(pemPrivateKey) {
  var regex = /-----BEGIN PRIVATE KEY----- ?\n?([\s\S]+?)\n?-----END PRIVATE KEY-----/;
  return regex.exec(pemPrivateKey)[1];
}
