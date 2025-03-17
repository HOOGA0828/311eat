// 產生AES-256金鑰
function generateAesKey() {
  log("Generate AES key.");
  var key = forge.random.getBytes(32);
  log(key, false);
  log(forge.util.encode64(key), false);
  return Promise.resolve(key);
}

// 產生隨機初始向量
function generateIV() {
  log("Generate Initial Vector.");
  var iv = forge.random.getBytes(16);
  log(iv, false);
  log(forge.util.encode64(iv), false);
  return Promise.resolve(iv);
}

// 產生RSA-2048金鑰組
function generateRsaKeyPair() {
  log("Generate RSA key pair.");
  var keypair = forge.pki.rsa.generateKeyPair({bits: 2048, e: 0x10001});
  return Promise.resolve(keypair);
}

// 產生ECC-256金鑰組
function generateEccKeyPair() {
  log("Generate ECC key pair.");
  return crypto.subtle.generateKey({
    name: "ECDSA",
    namedCurve: "P-256"
  }, true, ["sign", "verify"]);
}

// 匯出AES金鑰成Base64格式
function exportAesKey(aesKey) {
  log("Export AES key.")
  return forge.util.encode64(aesKey);
}

// 匯入Base64格式AES金鑰
function importAesKey(aesKeyRaw) {
  log("Import AES key.");
  return forge.util.decode64(aesKeyRaw);
}

// 匯出RSA公鑰成Base64格式
function exportRsaPublicKey(rsaPublicKey) {
  log("Export RSA public key.")
  var pem = forge.pki.publicKeyToPem(rsaPublicKey);
  return Promise.resolve(extractPemPublicKey(pem));
}

// 匯出RSA私鑰成Base64格式
function exportRsaPrivateKey(rsaPrivateKey) {
  log("Export RSA private key.")

  // convert a Forge private key to an ASN.1 RSAPrivateKey
  var rsaPrivateKey = forge.pki.privateKeyToAsn1(rsaPrivateKey);
  // wrap an RSAPrivateKey ASN.1 object in a PKCS#8 ASN.1 PrivateKeyInfo
  var privateKeyInfo = forge.pki.wrapRsaPrivateKey(rsaPrivateKey);
  // convert a PKCS#8 ASN.1 PrivateKeyInfo to PEM
  var pem = forge.pki.privateKeyInfoToPem(privateKeyInfo);
  // var pem = forge.pki.privateKeyToPem(rsaPrivateKey);
  return Promise.resolve(extractPemPrivateKey(pem));
}

// 匯入Base64格式RSA公鑰
function importRsaPublicKey(rsaPublicKeyRaw) {
  log("Import RSA public key.");
  var pem = createPemPublicKey(rsaPublicKeyRaw);
  return Promise.resolve(forge.pki.publicKeyFromPem(pem));
}

// 匯入Base64格式RSA私鑰
function importRsaPrivateKey(rsaPrivateKeyRaw) {
  log("Import RSA private key.");
  var pem = createPemPrivateKey(rsaPrivateKeyRaw);
  return Promise.resolve(forge.pki.privateKeyFromPem(pem));
}

// 匯出ECC公鑰成Base64格式
function exportEccPublicKey(eccPublicKey) {
  log("Export ECC public key.")
  return crypto.subtle.exportKey("spki", eccPublicKey);
}

// 匯出ECC私鑰成Base64格式
function exportEccPrivateKey(eccPrivateKey) {
  log("Export ECC private key.")
  return crypto.subtle.exportKey("pkcs8", eccPrivateKey);
}

// 匯入Base64格式ECC公鑰
function importEccPublicKey(eccPublicKey) {
  log("Import ECC public key.");
  var eccPublicKeyRaw = string_to_buffer64(eccPublicKey);
  return crypto.subtle.importKey(
    "spki",
    eccPublicKeyRaw,
    {name: "ECDSA", namedCurve: "P-256"},
    false,
    ["verify"]
  );
}

// 匯入Base64格式ECC私鑰
function importEccPrivateKey(eccPrivateKey) {
  log("Import ECC private key.");
  var eccPrivateKeyRaw = string_to_buffer64(eccPrivateKey);
  return crypto.subtle.importKey(
    "pkcs8",
    eccPrivateKeyRaw,
    {name: "ECDSA", namedCurve: "P-256"},
    false,
    ["sign"]
  );
}

// 利用AES-CBC加密訊息
function encryptAes(aesKeyBuf, ivBuf, msg) {
  log("Encrypt message with AES.");

  var msgBuf = forge.util.createBuffer(string_to_buffer(msg));
  var cipher = forge.cipher.createCipher('AES-CBC', aesKeyBuf);
  cipher.start({iv: ivBuf});
  cipher.update(msgBuf);
  cipher.finish();
  log(cipher.output, false);
  var encrypted = forge.util.encode64(cipher.output.data);
  log(encrypted, false);

  return Promise.resolve(encrypted);
}

// 利用AES-CBC解密訊息
function decryptAes(aesKeyBuf, iv64, msgEnc64) {
  log("Decrypt message with AES.");

  var ivBuf = forge.util.decode64(iv64);
  var msgEncBuf = forge.util.createBuffer(string_to_buffer64(msgEnc64));
  var decipher = forge.cipher.createDecipher('AES-CBC', aesKeyBuf);
  decipher.start({iv: ivBuf});
  decipher.update(msgEncBuf);
  var result = decipher.finish(); // check 'result' for true/false
  var msg = forge.util.decodeUtf8(decipher.output.data);
  return Promise.resolve(msg);
}

// 裡用RSA-PKCS1-V1_5加密AES金鑰
function encryptRsa(rsaPublicBuf, aesKeyBuf) {
  log("Encrypt message with RSA.");
  return Promise.resolve(
    forge.util.encode64(rsaPublicBuf.encrypt(aesKeyBuf, 'RSAES-PKCS1-V1_5'))
  );
}

// 裡用RSA-PKCS1-V1_5解密AES金鑰
function decryptRsa(rsaPrivateBuf, aesKeyEnc64) {
  log("Decrypt message with RSA.");
  var aesKeyEncBuf = forge.util.decode64(aesKeyEnc64);
  return Promise.resolve(rsaPrivateBuf.decrypt(aesKeyEncBuf));
}

// 利用ECC-P256(secp256r1)曲線對訊息做數位簽章
function signEcc(eccPrivateBuf, msgBuf) {
  log("Sign message with ECC.");
  log(msgBuf, false);
  return crypto.subtle.sign({
    name: "ECDSA",
    hash: {name: "SHA-256"}
  }, eccPrivateBuf, msgBuf);
}

// 利用ECC-P256(secp256r1)曲線驗證數位簽章
function verifyEcc(eccPublicBuf, signatureBuf, msgBuf) {
  log("Verify message with ECC.");
  return crypto.subtle.verify({
    name: "ECDSA",
    hash: {name: "SHA-256"}
  }, eccPublicBuf, signatureBuf, msgBuf);
}

// 取得指定ID的HTML物件
function element(id) {
  return document.getElementById(id);
}

// Log訊息至Console及TextArea
function log(obj, print = true) {
  console.log(obj);
  if (print) {
    var textarea = element('log');
    textarea.value += obj;
    textarea.value += "\n";
    textarea.scrollTop = textarea.scrollHeight;
  }
}

function error(obj, print = true) {
  console.error(obj);
  if (print) {
    var textarea = element('log');
    textarea.value += obj;
    textarea.value += "\n";
    textarea.scrollTop = textarea.scrollHeight;
  }
  alert(obj);
}

// 清除Log及Output
function clearAll() {
  console.log('Clear All');
  element('log').value = '';
  element('result').value = '';
}

// 產生新的RSA及ECC金鑰組
function generateKeys() {
  log("Generate Keys.");
  // Generat Rsa Key Pair.
  generateRsaKeyPair().then(function(rsaKeyPair) {
    exportRsaPublicKey(rsaKeyPair.publicKey).then(function(rsaPublic) {
      element("rsaPublic").value = rsaPublic;
    });
    exportRsaPrivateKey(rsaKeyPair.privateKey).then(function(rsaPrivate) {
      element("rsaPrivate").value = rsaPrivate;
    });
  });
  // Generat Ecc Key Pair.
  generateEccKeyPair().then(function(eccKeyPair) {
    exportEccPublicKey(eccKeyPair.publicKey).then(function(eccPublic) {
      element("eccPublic").value = buffer_to_string64(eccPublic);
    });
    exportEccPrivateKey(eccKeyPair.privateKey).then(function(eccPrivate) {
      element("eccPrivate").value = buffer_to_string64(eccPrivate);
    });
  });
  log("All keys generated.");
}

// 加密訊息及對訊息做簽章並組成WaCare訊息格式
function encryptPayload() {
  log("Encrypt payload.");

  var payload = {};
  var msgBuf = string_to_buffer(element("msg").value);
  var aesKey = null;
  var aesKeyBuf = null;
  // 開始載入加密用金鑰
  log("Loading encryption keys...");
  Promise.all([
    importRsaPublicKey(element("rsaPublic").value),
    importEccPrivateKey(element("eccPrivate").value)
  ]).then(function(result) {
    // 開始加密
    log("All encryption keys loaded.");
    var rsaPublic = result[0];
    var eccPrivate = result[1];
    log("Encrypting...");
    // 產生新的AES金鑰及初始向量
    var encryptionPromise = Promise.all([
      generateIV(),
      generateAesKey()
    ]).then(function(results) {
      // 加密AES金鑰
      var iv = results[0];
      var aesKey = results[1];
      log(aesKey, false);
      return Promise.all([
        encryptAes(aesKey, iv, element("msg").value),
        Promise.resolve(encryptRsa(rsaPublic, aesKey)),
        Promise.resolve(forge.util.encode64(iv))
      ]);
    })
    // 對訊息做數位簽章
    return Promise.all([
      encryptionPromise,
      signEcc(eccPrivate, msgBuf)
    ]).then(function(results) {
      // 組成WaCare訊息格式
      log("Successful.");
      log("Constructing Json payload....");
      log(results, false);
      var msgEnc64 = results[0][0];
      var aesEnc64 = results[0][1];
      var signatureBuf = results[1];
      var iv64 = results[0][2];
      payload["iv"] = iv64;
      payload["encryptAes"] = aesEnc64;
      // 將DER格式簽章轉換為IEEE格式
      payload["verifySign"] = buffer_to_string64(concat2der(signatureBuf));
      payload["cipherText"] = msgEnc64;
      log("Json payload constructed.");
      return payload;
    });
  }).then(function(payload) {
    // 加密完成
    log(payload, false);
    element("result").value = JSON.stringify(payload, null, 2);
    log("Payload encrypted.");
  }).catch((err) => {
    error("Encryption failed.\n" + err);
  });
}

// 解析WaCare訊息格式並解密訊息及對訊息做簽章驗證
function decryptPayload() {
  log("Decrypt payload.");
  var msg = null;
  // 開始載入解密用金鑰
  Promise.all([
    importRsaPrivateKey(element("rsaPrivate").value),
    importEccPublicKey(element("eccPublic").value)
  ]).then(function(result) {
    log("All decryption keys loaded.");
    var rsaPrivate = result[0];
    var eccPublic = result[1];
    // 開始解析WaCare加密訊息格式
    log("Parsing payload data...");
    var payload = JSON.parse(element("msg").value);
    var iv64 = payload.iv;
    var aesEnc64 = payload.encryptAes;
    var msgEnc64 = payload.cipherText;
    // 將IEEE格式簽章轉換為DER格式
    var signatureBuf = der2concat(string_to_buffer64(payload.verifySign));

    log("Successful.");
    log("Decrypting...");
    // 解密AES金鑰
    return decryptRsa(rsaPrivate, aesEnc64).then(function(aesKey) {
      log(aesKey, false);
      // 解密訊息內容
      return decryptAes(aesKey, iv64, msgEnc64);
    }).then(function(result) {
      msg = result;
      var msgBuf = string_to_buffer(msg);
      log(msg, false);
      log(msgBuf, false);
      log(signatureBuf, false);
      // 驗證數位簽章
      return verifyEcc(eccPublic, signatureBuf, msgBuf);
    }).then(function(verified) {
      if (verified) {
        // 簽章驗證成功, 呈現訊息內容
        log(signatureBuf, false);
        log(string_to_buffer(msg), false);
        element("result").value = msg;
        log("Successful.");
      } else {
        // 簽章驗證失敗, 跳出錯誤訊息
        error("Verification failed.");
      }
      log("Payload decrypted.");
    })
  }).catch((err) => {
    error("Decryption failed.\n" + err);
  });
}
