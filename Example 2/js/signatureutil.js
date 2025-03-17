// 由於WebCrypto簽出來的簽章格式為將r, s直接連再一起的IEEE Format, 而Java簽出來的為DER Format.
// 因此須將簽章稍作轉換後才可以通用.
// 參考: https://qiita.com/tomoyukilabs/items/b346a71a920eb7a93501
// 參考2: https://superuser.com/questions/1023167/can-i-extract-r-and-s-from-an-ecdsa-signature-in-bit-form-and-vica-versa

// DER -> IEEE
function der2concat(sig) {
  var buf = new Uint8Array(sig);
  var head = buf.slice(0, 2);
  var sStart = buf[3] + 4;
  var r = concatPart(buf, 4, buf[3] + 4);
  var s = concatPart(buf, buf[3] + 4 + 2, buf.length);
  var result = new Uint8Array(r.length + s.length);
  result.set(r);
  result.set(s, r.length);
  return result.buffer;
}

// IEEE -> DER
function concat2der(sig) {
  var buf = new Uint8Array(sig);
  var r = buf.slice(0, 32);
  var s = buf.slice(32);
  var r2 = derPart(r);
  var s2 = derPart(s);
  var result = new Uint8Array(2 + r2.length + s2.length);
  result.set([48, r2.length + s2.length]);
  result.set(r2, 2);
  result.set(s2, 2 + r2.length);
  return result.buffer;
}

// 建立包含資料長度及標頭的DER部分陣列
function derPart(arr) {
  var head = [2];
  if (arr[0] > 127) {
    head = head.concat([arr.length + 1, 0]);
  } else {
    head = head.concat(arr.length);
  }
  var result = new Uint8Array(head.length + arr.length);
  result.set(head);
  result.set(arr, head.length);
  return result;
}

// 擷取資料部分的陣列
function concatPart(arr, start, end) {
  var r = arr.slice(start, end);
  if (r[0] == 0 && r[1] > 127) {
    r = r.slice(1);
  }
  return r;
}
