// 文字列から ArrayBuffer への変換
var encoder = new TextEncoder(); // always utf-8
var decoder = new TextDecoder();
function string_to_buffer(src) {
  return encoder.encode(src);
}

// ArrayBuffer から文字列への変換

function buffer_to_string(buf) {
  return decoder.decode(buf);
}

// base64 文字列から ArrayBuffer への変換
function string_to_buffer64(src) {
  var byteCharacters = atob(src);
  var byteNumbers = new Uint8Array(byteCharacters.length);
  for (var i = 0; i < byteCharacters.length; i++) {
      byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  return byteNumbers.buffer;
}

// ArrayBuffer から Base64 文字列への変換

function buffer_to_string64(buf) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
}
