import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:halo_crypto/halo_crypto.dart';
import 'package:halo_crypto/src/crypto/keccak.dart';
import 'package:pointycastle/src/utils.dart' as p_utils;

/// If present, removes the 0x from the start of a hex-string.
String strip0x(String hex) {
  if (hex.startsWith('0x')) return hex.substring(2);
  return hex;
}

String pad0x(String hex) {
  if (hex.startsWith('0x')) {
    return hex;
  } else {
    return '0x$hex';
  }
}

bool isValidFormat(String address) {
  return RegExp(r"^[0-9a-fA-F]{40}$").hasMatch(strip0x(address));
}

String bytesToHex(List<int> bytes, {bool include0x = false, int? forcePadLength, bool padToEvenLength = false}) {
  var encoded = hex.encode(bytes);

  if (forcePadLength != null) {
    assert(forcePadLength >= encoded.length);

    final padding = forcePadLength - encoded.length;
    encoded = ('0' * padding) + encoded;
  }

  if (padToEvenLength && encoded.length % 2 != 0) {
    encoded = '0$encoded';
  }

  return (include0x ? '0x' : '') + encoded;
}

Uint8List hexToBytes(String hexStr) {
  final bytes = hex.decode(strip0x(hexStr));
  if (bytes is Uint8List) return bytes;

  return Uint8List.fromList(bytes);
}

Uint8List unsignedIntToBytes(BigInt number) {
  assert(!number.isNegative);
  return p_utils.encodeBigIntAsUnsigned(number);
}

BigInt bytesToUnsignedInt(Uint8List bytes) {
  return p_utils.decodeBigIntWithSign(1, bytes);
}

BigInt bytesToInt(List<int> bytes) => p_utils.decodeBigInt(bytes);

Uint8List intToBytes(BigInt number) => p_utils.encodeBigInt(number);

BigInt hexToInt(String hex) {
  return BigInt.parse(strip0x(hex), radix: 16);
}

int hexToDartInt(String hex) {
  return int.parse(strip0x(hex), radix: 16);
}

bool isHexString(String value, {int? length}) {
  RegExp regExp = RegExp(
    r"^0x[0-9A-Fa-f]*$",
  );
  if (length != null && value.length != 2 + 2 * length) {
    return false;
  }
  return regExp.hasMatch(value);
}

String getChecksumAddress(String address) {
  if (!isHexString(address, length: 20)) {
    throw 'invalid hex value';
  }
  address = address.toLowerCase();

  final chars = address.substring(2).split("");

  Uint8List expanded = Uint8List(40);
  for (var i = 0; i < 40; i++) {
    expanded[i] = chars[i].codeUnitAt(0);
  }

  final hashed = keccak256(expanded);
  for (var i = 0; i < 40; i += 2) {
    if ((hashed[i >> 1] >> 4) >= 8) {
      chars[i] = chars[i].toUpperCase();
    }
    if ((hashed[i >> 1] & 0x0f) >= 8) {
      chars[i + 1] = chars[i + 1].toUpperCase();
    }
  }

  return '0x' + chars.join('');
}

bool isValidEthereumAddress(String address) {
  if (!isValidFormat(address)) {
    return false;
  }

  final addr = strip0x(address);
  // if all lowercase or all uppercase, as in checksum is not present
  if (RegExp(r"^[0-9a-f]{40}$").hasMatch(addr) || RegExp(r"^[0-9A-F]{40}$").hasMatch(addr)) {
    return true;
  }

  String checksumAddress;
  try {
    checksumAddress = getChecksumAddress(address);
  } catch (err) {
    return false;
  }

  return addr == checksumAddress.substring(2);
}

bool isValidatePrivateKey(String privateKey) {
  if (privateKey.trim().isEmpty) {
    return false;
  }
  // EVM私钥格式 0x+64位字符，字符范围0-9a-fA-F
  RegExp regExpStr = RegExp(r'^[0-9a-fA-F]{64}$');
  String privateKeyNo0x = strip0x(privateKey.trim());
  return regExpStr.hasMatch(privateKeyNo0x);
}

Uint8List uint8ListFromList(List<int> data) {
  if (data is Uint8List) return data;

  return Uint8List.fromList(data);
}

Uint8List padUint8ListTo32(Uint8List data) {
  assert(data.length <= 32);
  if (data.length == 32) return data;

  // todo there must be a faster way to do this?
  return Uint8List(32)..setRange(32 - data.length, 32, data);
}

extension ListIntExt on List<int> {
  String get toBase58 => base58.encode(toUint8List);

  String get toHex => bytesToHex(this);

  String get toHexWith0x => bytesToHex(this, include0x: true);

  BigInt get toInt => bytesToInt(this);

  Uint8List get toUint8List => Uint8List.fromList(this);
}

extension StringExt on String {
  Uint8List get hex2Bytes => hexToBytes(this);

  Uint8List get base58ToBytes => base58.decode(this);

  BigInt get toInt => hexToInt(this);
}
