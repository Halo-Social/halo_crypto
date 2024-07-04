import 'dart:typed_data';

import 'package:eth_sig_util/eth_sig_util.dart';
import 'package:halo_crypto/src/crypto/secp256k1.dart' as secp256k1;
import 'package:halo_crypto/src/utils/formatting.dart';
import 'package:halo_crypto/src/wallet/i_wallet.dart';

class EthWallet extends IWallet with EthSinger, EthRecoverSignature {
  @override
  int get coinForBip32 => 60;

  @override
  String get address => secp256k1.publicKeyToAddress(publicKey.hex2Bytes).toHexWith0x;

  @override
  String get publicKey => secp256k1.privateKeyBytesToPublic(ecPrivateKey).toHexWith0x;

  String get compressedPublicKey => secp256k1.privateKeyBytesToCompressedPublic(ecPrivateKey).toHexWith0x;

  @override
  bool validateAddress({required String address}) {
    return isValidEthereumAddress(address);
  }
}

mixin EthSinger on IWallet {
  /// Disables universal signature functions
  /// [Deprecated]
  String signMessage(Uint8List message) {
    throw 'not support signMessage, because unsafe act';
  }
  ///  [message] will add personal prefix
  String signPersonalMessage(Uint8List message) {
    return EthSigUtil.signPersonalMessage(message: message, privateKeyInBytes: ecPrivateKey);
  }
  /// Eip712
  String signPersonalTypedData({required String jsonData, required TypedDataVersion version}) {
    return EthSigUtil.signPersonalTypedData(jsonData: jsonData, version: version, privateKeyInBytes: ecPrivateKey);
  }
}

mixin EthRecoverSignature {
  /// return wallet address
  String recoverSignature({required String signature, required Uint8List message}) {
    return EthSigUtil.recoverSignature(signature: signature, message: message);
  }
  /// return wallet address
  /// [signature] is result of [signPersonalMessage]
  String recoverPersonalSignature({required String signature, required Uint8List message}) {
    return EthSigUtil.recoverPersonalSignature(signature: signature, message: message);
  }
}
