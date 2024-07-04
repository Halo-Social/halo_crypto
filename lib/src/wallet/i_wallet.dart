import 'dart:typed_data';

import 'package:halo_crypto/src/bip32/bip32_base.dart';
import 'package:halo_crypto/src/utils/formatting.dart';
import 'package:halo_crypto/src/mnemonic.dart';

part 'hd_node.dart';

/// path: m/purpose'/coin'/account'/change/index
abstract class IWallet {
  late Uint8List ecPrivateKey;

  String get privateKey => ecPrivateKey.toHexWith0x;

  String get publicKey;

  String get address;

  int get coinForBip32;

  Future restoreWalletFromMn({required String mnemonic, int account = 0, int change = 0, int index = 0}) {
    return restoreWalletFromSeed(seed: Mnemonic.mnemonicToSeed(mnemonic), account: account, change: change, index: index);
  }

  Future restoreWalletFromSeed({required Uint8List seed, int account = 0, int change = 0, int index = 0}) {
    var path = "m/44'/$coinForBip32'/$account'/$change/$index";
    var hdNode = HDNode.fromSeed(seed).derivePath(path);
    return restoreWalletFromPrivateKey(privateKey: hdNode.privateKey);
  }

  Future restoreWalletFromPrivateKey({required Uint8List privateKey}) async {
    ecPrivateKey = privateKey;
  }

  bool validateAddress({required String address});
}
