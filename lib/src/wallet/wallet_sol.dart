import 'dart:typed_data';

import 'package:halo_crypto/halo_crypto.dart';
import 'package:halo_crypto/src/utils/formatting.dart';
import 'package:halo_crypto/src/wallet/i_wallet.dart';
import 'package:ed25519_hd_key/ed25519_hd_key.dart';
import 'package:pinenacl/ed25519.dart' hide IntListExtension;
import 'package:solana/solana.dart';

/// sol推导私钥 使用的是ED25519而不是bip32
class SolWallet extends IWallet {
  Ed25519HDKeyPairData? _keyPair;

  @override
  int get coinForBip32 => 501;

  @override
  String get privateKey => _keyPair!.base58PrivateKey;

  @override
  String get publicKey => _keyPair!.base58PublicKey;

  @override
  String get address => _keyPair!.base58Address;

  @override
  Future restoreWalletFromSeed({required Uint8List seed, int account = 0, int change = 0, int index = 0}) async {
    String path = _getHDPath(account, change);
    final KeyData keyData = await ED25519_HD_KEY.derivePath(path, seed);
    return restoreWalletFromPrivateKey(privateKey: Uint8List.fromList(keyData.key));
  }

  @override
  Future restoreWalletFromPrivateKey({required Uint8List privateKey}) async {
    super.restoreWalletFromPrivateKey(privateKey: privateKey);
    var keyPair = await Ed25519HDKeyPair.fromPrivateKeyBytes(privateKey: privateKey);
    _keyPair = await keyPair.extract();
  }

  @override
  bool validateAddress({required String address}) {
    return address.startsWith("1") && address.length == 34;
  }

  String _getHDPath(int? account, int? change) {
    final path = StringBuffer("m/44'/501'");
    path.write("/${account ?? 0}'");
    path.write("/${change ?? 0}'");

    return path.toString();
  }
}

extension _Ed25519HDKeyPairDataExt on Ed25519HDKeyPairData {
  String get base58PrivateKey => SigningKey.fromSeed(bytes.toUint8List).toBase58;

  String get base58PublicKey => publicKey.bytes.toBase58;

  /// 公钥就是地址base58后就是地址
  String get base58Address => publicKey.bytes.toBase58;
}
