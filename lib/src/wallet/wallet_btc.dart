import 'dart:typed_data';

import 'package:halo_crypto/src/utils/formatting.dart';
import 'package:halo_crypto/src/wallet/i_wallet.dart';
import 'package:bitcoin_base/bitcoin_base.dart';

class BtcWallet extends IWallet {
  ECPrivate? __ecPrivate;

  ECPrivate get _ecPrivate => __ecPrivate ??= ECPrivate.fromHex(ecPrivateKey.toHexWith0x);

  @override
  int get coinForBip32 => 0;

  @override
  String get privateKey => _ecPrivate.toWif();

  @override
  String get address => _ecPrivate.getPublic().toP2pkAddress().toAddress(BitcoinNetwork.mainnet);

  @override
  String get publicKey => _ecPrivate.getPublic().toHex(compressed: false);

  @override
  bool validateAddress({required String address}) {
    return address.startsWith("1") && address.length == 34;
  }
}
