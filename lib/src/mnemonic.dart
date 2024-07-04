import 'dart:typed_data';

import 'package:halo_crypto/src/bip39/bip39_base.dart';
import 'package:halo_crypto/src/bip39/wordlists/english.dart';

class Mnemonic {
  /// 生成助记词
  /// 128=>12,160=>15,192=>18,224=>21,256=>24
  static String generateMnemonic({int strength = 128}) {
    return BIP39.generateMnemonic(strength: strength);
  }

  /// 检查助记词
  static bool validateMnemonic(String mnemonic) {
    return BIP39.validateMnemonic(mnemonic);
  }

  /// 所有的英文集合
  static List<String> wordList() {
    return gEnglishWordList;
  }

  static Uint8List mnemonicToSeed(String mnemonic) {
    final wordsList = mnemonic.split(' ');
    wordsList.removeWhere((word) => word == '');
    mnemonic = wordsList.join(' ');
    if (!BIP39.validateMnemonic(mnemonic)) {
      throw 'invalid mnemonic';
    }

    return BIP39.mnemonicToSeed(mnemonic);
  }
}
