part of 'i_wallet.dart';

class HDNode {
  final Uint8List privateKey;

  /// The (compresses) public key for this HDNode.
  final Uint8List publicKey;

  final String chainCode;

  final String fingerprint;

  final String parentFingerprint;

  final int index;

  final int depth;

  HDNode({
    required this.privateKey,
    required this.publicKey,
    required this.chainCode,
    required this.fingerprint,
    required this.parentFingerprint,
    required this.index,
    required this.depth,
  });

  static HDNode _nodeFromRoot(
    BIP32 root, {
    String? path,
  }) {
    return HDNode(
      privateKey: root.privateKey!,
      publicKey: root.publicKey,
      chainCode: bytesToHex(root.chainCode, include0x: true),
      index: root.index,
      depth: root.depth,
      parentFingerprint: root.parentFingerprint != 0 ? pad0x(root.parentFingerprint.toRadixString(16)) : '0x00000000',
      fingerprint: bytesToHex(root.fingerprint, include0x: true),
    );
  }

  factory HDNode._fromSeed(Uint8List seed) {
    if (seed.length < 16 || seed.length > 64) {
      throw 'invalid seed';
    }
    final root = BIP32.fromSeed(seed);

    return _nodeFromRoot(root);
  }

  factory HDNode.fromMnemonic(String mnemonic) {
    return HDNode._fromSeed(Mnemonic.mnemonicToSeed(mnemonic));
  }

  factory HDNode.fromSeed(Uint8List seed) {
    return HDNode._fromSeed(seed);
  }

  HDNode neuter() {
    var newHDNode = this;
    return newHDNode;
  }

  HDNode derivePath(String path) {
    final root = BIP32.fromPrivateKey(
      privateKey,
      hexToBytes(chainCode),
    );

    final child = root.derivePath(path);
    return _nodeFromRoot(child, path: path);
  }
}


