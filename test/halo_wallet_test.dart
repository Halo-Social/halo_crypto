import 'dart:convert';
import 'dart:typed_data';

import 'package:halo_crypto/halo_crypto.dart';
import 'package:test/test.dart';

void main() async {
  for (var it in [128, 160, 192, 224, 256]) {
    test('world length', () {
      String mn = Mnemonic.generateMnemonic(strength: it);
      expect(it / 32 * 3, mn.split(' ').length);
    });
  }
  for (var it in testData) {
    test('restore wallet', () async {
      String mn = it['mn'] as String;
      var ethWallet = EthWallet();
      await ethWallet.restoreWalletFromMn(mnemonic: mn);
      var btcWallet = BtcWallet();
      await btcWallet.restoreWalletFromMn(mnemonic: mn);
      var solWallet = SolWallet();
      await solWallet.restoreWalletFromMn(mnemonic: mn);
      expect(it['eth']['pri'], ethWallet.privateKey);
      expect(it['eth']['addr'], ethWallet.address);
      expect(it['btc']['pri'], btcWallet.privateKey);
      expect(it['btc']['addr'], btcWallet.address);
      expect(it['sol']['pri'], solWallet.privateKey);
      expect(it['sol']['addr'], solWallet.address);
    });
  }

  test('test signPersonalMessage', () async {
    var data = testData[0];
    String mn = data['mn'] as String;
    var ethWallet = EthWallet();
    await ethWallet.restoreWalletFromMn(mnemonic: mn);
    var message = Uint8List.fromList(utf8.encode("this is a test message"));
    String signature =  ethWallet.signPersonalMessage(message);

    var address = ethWallet.recoverPersonalSignature(signature: signature, message: message);
    expect(data['eth']['addr'], address);

  });
}

var testData = <Map<String, dynamic>>[
  {
    "mn": "view pigeon ritual wise spatial mimic tool cattle lazy affair earth cheap",
    "eth": {
      "pri": "0xc3285539a1ef7ce18d1a46350c637d2a13335991cd588e2aa004fbe45527d3fb",
      "addr": "0x5eb557a61eca7a5a48db3274bac1d28698c0ef9c"
    },
    "btc": {
      "pri": "L3gJwwshhBMF5BLkPK3drtq9Wk3cAsZndVvZxkagxahNLNBmRR3g",
      "addr": "1JbbxEK6vt6ieCoSuwic8VKuZtCqkXMXco"
    },
    "sol": {
      "pri": "wnxerWbTosXZdhwGKLniDzVZApSPj1oWcoGfGPM8PybTwpvhQX45U65eQcKFkqZiWucdge1AGuaVvPrDePaSCLD",
      "addr": "3VktaHww4Uthv44dNXzMiQXE8Nu7rTLtbxBdaGUT9CnZ"
    }
  },
  {
    "mn": "exhaust behave echo there identify fine pink latin stadium negative width prefer",
    "eth": {
      "pri": "0xfe1c9c509f61a73de71e3fd788d96eec0ef66e6d1a3f076a2dc3c1494a74811b",
      "addr": "0x101f208f28fcfc4eb487f7344cf6c185e23503f4"
    },
    "btc": {
      "pri": "L4RGV4Z9UCo2roP52hTKNQfLTP4RjmWLTu7hTo56a24LerF4Nqop",
      "addr": "1ENeRPappR2SzefVsp2r7tm1KgzByLhxVq"
    },
    "sol": {
      "pri": "43myik1XjeqFZDgNnxcYSUhKLAQbK2h7w3nEHYkrLqgkA73DhvHVKuuokydUxfmCYZE4CgALWzorkftx2ExGy2UW",
      "addr": "AFX2HEGGHkN3w6r7h4zrNxZ3xKJ27s34xaQJEPUVbAut"
    }
  },
  {
    "mn": "document clip winter chase pool split tail give lottery summer rail pilot",
    "eth": {
      "pri": "0xf4c7650abf147562d4fd0ac7d01fef0afdf52539881f24bc4dcb8e422abc238d",
      "addr": "0xac65c900cf837c2b00f2ed4ac3fd1c6854f882e7"
    },
    "btc": {
      "pri": "KxfKp9NCo2JgUBbVneKEmJzsY2Wmmb41PkYy1SGSyfkn8ivSsuDP",
      "addr": "1DjrZrvmSxRRgsgJJ8MhqAcHgDtvu5UXAr"
    },
    "sol": {
      "pri": "22DNFrEoZDrhEC47q1Pq71QN9zxazHcTisNeGUAge5LFtKmBSyci33by3QsER81t9MZtSEukiiAgVkrkfjK2Sbcc",
      "addr": "CwzE5giX2HUwGoiJszyHxTEnFieFryqeiRU32qmUSyhA"
    }
  },
  {
    "mn": "resist duty rare payment item lecture subway wise stomach fruit write grunt",
    "eth": {
      "pri": "0x0cac8e506629f6d5182298d7a9af32dc842ae6200a97685d0c36e3a3a5513fa2",
      "addr": "0x5e429f216b3be545af9803487f4230b7ada9b0fa"
    },
    "btc": {
      "pri": "KwVRAjjRKjCxBe7h7d8gfA3L9x1HKEsyAVR24s3Lkwch6RP4PgqG",
      "addr": "1LfQQNWvH7CVNo2PLPPovMLqY6EYxL4B6V"
    },
    "sol": {
      "pri": "3mm5VN9dBoiup22Xt9UXbJ5GmJta6HZxDf9LvVVsg7Qo9PRHRSJfKU6Y8kMpoJqs1ejZ3crDhRmpjtFcJPhDK81n",
      "addr": "5RX7mw7woGj5NrphxYeFA9GewVoN2CQZf17Ldk9A3yrY"
    }
  },
  {
    "mn": "cigar lecture dynamic crack second age innocent recycle moon urge solid ridge",
    "eth": {
      "pri": "0xd19b0fdf070713bc94c2b262106a044c47bae4c98d62a74ada16ec45c6fb08f8",
      "addr": "0xd0128a7052cfdd90222577f2ae3afe0fee84c132"
    },
    "btc": {
      "pri": "L2X2BC6pMxdZbjyswYfAbRbVCsgG1niXjxU8Gn48gzsa2AyufqW6",
      "addr": "12u11ftWGY8PBhfZ4sS2CSj5LfX3iwVmfw"
    },
    "sol": {
      "pri": "5GYBzPf91MDDocdqqViTUbaCxpXbuhef7DwWWdwE7txuVfPyZ2p7cRauChzsqFz2tAKELnyf3L4XCznbEiwSMr4p",
      "addr": "7jQy8eezLqgNwGL37JHkhAG7oTHME4GFTL3pebW8whUt"
    }
  },
  {
    "mn": "beef weapon purse wink chase runway case general library junior cinnamon hamster",
    "eth": {
      "pri": "0xb8b43bb8b1852423ce08c20cb36edfc511f64bdfdabef90b14e6497169e647d5",
      "addr": "0x38cd9dd1e79e32c66b2e0655da754f846cf25b3c"
    },
    "btc": {
      "pri": "KytR2N6vwu3RkQysuM3R3abQCrM71m4XLEH8Ghcd2oReJevcej9N",
      "addr": "1AvC3y5dWBaDUy8ENzG3CqzEhkA6R3Y4hE"
    },
    "sol": {
      "pri": "2W5YX4dHZVYgo1rASEY4nEpHFhbLPtVcF9qTJzMtc5kZ9ubbznRzKwDJ5fnDaTp7bPTPHSM2hxANDD3QhRZNJrU6",
      "addr": "7DTERqNpoUPEtaNdDoLSKtZW2DDN7Sdv7wfUCTz1vSjG"
    }
  },
  {
    "mn": "sunny style baby sorry pigeon lizard intact frequent giggle around dentist book",
    "eth": {
      "pri": "0xf0c40f094f6fdb1f7a7e5a9e9dc21adae9163aecb392214b4c11e5bcf313ce92",
      "addr": "0xd1060cc732b29e90f0a2658680b993d5d87506f1"
    },
    "btc": {
      "pri": "L4RQHMkrPQp2yXT2Fudaueob5vx5fdKJfuqyACVqFXE62Zx72zcA",
      "addr": "1HVDUuQfCxbFxSBJazebv34uGnxinxBCYo"
    },
    "sol": {
      "pri": "4bKUG2w2dfs7v5waGht6BEyneQCUi6uo6TGSAQtDH6rKJbynBFecdcQuAJBcDiKPJ7phjnPqcwfhESifGarUxQ7T",
      "addr": "FM8VQ1U3XVBwZsFyuP2h9vc5mh4zyngn9spMvkzgdjso"
    }
  },
  {
    "mn": "sail edge giraffe blanket infant clarify hammer champion tuition list deer frequent",
    "eth": {
      "pri": "0xbc0e28fdc932f6219d37d4695998ef394fbedd58e6b8465206a5a3459e574c17",
      "addr": "0x05ae7086cc18a773b0426d0a7e4443ddbd330f70"
    },
    "btc": {
      "pri": "KzbAGKKp4owfv1ZBva1AzsFSfxtyHWzpKFpYY3VcjgAh5gG1txWM",
      "addr": "1PSZLY6RdKUwnVBK1tNeQPhsdVuYSgPHdD"
    },
    "sol": {
      "pri": "pVUooDgxBgUN7HjDSwPFMDgAt1er76HinjW87zkmuzknvjrowyxhqByw1sDfKGQcFwiosX5NkAckG5YsCZikxEU",
      "addr": "CFY9hicVWrrwvxdZLQEGhZ5i2VqNf5CHsaktaMWrssUk"
    }
  },
  {
    "mn": "rescue monkey travel hold citizen rubber critic miracle symptom logic multiply dream",
    "eth": {
      "pri": "0x21898f9ad16226c80d6f4bcf0d36ececcd9aea1cce84742025f04ec21a7c7a69",
      "addr": "0x3125168730d9ec77851b610634d92f89f6f7c8a1"
    },
    "btc": {
      "pri": "L3wkB4ZwiJA7ys61KeVn8KVn4wCvS1Uh3M7SYjB64n8Vk9cipVL6",
      "addr": "1FUT3JeYMKhNd9HZeSjuNa35JLQcvu86qt"
    },
    "sol": {
      "pri": "4M5PzztkaWEWtdcHjz6taQJiRfkucv8xi3bHgaBf2FszB65FSEu38SASigiAoqFdnzTjzpAgj9pXf1doxjsDRr7r",
      "addr": "98z6Ef9pCQ2WDTCNkxYrd89s4HPr7Vm1tPaDx35ofycL"
    }
  },
  {
    "mn": "steel sting company kite mule buffalo veteran bean slice plunge question napkin",
    "eth": {
      "pri": "0x3d1047494f3a3e1e2f67be206e74064580ae39336b81d713737351adb39016cc",
      "addr": "0x06db8494a9baf3da97f7d4145ac82aa686d492fc"
    },
    "btc": {
      "pri": "KyaYo2aE3AvUS2GPp9xfpHXyESiqydhBkAV7eqFsXTUGyAXmS2L9",
      "addr": "12bJF7qhE9GCA51UNZBSBMqREE5Kb8Zyu1"
    },
    "sol": {
      "pri": "4m9KJJAMQ1xtwP5X6p9UPVz1J4ySEqrDC3GnipHyggDYLevWyJRBwfqJ9KDnCUEjKGj1SfkVDLgiFwsmREL1ZXRd",
      "addr": "6LUWcx6CnPqhd84vPawimHBSWUM4U6yuzhMhfG3DAsto"
    }
  }
];
