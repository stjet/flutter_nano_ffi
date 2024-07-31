import 'dart:typed_data';

import 'package:flutter_nano_ffi/src/ffi/ed25519_blake2b.dart';
import 'package:flutter_nano_ffi/src/util.dart';
import 'package:flutter_nano_ffi/src/account/account_util.dart';
import 'package:flutter_nano_ffi/src/blocks/state_block.dart';
import 'package:flutter_nano_ffi/src/keys/keys.dart';

class NanoSignatures {
  static String signBlock(String hash, String privKey) {
    return NanoHelpers.byteToHex(Ed25519Blake2b.signMessage(
        NanoHelpers.hexToBytes(hash), NanoHelpers.hexToBytes(privKey))!);
  }

  static bool validateSig(String hash, Uint8List pubKey, Uint8List signature) {
    return Ed25519Blake2b.verifySignature(
        NanoHelpers.hexToBytes(hash), pubKey, signature);
  }

  static String signMessage(int accountType, String message, String privKey) {
    final message_block_hash = NanoBlocks.generateMessageBlockHash(
      accountType,
      NanoAccounts.createAccount(
          accountType, NanoKeys.createPublicKey(privKey)),
      message,
    );
    return NanoHelpers.byteToHex(Ed25519Blake2b.signMessage(
        NanoHelpers.hexToBytes(message_block_hash),
        NanoHelpers.hexToBytes(privKey))!);
  }

  static bool validateMessageSig(
      int accountType, String message, Uint8List pubKey, Uint8List signature) {
    final message_block_hash = NanoBlocks.generateMessageBlockHash(
      accountType,
      NanoAccounts.createAccount(accountType, NanoHelpers.byteToHex(pubKey)),
      message,
    );
    return validateSig(
      message_block_hash,
      pubKey,
      signature,
    );
  }
}
