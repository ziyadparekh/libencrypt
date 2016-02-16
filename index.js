"use strict";

var fs = require('fs');
var mkDeferred = require("./lib/deferred");
var kbpgp = require("kbpgp");
var master_passphrase = new Buffer('so long and thanks for all the fish', "utf8");

class Encryptor {
  constructor(args) {
    this.kbpgp = kbpgp;

    this.privKeyPath = args.privKeyPath;
    this.pubKeyPath = args.pubKeyPath;
    this.passphrase = args.passphrase;

    if (!this.pubKeyPath || 
        !fs.statSync(this.pubKeyPath)) {
      throw Error("Please provide path to public key file");
    }

    this.publicKey = fs.readFileSync(this.pubKeyPath, 'utf8');
    if (this.privKeyPath) {
      this.privateKey = fs.readFileSync(this.privKeyPath, 'utf8'); 
    }
  }

  encrypt(params) {
    var def = mkDeferred();
    if (!params.msg &&
        !params.encrypt_for &&
        !params.sign_with &&
        !params.encrypt_for instanceof this.kbpgp.KeyManager &&
        !params.sign_with instanceof this.kbpgp.KeyManager) 
    {
      def.reject(new Error("Invalid arguments to encrypt"));
    }
    this.kbpgp.box(params, function (err, result_string, result_buffer) {
      if (err) {
        def.reject(new Error("Unable to encrypt and sign payload"));
      } else {
        def.resolve(result_string);
      }
    });
    return def.getPromise();
  }

  sign(params) {
    var def = mkDeferred();
    if (!params.msg &&
        !params.sign_with &&
        !params.sign_with instanceof this.kbpgp.KeyManager)
    {
      def.reject(new Error("Invalid arguments to sign")); 
    }
    this.kbpgp.box(params, function (err, result_string, result_buffer) {
      if (err) {
        def.reject(new Error("Unable to sign payload"));
      } else {
        def.resolve(result_string);
      }
    });
    return def.getPromise();
  }

  decrypt(msg, decryptor, encryptor) {
    var def = mkDeferred();
    var keyring = new this.kbpgp.keyring.KeyRing;
    if (!decryptor ||
        !encryptor ||
        !decryptor instanceof this.kbpgp.KeyManager ||
        !encryptor instanceof this.kbpgp.KeyManager)
    {
      def.reject(new Error("Decryptor and Encryptor missing"));
    }
    keyring.add_key_manager(decryptor);
    keyring.add_key_manager(encryptor);
    this.kbpgp.unbox({
      keyfetch: keyring,
      armored: msg
    }, function (err, literals){
      if (err) {
        def.reject(new Error("Error decrypting message"));
      } else {
        def.resolve(literals[0].toString());
      }
    });
    return def.getPromise();
  }

  loadKeyManager() {
    var def = mkDeferred();
    this.kbpgp.KeyManager.import_from_armored_pgp({
      armored: this.privateKey || this.publicKey
    }, function (err, keyManager) {
      if (err) {
        def.reject(new Error("Error Loading KeyManager"));
      } else {
        def.resolve(keyManager);
      }
    });
    return def.getPromise();
  }

  unlockKeyManager(keyManager) {
    var def = mkDeferred();
    if (!keyManager.is_pgp_locked) {
      def.resolve(keyManager);
    } else {
      keyManager.unlock_pgp({
        passphrase: this.passphrase
      }, function (err) {
        if (!err) {
          def.resolve(keyManager);
        } else {
          def.reject(new Error("Unable to unlock KeyManager"));
        }
      });
    }
    return def.getPromise();
  }
}

module.exports = Encryptor;