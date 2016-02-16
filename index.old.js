"use strict";

var kbpgp = require("kbpgp");
var mkDeferred = require("./lib/deferred");
var master_passphrase = new Buffer('so long and thanks for all the fish', "utf8");

var Encrypt = function (options) {
  this.userId = options.userId
  this.kbpgp = kbpgp;
}

Encrypt.prototype.encrypt = function(jsonString, encWith, encFor) {
  var self = this;
  var def = mkDeferred();
  
  this.generateEccKeypairs().then(function (keypair) {
    return self.signKeypair(keypair);
  }).then(function (keypair) {
    return self.exportPublic(keypair)
    .then(function (publicKey) {
      console.log(publicKey);
      return self.exportPrivate(keypair, {});
    }).then(function (privKey) {
      console.log(privKey);
      return self.encryptData(keypair, jsonString);
    }).then(function (encString) {
      console.log(encString);
      return self.toBase64(encString);
    }).then(function (b64String) {
      def.resolve(b64String);
    }).catch(function (err) {
      def.reject({ err: err.message });  
    });
  });

  return def.getPromise();
};

Encrypt.prototype.generateEccKeypairs = function() {
  var def = mkDeferred();
  this.kbpgp.KeyManager.generate_ecc({"userid": "ziyad parekh"}, function(err, keypair) {
    if (err) {
      def.reject(new Error("Error generating ecc keypair"))
    } else {
      def.resolve(keypair);
    }
  });
  return def.getPromise();
};

Encrypt.prototype.signKeypair = function(keypair) {
  var def = mkDeferred();
  keypair.sign({}, function (err) {
    if (err) {
      def.reject(new Error("Error signing keypair"));
    } else {
      def.resolve(keypair);
    }
  });
  return def.getPromise();
};

Encrypt.prototype.exportPrivate = function(keypair, secret) {
  var def = mkDeferred();
  keypair.export_pgp_private(secret, function (err, privKey) {
    if (err) {
      def.reject(new Error("Error exporting private key"));
    } else {
      def.resolve(privKey);
    }
  });
  return def.getPromise();
};

Encrypt.prototype.exportPublic = function(keypair) {
  var def = mkDeferred();
  keypair.export_pgp_public({}, function (err, publicKey) {
    if (err) {
      def.reject(new Error("Error exporting public key"));
    } else {
      def.resolve(publicKey);
    }
  });
  return def.getPromise();
};

Encrypt.prototype.encryptData = function(keypair, payload) {
  var def = mkDeferred();
  
  // For testing purposes
  var params = {
    msg: "this will be encrypted with credit card data",
    sign_with: keypair
  };

  this.kbpgp.box(params, function (err, result_string, result_buffer) {
    if (err) {
      def.reject(new Error("Error encrypting data ", params));
    } else {
      def.resolve(result_string);
    }
  });
  return def.getPromise();
};

Encrypt.prototype.toBase64 = function(encString) {
  return new Buffer(encString).toString('base64');
};

var enc = new Encrypt({ userid : "Ziyad Parekh <ziyad.parekh@gmail.com>" });

var json = { "msg": "this will be encrypted with credit card data" };
var jsonString = JSON.stringify(json);

enc.encrypt(jsonString).then(function (b64String) {
  console.log(b64String);
}).catch(function (err) {
  console.log(err);
});

