"use strict";

var expect = require('chai').expect;
var Encryptor = require('../index');
var config = {
  passphrase: new Buffer('so long and thanks for all the fish', "utf8"),
  privKeyPath: './keys/privatekey.txt',
  pubKeyPath: './keys/publickey.txt'
};

var partial_config = {
  pubKeyPath: './keys/publickey.txt'
};

var payment_config = {
  passphrase: new Buffer('this is for the payment service', "utf8"),
  privKeyPath: './keys/payment_private.txt',
  pubKeyPath: './keys/payment_public.txt'
};

var partial_payment_config = {
  pubKeyPath: './keys/payment_public.txt'
};

var msg = `-----BEGIN PGP MESSAGE-----
Version: Keybase OpenPGP v2.0.50
Comment: https://keybase.io/crypto

yMAXAnicO8LLzMDFOPfTypkJGn+1GU/LlzKEHao6EpKRWaxQnpmTo5CUqpCoUJyZ
npeaopBbnH5oDgsDIxcDGysTSBkDF6cATK/1Leb/CXKdwaImxnt0N53btImboYM5
JVGhOmXFtCmvI3fF72PvVcuR4Hldr9px5hL7mf/lfxQX7ZzY0PlL22/u7s6Gpi11
MuJxbOdXdtatXKp5s9/s+yR+md9xgdPP85yYo/PV75bC3R2msVMebMveqsvEyx/z
NkCrYdtVy7dLFF4+bo/Te74oS94VAIgNWbk=
=gEI+
-----END PGP MESSAGE-----`;


function newEncryptor(cfg) {
  return new Encryptor(cfg);
};

describe("Encryptor", function () {

  it("should initialize the encryptor", function () {
    var encryptor = new Encryptor(config);
    expect(encryptor).to.be.ok;
    expect(encryptor).to.be.an.instanceof(Encryptor);
  });

  it('should go through the flow', (done) => {
    var payment = newEncryptor(payment_config);
    var payment_partial = newEncryptor(partial_payment_config);
    var basic = newEncryptor(config);
    var basic_partial = newEncryptor(partial_config);
    var payment_km;
    var basic_km;
    var encryptedMsg;
    var decryptedMsg;

    payment.loadKeyManager().then((km) => {
      return payment.unlockKeyManager(km);
    }).then((km) => {
      payment_km = km;
      return basic_partial.loadKeyManager();
    }).then((km) => {
      var params = {
        msg: "This will be a signed and encrypted msg",
        encrypt_for: km,
        sign_with: payment_km
      };
      return payment.encrypt(params);
    }).then((encrypted) => {
      console.log("Encrypted: ", encrypted);
      encryptedMsg = encrypted;
      return basic.loadKeyManager();
    }).then((km) => {
      return basic.unlockKeyManager(km);
    }).then((km) => {
      basic_km = km;
      return payment_partial.loadKeyManager();
    }).then((km) => {
      return basic.decrypt(encryptedMsg, basic_km, km);
    }).then((decrypted) => {
      console.log("Decrypted: ", decrypted);
      expect(decrypted).to.equal("This will be a signed and encrypted msg");
      done();
    }).catch((err) => {
      console.log(err);
      throw Error(err);
      done();
    });
  });

  it('should sign', (done) => {
    var payment = newEncryptor(payment_config);
    var payment_km;

    payment.loadKeyManager().then((km) => {
      return payment.unlockKeyManager(km);
    }).then((km) => {
      payment_km = km;
      var params = {
        msg: "This will be a signed msg",
        sign_with: payment_km
      }
      return payment.sign(params);
    }).then((signed) => {
      console.log(signed);
      expect(signed).to.be.ok
      done();
    }).catch((err) => {
      throw err;
      done();
    });
  });

  it('should verify', (done) => {
    var basic = newEncryptor(config);
    var payment = newEncryptor(partial_payment_config);
    var basic_km;

    basic.loadKeyManager().then((km) => {
      return basic.unlockKeyManager(km);
    }).then((km) => {
      basic_km = km;
      return payment.loadKeyManager();
    }).then((km) => {
      return basic.decrypt(msg, basic_km, km);
    }).then((decrypted) => {
      console.log(decrypted);
      expect(decrypted).to.equal("This will be a signed msg");
      done();
    }).catch((err) => {
      throw err;
      done();
    });

  });

  it('should encrypt', (done) => {
    var basic = newEncryptor(config);
    var payment = newEncryptor(payment_config);
    var payment_km;
    var basic_km;

    payment.loadKeyManager().then((km) => {
      return payment.unlockKeyManager(km);
    }).then((km) => {
      payment_km = km;
      return basic.loadKeyManager();
    }).then((km) => {
      return basic.unlockKeyManager(km);
    }).then((km) => {
      basic_km = km;
      var params = {
        msg: "This will be an encrypted msg",
        encrypt_for: payment_km,
        sign_with: basic_km
      }
      return basic.encrypt(params);
    }).then((encrypted) => {
      console.log(encrypted);
      expect(encrypted).to.be.ok;
      done();
    }).catch((err) => {
      throw err;
      done();
    });
  });

  it('should decrypt', (done) => {
    var basic = newEncryptor(config);
    var payment = newEncryptor(payment_config);
    var payment_km;
    var basic_km;

    payment.loadKeyManager().then((km) => {
      return payment.unlockKeyManager(km);
    }).then((km) => {
      payment_km = km;
      return basic.loadKeyManager();
    }).then((km) => {
      return basic.unlockKeyManager(km);
    }).then((km) => {
      basic_km = km;
      var params = {
        msg: "This will be an encrypted msg",
        encrypt_for: payment_km,
        sign_with: basic_km
      }
      return basic.encrypt(params);
    }).then((encrypted) => {
      return payment.decrypt(encrypted, payment_km, basic_km);
    }).then((decrypted) => {
      console.log(decrypted);
      expect(decrypted).to.equal("This will be an encrypted msg");
      done();
    }).catch((err) => {
      throw err;
      done();
    });
  })

});