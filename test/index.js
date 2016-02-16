"use strict";

var expect = require('chai').expect;
var Encryptor = require('../index');
var config = {
  passphrase: new Buffer('so long and thanks for all the fish', "utf8"),
  privKeyPath: './keys/privatekey.txt',
  pubKeyPath: './keys/publickey.txt'
};

var payment_config = {
  passphrase: new Buffer('this is for the payment service', "utf8"),
  privKeyPath: './keys/payment_private.txt',
  pubKeyPath: './keys/payment_public.txt'
};


function newEncryptor(cfg) {
  return new Encryptor(cfg);
};

describe("Encryptor", function () {

  it("should initialize the encryptor", function () {
    var encryptor = new Encryptor(config);
    expect(encryptor).to.be.ok;
    expect(encryptor).to.be.an.instanceof(Encryptor);
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
      console.log(err);
      expect(Encryptor).to.throw;
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
      done();
    }).catch((err) => {
      console.log(err);
      expect(Encryptor).to.throw;
      done();
    });
  })

});