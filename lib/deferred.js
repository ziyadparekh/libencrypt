'use strict';

var Q = require('q');

Q.makePromise.prototype.always = function finMask () {
    this.fin.apply(this, arguments);
    return this;
};

Q.makePromise.prototype.done = Q.defer.prototype.done = function thenMask () {
    this.then.apply(this, arguments);
    return this;
};

Q.makePromise.prototype.getPromise = Q.defer.prototype.getPromise = function finMask () {
    return this.promise;
};

function getPromise () {
    var prom = this.promise;
    prom.getPromise = getPromise;
    return prom;
}

function mkDeferred () {
    return Q.defer();
}

mkDeferred.when = function () {
    var args = [].slice.call(arguments);
    if (args.length > 1) {
        return Q.all(args);
    }
    return Q.when(args[0]);
};
mkDeferred.all = Q.all;

module.exports = mkDeferred;