var Bitcoin = require('bitcoinjs-lib');
var Crypto = require('crypto');
var buffer = require('buffer').Buffer;
var bencode = require('bencode');
var request = require('request');
var wif = require('wif');
var BigInteger = require('bigi');
var bs58check = require('bs58check')


var twister_network = Bitcoin.networks.bitcoin;

twister_network.messagePrefix= '\x18twister Signed Message:\n';
twister_network.pubKeyHash= 0x00;

var username = "pampalulu";
var pubkey ="032d48cdb8404165425a35ad60744263caf0c8d405bb97152dea4fd867744e1627";
var privkey = "L12kz6tabDN6VmPes1rfEpiznztPF6vgkHp8UZVBgZadxzebHhAp"

var rpc = function(method,payload,callback){

      request({

          uri: "http://user:pwd@127.0.0.1:28332",
          method: "POST",
          timeout: 2000,
          followRedirect: true,
          maxRedirects: 10,
          body: '{"jsonrpc": "2.0", "method": "'+method+'", "params": '+payload+', "id": 0}'

      }, callback)
      
}

var buffer = bs58check.decode(privkey)

var decoded = wif.decodeRaw(0x80, buffer)
var d = BigInteger.fromBuffer(decoded.d)

keyPair = new Bitcoin.ECPair(d, null);

console.log("\nTho following public keys should be equal:")
console.log(new Buffer(pubkey, 'hex'))
console.log(keyPair.getPublicKeyBuffer());









//////////////////////////////////////////////
/// STEP ONE: REPRODUCE SIGNATURE FROM DHT ///
//////////////////////////////////////////////

var postFromDht = {
        "p" : {
            "height" : 84886,
            "seq" : 2,
            "target" : {
                "n" : "pampalulu",
                "r" : "status",
                "t" : "s"
            },
            "time" : 1430403206,
            "v" : {
                "sig_userpost" : "203f5014737b922603e805f01141ee60ce8371b4d766750e9db77803c01dae25e2a29c75a44f95034f50a2f9b4c816cf91cc5fe10e581f0b489cbfba81c0d2a6aa",
                "userpost" : {
                    "height" : 84886,
                    "k" : 2,
                    "lastk" : 1,
                    "n" : "pampalulu",
                    "rt" : {
                        "height" : 75477,
                        "k" : 34,
                        "lastk" : 33,
                        "msg" : "@chinanet @mfreitas @tasty @m0dark  I can't find duplicate posts. Maybe because i can't read chinese. Do you have an english example?",
                        "n" : "tschaul",
                        "reply" : {
                            "k" : 8122,
                            "n" : "chinanet"
                        },
                        "time" : 1424700736
                    },
                    "sig_rt" : "2052eed3e98df9ab166a2abf1e6e3b32a61483de97d91e9ee3a35b955c1ae06f1be6e88c80e9f9212e7604f3bea6d13cc4d231478b23f3fcba23d7cca6ea1f5c3f",
                    "time" : 1430403206
                }
            }
        },
        "sig_p" : "20e8a1106528e4f2f93b8ddae79da01edd8c25e41bcff0e3474cb1aa7dccae350d6d581ccb6853a6d099fbdc6d1a9ca1b10953109244e9183ab8feed174fcf3242",
        "sig_user" : "pampalulu"
    };




var signature = JSON.parse(JSON.stringify(postFromDht.sig_p));

var message = JSON.parse(JSON.stringify(postFromDht.p));

if ("v" in message && (typeof message.v)=="object"){ 
    if("sig_userpost" in message.v) {
        message.v.sig_userpost = new Buffer(message.v.sig_userpost, 'hex');
    }
    if ("userpost" in message.v) { 
        if ("sig_rt" in message.v.userpost) {
            message.v.userpost.sig_rt = new Buffer(message.v.userpost.sig_rt, 'hex');
        }
    }
}

if ("sig_rt" in message) {
    message.sig_rt = new Buffer(message.sig_rt, 'hex');
}

message = bencode.encode(message);
signature = new Buffer(signature, 'hex');

var verifed = Bitcoin.message.verify(keyPair, signature, message, twister_network);

console.log("\n message could be verified: ",verifed);

var retVal = Bitcoin.message.sign(keyPair,message ,twister_network);


console.log("\nTho following signatures should be equal:")
console.log(retVal);
console.log(signature);
