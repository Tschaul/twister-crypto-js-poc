var Bitcoin = require('bitcoinjs-lib');
var Crypto = require('crypto');
var buffer = require('buffer').Buffer;
var bencode = require('bencode');
var request = require('request');
var wif = require('wif');
var BigInteger = require('bigi');
var bs58check = require('bs58check');

var twister_network = Bitcoin.networks.bitcoin;

twister_network.messagePrefix= '\x18twister Signed Message:\n';

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


///////////////////////////////////////////////////
/// STEP ONE: RECOVER KEY PAIR FROM DUMP STRING ///
//////////////////////////////////////////////////

keyPair = new Bitcoin.ECPair.fromWIF(privkey,twister_network);


console.log("\nTho following public keys should be equal:")
console.log(new Buffer(pubkey, 'hex'))
console.log(keyPair.getPublicKeyBuffer());



///////////////////////////////////////////
/// STEP TWO: VERIFY SIGNATURE FROM DHT ///
///////////////////////////////////////////

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


// Preprocess message

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


// Verify signature

var verifed = Bitcoin.message.verify(keyPair.getAddress(), signature, message, twister_network);

console.log("\n message signature could be verified: ",verifed);


////////////////////////////////
/// STEP THREE: SIGN MESSAGE ///
////////////////////////////////

var retVal = Bitcoin.message.sign(keyPair,message ,twister_network);

var verifed = Bitcoin.message.verify(keyPair.getAddress(), retVal, message, twister_network);

console.log("\n self generated signature could be verified: ",verifed);


///////////////////////////////////
/// STEP THREE: DECRYPT MESSAGE ///
///////////////////////////////////

var encryptedPost = {
        "sig_userpost" : "20ab1898d8402f6afaeff8d3ee4e5c7462380e1364fb46a6197f24c40bada6e7c0f1e6773e79328cc961da206a5d6032c99699eeebf20a763949980c09e5c3352d",
        "userpost" : {
            "dm" : {
                "body" : "a9bed4f416c67d1280582e95ac3082f85432de738d9d58363c14ea20a2b55cc2",
                "key" : "0310e6e3315f03f9be1d486911d9c8ea76f42df5c8723d1976fcdf2bf372b84c97",
                "mac" : "b95028e067070ac69e38ad8d9a8c4fb79602127dc92b1bf3b3b7e8723df502378577713844eebe81d3e8e1a899354f79e5fcc41a005c55751bab2711f9b14e2e",
                "orig" : 30
            },
            "height" : 106793,
            "k" : 49,
            "n" : "tschaul",
            "time" : 1444577982
        }
    };
// retrvied by ./twister-core/twisterd getposts 1 '[{"username":"tschaul"}]' 2 2

var sec_key = encryptedPost.userpost.dm.key;
var sec_body = encryptedPost.userpost.dm.body;
var sec_mac = encryptedPost.userpost.dm.mac;
var sec_orig = encryptedPost.userpost.dm.orig;

var testvector = {
    "secret" : "KxQfV51HeY7dsML7jZonw1KxoEWrQ4f93QaQua2RZFNHc4d1VpkL",
    "sec" : {
        "ecies_key_derivation" : "910d1b7dff1ce8373af697b0d0586a8f0934143127fec00d502e6fbbd86b8a02",
        "aes_key" : "fba95549c948b84fb6e338626eaa6e2db7c963533b87d2da65e7b751413e055f3a599f8541aff2e2134508de8ca207be16890fb35e520b90d85f37bc1027da56",
        "key" : "0337cf4c9db7e37943fab38c5e700c9c96c33a14bbe493f2bf3f49d8d9f5d7ef99",
        "mac" : "811fcddf475b9aecf6f6cc2930024372dfad48ac731e347ac7fc0670ba51404fd39df704b7a32b4b69a05e781e58f88fd24cee111eba2bff2e8cb6b40de037f1",
        "orig" : 43,
        "body" : "2a1d32be3c58f869c92ef3cb784d0439b65892929f43b2995d26a391f3e1baaf5ded64662d80a1d43babeeab5eb93649"
    }
}

var sec_key = testvector.sec.key;
var sec_body = testvector.sec.body;
var sec_mac = testvector.sec.mac;
var sec_orig = testvector.sec.orig;


keyPair = new Bitcoin.ECPair.fromWIF(testvector.secret,twister_network);

if (!Buffer.isBuffer(sec_key)) {
    sec_key = new Buffer(sec_key, "hex");
}
if (!Buffer.isBuffer(sec_body)) {
    sec_body = new Buffer(sec_body, "hex");
}
if (!Buffer.isBuffer(sec_mac)) {
    sec_mac = new Buffer(sec_mac, "hex");
}
var pubkey = Bitcoin.ECPair.fromPublicKeyBuffer(sec_key)
var secret = pubkey.Q.multiply(keyPair.d).getEncoded().slice(1,33)


var hash_secret = Crypto.createHash('sha512').update(secret).digest()
var aes_key = hash_secret.slice(0,32)
var hmac_key = hash_secret.slice(32,64)

var hmac=Crypto.createHmac("sha512",hmac_key)
hmac.update(sec_body)
var hmac_val = hmac.digest()

console.log("\n the following hashes should be equal")
console.log(hmac_val)
console.log(sec_mac)


var decrypter = Crypto.createDecipheriv("aes-256-cbc",aes_key,new Buffer(16))
var out = []
out.push(decrypter.update(sec_body))
out.push(decrypter.final())
var decrypted = Buffer.concat(out).slice(0,sec_orig)
//console.log(decrypted);