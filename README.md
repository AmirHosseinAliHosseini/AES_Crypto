# AES
C++ AES(Advanced Encryption Standard) implementation  

**This class is very simple to use:**
```c++
...
string key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
string plain = "f69f2445df4f9b17ad2b417be66c3710f69f2445df4f9b17ad2b417be66c3710";
string iv = "23304b7a39f9f3ff067d8d8f9e24ecc7";

deque<Byte> key_, plain_, iv_, out_;
bool res;

AES aes;
aes.convertSTRtoVEC(key, key_);
aes.convertSTRtoVEC(plain, plain_);
aes.convertSTRtoVEC(iv, iv_);


res = aes.EncryptOFB(plain_, key_, iv_, out_);
if (res)
	aes.printHexArray(out_);
    
plain_.clear();
res = aes.DecryptOFB(out_, key_, iv_, plain_);
if (res)
	aes.printHexArray(plain_);
...
```
Or for deque:
```c++
...


deque<Byte> key_ {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
deque<Byte> plain_ {0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
deque<Byte> iv_ {0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff, 0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7} ;

deque<Byte> out_;
bool res;

AES aes;

res = aes.EncryptOFB(plain_, key_, iv_, out_);
if (res)
	aes.printHexArray(out_);
    
plain_.clear();
res = aes.DecryptOFB(out_, key_, iv_, plain_);
if (res)
	aes.printHexArray(plain_);
...
```
ECB, CBC, PCBC, CFB, OFB modes are supported.


You can read more about AES here:

https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf


**Development:**
1. `git clone https://github.com/AmirHosseinAliHosseini/AES_Crypto`
2. `used AES Library in your Project with include files`
