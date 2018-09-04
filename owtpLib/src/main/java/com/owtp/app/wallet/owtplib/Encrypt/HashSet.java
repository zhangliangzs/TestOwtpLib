package com.owtp.app.wallet.owtplib.Encrypt;//#define HASH_ALG_SHA256            0xA0000002
//#define HASH_ALG_SHA512            0xA0000003
//#define HASH_ALG_MD4               0xA0000004
//#define HASH_ALG_MD5               0xA0000005
//#define HASH_ALG_RIPEMD160         0xA0000006
//#define HASH_ALG_BLAKE2B           0xA0000007
//#define HASH_ALG_BLAKE2S           0xA0000008
//#define HASH_ALG_SM3               0xA0000009
//#define HASh_ALG_DOUBLE_SHA256     0xA000000A
//#define HASH_ALG_HASH160           0xA000000B
//#define HASH_ALG_KECCAK256         0xA000000

public class HashSet {

    static {
        System.loadLibrary("HashSet");
    }

    public static final int HASH_ALG_SHA256 = 0xA0000002;
    public static final int HASH_ALG_SHA512 = 0xA0000003;
    public static final int HASH_ALG_HASH160 = 0xA000000B;
    public static native byte[] hash(byte[] msg,int msgLen,int digestLen,int type);
}
