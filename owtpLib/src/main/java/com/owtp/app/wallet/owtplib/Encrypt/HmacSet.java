package com.owtp.app.wallet.owtplib.Encrypt;

//#define  HMAC_SHA256_ALG        0x50505050
//#define  HMAC_SHA512_ALG        0x50505051
//#define  HMAC_SM3_ALG           0x50505052
/*
 @paramter[in]K,the pointer points to key
 @paramer[in]Klen,the byte length of K
 @parameter[in]M,the pointer points to message
 @paramter[in]Mlen,the byte length of M
 @paramter[in]outlen,the byte length of output.sha256:outlen=32; sha512:outlen=64;sm3:outlen=32
 @paramter[in]type,the hash algorithm flag.0x50505050:sha256;0x50505051:sha512;0x50505052:sm3
 @return:Hmac operation result.the space size is outlen
*/
public class HmacSet {
    static {
        System.loadLibrary("HmacSet");
    }
    public static final int HMAC_SHA256_ALG = 0x50505050;
    public static final int HMAC_SHA512_ALG = 0x50505051;
    public static final int HMAC_SM3_ALG = 0x50505052;
    public static native byte[] hmac (byte[] K,int Klen,byte[]M,int Mlen,int outlen, int type);
}
