package com.owtp.app.wallet.owtplib.Encrypt;// ECC_CURVE_SECP256K1     0xECC00000
//  ECC_CURVE_SECP256R1     0xECC00001
//  ECC_CURVE_PRIMEV1       ECC_CURVE_SECP256R1
//  ECC_CURVE_NIST_P256     ECC_CURVE_SECP256R1
//    0xECC00002
//  ECC_CURVE_ED25519       0xECC00003

public class EccSet {

    static {
           System.loadLibrary("EccSet");
    }


    public static final int ECC_CURVE_SECP256K1 = 0xECC00000;
    public static final int ECC_CURVE_SECP256R1=0xECC00001;
    public static final int ECC_CURVE_SM2_STANDARD = 0xECC00002;
    public static final int ECC_CURVE_ED25519=0xECC00003;

    //私钥生成公钥 API
    public static native byte[] EccGenPubkey(byte[] prikey,int type);
    //签名
    public static native byte[] EccSign(byte[] prikey,byte[]ID,int IDlen,byte[]message, int messageLen,int type);
    //验签
    public static native byte EccVerify(byte[] pubkey,byte[]ID,int IDlen,byte[]message,int messageLen,byte[]sig, int type);
    //加密(密文长度 = 明文长度 + 97 (Byte).这里不再返回密文长度，如果需要可以外部计算)
    public static native byte[] EccEnc(byte[] pubkey,byte[]plain,int plainLen,int type);
    //解密(明文长度 = 密文长度 - 97 (Byte).这里不再返回明文长度，如果需要可以外部计算)
    public static native byte[] EccDec(byte[] prikey,byte[]cipher,int cipherLen,int type);
    //密钥协商发起方 step1，返回的数组中前32字节是临时私钥，后64字节是临时公钥
    public static native byte[] EccKeyExchangeInitiatorStep1(int type);
    //密钥协商发起方 step2(输出结果为Sout和key)
    public static native byte[] EccKeyExchangeInitiatorStep2(byte[]IDinitiator,int IDinitiatorLen,byte[]IDresponder,int IDresponderLen,
                                                             byte[]priInitiator,byte[]pubInitiator,byte []pubResponder,byte[]tmpPriInitiator,byte[]tmpPubInitiator,byte[]tmpPubResponder,byte[]Sin,
                                                             int keyLen,int type);
    //密钥协商响应方 step1
    public static native byte[] EccKeyExchangeResponderStep1(byte[]IDinitiator,int IDinitiatorLen,byte[]IDresponder,
                                                             int IDresponderLen,byte[]priResponder,byte[]pubResponder,byte []pubInitiator,byte[]tmpPubResponder,
                                                             byte[]tmpPubInitiator,int keyLen,int type);
    //密钥协商响应方 step2(true:协商成功；false：协商失败)
    public static native byte EccKeyExchangeResponderStep2(byte[]Sinitiator, byte[]Sresponder, int type);
    //点乘和点加的混合运算（先点乘，再点加）
    public static native byte[]EccPointMulAdd(byte[]Inputpoint1,byte[]InputPoint2,byte[]k,int type);
    //点乘和点加的混合运算（基点G）
    public static native byte[]EccPointMulBaseGAdd(byte[]InputPoint,byte[]k,int type);
    //点乘（基点G）
    public static native byte[]EccPointMulBaseG(byte[]scalar,  int type);
    //点的压缩
    public static native byte[]EccPointCompress(byte[]point,int pointLen,int type);
    //点的解压缩
    public static native byte[]EccPointDeCompress(byte[]x,int xLen,int type);
    //获取曲线的阶
    public static native byte[]EccGetCurveOrder(int type);


}

