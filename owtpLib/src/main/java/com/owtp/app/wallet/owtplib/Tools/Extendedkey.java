package com.owtp.app.wallet.owtplib.Tools;

import com.owtp.app.wallet.owtplib.Encrypt.EccSet;
import com.owtp.app.wallet.owtplib.Encrypt.HashSet;
import com.owtp.app.wallet.owtplib.Encrypt.HmacSet;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
/**
 *私钥扩展类
 * zhangliang
 * QQ:1179980507
 * tel:18028301898
 * @return
 */
public class Extendedkey {
    // 用于产生根密钥的种子长度
    private int RecommendedSeedLen = 32;
    // 强化子密钥索引号起始值b
    byte[] hStart=new byte[]{(byte) 0x80,0x00,0x00,0x00};
    private BigInteger HardenedKeyStart = new BigInteger(byteArrayToHex(hStart),16);
    // 扩展深度限制
    private int maxUint8 = 1<<8-1;
    public int depth;//      uint8  //深度
    public byte[] parentFP;//   []byte //父密钥指纹
    public int serializes;// uint32 //序列号
    public byte[] chainCode;//  []byte //链码
    public byte[] key;//        []byte //密钥数据
    public boolean isPrivate;//  bool   //当前密钥的私钥标记
    public int curveType;  //uint32 //曲线类型
    public int getDepth() {
        return depth;
    }

    public void setDepth(int depth) {
        this.depth = depth;
    }

    public byte[] getParentFP() {
        return parentFP;
    }

    public void setParentFP(byte[] parentFP) {
        this.parentFP = parentFP;
    }

    public int getSerializes() {
        return serializes;
    }

    public void setSerializes(int serializes) {
        this.serializes = serializes;
    }

    public byte[] getChainCode() {
        return chainCode;
    }

    public void setChainCode(byte[] chainCode) {
        this.chainCode = chainCode;
    }

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public boolean isPrivate() {
        return isPrivate;
    }

    public void setPrivate(boolean aPrivate) {
        isPrivate = aPrivate;
    }

    public int getCurveType() {
        return curveType;
    }

    public void setCurveType(int curveType) {
        this.curveType = curveType;
    }

    public Extendedkey(int depth, byte[] parentFP, int serializes, byte[] chainCode, byte[] key, boolean isPrivate, int curveType)
    {
        this.depth=depth;
        this.parentFP=parentFP;
        this.serializes=serializes;
        this.chainCode=chainCode;
        this.key=key;
        this.isPrivate=isPrivate;
        this.curveType=curveType;
    }


    public void InitRootKeyFromSeed(String  seed,int curveType)
    {
        curveType= HashSet.HASH_ALG_SHA512;
        byte msg[]= toByte(seed);
        //message length
        int msgLen=msg.length;
        //digest bufff
        byte digest[];
        //digest length
        int digestLen=64;
        //为digest分配空间
        digest=new byte[digestLen];
        //如果想调用sha256算法，需要将hash_set.type设置成0xA0000002(具体可以参考hash_set.java中的说明)
        digest=HashSet.hash(msg,msgLen,digestLen,curveType);

        if(curveType== EccSet.ECC_CURVE_ED25519)
        {
            digest[0]&=248;
            digest[31]&=63;
            digest[31]|=64;
        }
    }
    public byte[] getFP(byte[] key, boolean isPrivate, int typeChoose)  {
        byte[] fingerPrintTemporary;
        byte[] fingerPrint = new byte[4];
        byte[] pubkey;
        if (!isPrivate) {
            fingerPrintTemporary = HashSet.hash(key, key.length, 20,HashSet.HASH_ALG_HASH160);
        } else {
            pubkey= EccSet.EccPointMulBaseG(key, typeChoose);
            fingerPrintTemporary = HashSet.hash(pubkey, pubkey.length, 20,HashSet.HASH_ALG_HASH160);
        }
        fingerPrint[0]=fingerPrintTemporary[0];
        fingerPrint[1]=fingerPrintTemporary[1];
        fingerPrint[2]=fingerPrintTemporary[2];
        fingerPrint[3]=fingerPrintTemporary[3];
        return fingerPrint;
    }

    //GenPrivateChild 通过k扩展子私钥
    public Extendedkey GenPrivateChild(Extendedkey k,int serializes)
    {
        byte i[];
        byte childChainCode[];
        //越过最大深度限制
        if (k.depth == maxUint8) {
            return null;
        }
        //不能从父公钥扩展子私钥
        if(!k.isPrivate)  {
            return null;
        }

        if( new BigInteger(String.valueOf(serializes)).compareTo(HardenedKeyStart)>0) { //强化扩展
            i = getI(k.key, k.chainCode, serializes, k.curveType);
        } else { //普通扩展\\

            byte[]  point = EccSet.EccPointMulBaseG(k.key, k.curveType);
            i = getI(point, k.chainCode, serializes, k.curveType);
        }
        byte[] childKey= getPriChildViaPriParent(getIndexbyte(0,32,i), k.key, k.curveType);
        childChainCode = getIndexbyte(32,i.length,i);
        byte[] parentFP= getFP(k.key, k.isPrivate, k.curveType);
        return new Extendedkey(k.depth+1,parentFP,
                serializes, childChainCode,childKey, true, k.curveType);
    }

    //GenPublicChild 通过k扩展子公钥
    public  Extendedkey GenPublicChild(Extendedkey k,int serializes)
    {
        if (!k.isPrivate) {
            if (new BigInteger(String.valueOf(serializes)).compareTo(HardenedKeyStart)>0 ){ //不能从父公钥强化扩展
                return null;
            }
            byte[] i = getI(k.key, k.chainCode, serializes, k.curveType);
            byte[] childKey= getPubChildViaPubParent(getIndexbyte(0,32,i), k.key, k.curveType);

            byte[] childChainCode = getIndexbyte(i.length/2,i.length,i);
            byte[] parentFP = getFP(k.key, false, k.curveType);
            return new Extendedkey(k.depth+1,parentFP,serializes,childChainCode,childKey, false, k.curveType);

        }
        Extendedkey childPrikey= k.GenPrivateChild(k,serializes);
        byte[] childKey= EccSet.EccPointMulBaseG(childPrikey.key, childPrikey.curveType);
        return new Extendedkey(k.depth+1,childPrikey.parentFP,serializes,childPrikey.chainCode,childKey ,false, k.curveType);
    }


    public byte[] getIndexbyte(int s,int e,byte[] b)
    {
        byte[] bytes=new byte[e-s];

        int j=0;
        for (int i=s;i<e;i++)
        {
            bytes[j]=b[i];
            j++;
        }
        return bytes;
    }
    public byte[] getPubChildViaPubParent(byte[] il,byte[] pubkey, int typeChoose) {
        if (typeChoose == EccSet.ECC_CURVE_ED25519) {
            BigInteger ilNum = new BigInteger(byteArrayToHex(inverse(getIndexbyte(0,28,il))),16);
            BigInteger num8 = new BigInteger(new byte[]{8});
            ilNum=ilNum.multiply(num8);
            byte[] il2 = inverse(ilNum.toByteArray());
            byte[] point= EccSet.EccPointMulBaseGAdd(pubkey, il2, typeChoose);
            return point;
        }
        BigInteger ilNum = new BigInteger(byteArrayToHex(il),16);
        BigInteger curveOrder = new BigInteger(byteArrayToHex(EccSet.EccGetCurveOrder(typeChoose)),16);
        if (ilNum.compareTo(curveOrder) >= 0 || ilNum.signum() == 0) {
            return null;
        }
        byte[] parentPubPoint= EccSet.EccPointDeCompress(pubkey,33,typeChoose);
        byte[] point= EccSet.EccPointMulBaseGAdd(getIndexbyte(1,parentPubPoint.length,parentPubPoint), il, typeChoose);
        point = EccSet.EccPointCompress(point,point.length, typeChoose);
        return point;
    }

    public byte[] getPriChildViaPriParent(byte[] il,byte[] prikey ,int typeChoose) {
        byte[] priChild;
        if (typeChoose == EccSet.ECC_CURVE_ED25519) {
            BigInteger ilNum = new BigInteger(byteArrayToHex(inverse(getIndexbyte(0,32,il))),16);
            BigInteger kpr =  new BigInteger(byteArrayToHex(inverse(prikey)),16);
            BigInteger num8 = new BigInteger(new byte[]{8});
            BigInteger  curveOrder = new BigInteger(byteArrayToHex(EccSet.EccGetCurveOrder(typeChoose)),16);
            ilNum=ilNum.multiply(num8);
            ilNum=ilNum.add(kpr);
            ilNum=ilNum.mod(curveOrder);
            BigInteger check = ilNum;
            if (check.signum() == 0) {
                return null;
            }
            priChild = inverse(check.toByteArray());
        } else {

            BigInteger ilNum = new BigInteger(byteArrayToHex(il), 16);
            BigInteger curveOrder = new BigInteger(byteArrayToHex(EccSet.EccGetCurveOrder(typeChoose)), 16);
            if (ilNum.compareTo(curveOrder) >= 0 || ilNum.signum() == 0) {
                return null;
            }
            BigInteger kpr = new BigInteger(byteArrayToHex(prikey),16);
            ilNum=ilNum.add(kpr);
            ilNum=ilNum.mod(curveOrder);

            if (ilNum.signum() == 0) {
                return null;
            }
            priChild =ilNum.toByteArray();
        }
        return priChild;
    }

    public byte[] getI(byte[] data, byte[] key, int serializes, int typeChoose) {

        String ee=byteArrayToHex(data);
        byte[]tmp =intToByteArray(serializes);
        byte[]m;
        if (data.length == 32) {
            byte[]head ={0};
            m =unitByteArray(head,data);
        }
        m =unitByteArray(data,tmp);

        String edd=byteArrayToHex(m);

        byte[] hmac512 = HmacSet.hmac(key,key.length,m,m.length,64,HmacSet.HMAC_SHA512_ALG);
        return hmac512;
    }
    /**
     * 倒序数组
     */
    public byte[] inverse(byte[] data) {
        byte[] ret={};
        for(int i=0;i<data.length;i++)
        {
            ret[i]=data[data.length-1-i];
        }
        return ret;
    }


    /**
     * byte数组转成String
     */
    public static String byteArrayToHex(byte[] data){
        String ret = "";
        for (byte b : data) {
            String hex = Integer.toHexString(b & 0xFF);
            if(hex.length() < 2){
                hex = "0" + hex;
            }
            ret += hex;

        }
        return ret;
    }

    /**
     * 合并byte数组
     */
    public static byte[] unitByteArray(byte[] byte1,byte[] byte2){
        byte[] unitByte = new byte[byte1.length + byte2.length];
        System.arraycopy(byte1, 0, unitByte, 0, byte1.length);
        System.arraycopy(byte2, 0, unitByte, byte1.length, byte2.length);
        return unitByte;
    }

    /**
     * int到byte[]
     * @param i
     * @return
     */
    public static byte[] intToByteArray(int i) {
        byte[] result = new byte[4];
        //由高位到低位
        result[0] = (byte)((i >> 24) & 0xFF);
        result[1] = (byte)((i >> 16) & 0xFF);
        result[2] = (byte)((i >> 8) & 0xFF);
        result[3] = (byte)(i & 0xFF);
        return result;
    }

    /**
     * byte[]转int
     * @param bytes
     * @return
     */
    public static int byteArrayToInt(byte[] bytes) {
        int value = 0;
        //由高位到低位
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (bytes[i] & 0x000000FF) << shift;//往高位游
        }
        return value;
    }

    /**
     * 对象转btye
     *
     * @param obj
     * @return 转换异常返回 0
     */
    public static byte[] toByte(String str) {

        byte[] srtbyte = null;
        try {
            srtbyte = str.getBytes("UTF-8");//string 转 byte[]
            //  String res = new String(srtbyte, "UTF-8");//byte[] 转 string
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return srtbyte;
    }

}

