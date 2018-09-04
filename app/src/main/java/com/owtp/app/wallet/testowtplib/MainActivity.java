package com.owtp.app.wallet.testowtplib;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.owtp.app.wallet.owtplib.Encrypt.EccSet;
import com.owtp.app.wallet.owtplib.Tools.Extendedkey;
import com.owtp.app.wallet.owtplib.Tools.KeyUtil;



public class MainActivity extends AppCompatActivity {
    public byte[] rootPri ={(byte) 0x9e, (byte)0xa1, (byte)0x9e, 0x6e, (byte)0xc2, 0x59, (byte)0xf7, (byte)0x85, 0x4e, (byte)0xe4, 0x1b, 0x53, 0x07, (byte)0xcf, (byte)0xc4, (byte)0xb8, (byte)0xf4, 0x47, 0x75, 0x34, 0x20, 0x5e, (byte)0xc9, (byte)0x83, (byte)0xc4,(byte) 0xd3, (byte)0xa9, (byte)0xb5, 0x6c, 0x0b, 0x27, 0x0c};
    public byte[] rootChainCode={(byte)0xab, (byte)0xc9, (byte)0xcc, 0x46, (byte)0xa8, 0x16, 0x6d, (byte)0x81, 0x55,(byte) 0xac, 0x1e, (byte)0xd1, 0x2b, (byte)0xe4, 0x11,(byte) 0xcd, 0x21, 0x3a, 0x3e, 0x28,(byte) 0xe4,(byte) 0xef, 0x46, 0x46,(byte) 0xfe, 0x03, (byte)0xd7, 0x00, 0x2f, (byte)0xef, 0x15, 0x2c};
    public byte[] rootParentFP={0, 0, 0, 0};
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView action_text=findViewById(R.id.action_text);
        String seedContent= KeyUtil.getSeedWordStr(this);
        action_text.setText(seedContent);
        test();
    }

    public void test()
    {
        Extendedkey rooPriKey = new Extendedkey(0, rootParentFP, 0,rootChainCode,rootPri, true, EccSet.ECC_CURVE_SECP256K1);

        Log.e("++++++","JNIUTIL");


        Log.e("父私钥 -----> 普通子私钥","JNIUTIL");
        Log.e("root private key data:","JNIUTIL");
        Log.e("key:"+rooPriKey.byteArrayToHex(rooPriKey.key),"JNIUTIL");
        Log.e("chaincode:"+rooPriKey.byteArrayToHex(rooPriKey.chainCode),"JNIUTIL");
        Log.e("parent FP:"+rooPriKey.byteArrayToHex(rooPriKey.parentFP),"JNIUTIL");
        Log.e("dpth:"+rooPriKey.depth+"","JNIUTIL");
        Log.e("serializes"+rooPriKey.serializes+"","JNIUTIL");
        Log.e("private flag:"+rooPriKey.isPrivate+"","JNIUTIL");
        Log.e("++++++++++","JNIUTIL");
        int serialize=0;


        String expectChildPri = "f938a2e7fef45315b9b0c31b4db08e23a84b362e71876e7fc1880b2ea94e38f1";
        String  expectChildChainCode = "a9e25b8ef131d1180292e8b7ef967347004ed436abf02ea14929325952f72809";
        String expectChildParentFP = "fb080f46";
        int expectChildDpth = 1;
        int expectChildSerialize = serialize;
        boolean expectChildPriFlag = true;
        Extendedkey childPriKey= rooPriKey.GenPrivateChild(rooPriKey,serialize);
        //Extendedkey childPriKeyc= childPriKey.GenPrivateChild(childPriKey,serialize);

        Log.e("child private key data:","JNIUTIL");
        Log.e("key:"+childPriKey.byteArrayToHex(childPriKey.key),"JNIUTIL");
        Log.e("chaincode:"+childPriKey.byteArrayToHex(childPriKey.chainCode),"JNIUTIL");
        Log.e("parent FP:"+childPriKey.byteArrayToHex(childPriKey.parentFP),"JNIUTIL");
        Log.e("dpth:"+ childPriKey.depth+"","JNIUTIL");
        Log.e("serializes"+ childPriKey.serializes+"","JNIUTIL");
        Log.e("private flag:"+ childPriKey.isPrivate+"","JNIUTIL");
        Log.e("++++++","JNIUTIL");

    }
}
