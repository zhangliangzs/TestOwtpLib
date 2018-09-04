package com.owtp.app.wallet.testowtplib;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.support.multidex.MultiDexApplication;
import android.text.ClipboardManager;
import android.util.Log;

import java.util.Timer;
import java.util.TimerTask;

public class AppContext extends MultiDexApplication {
    private static AppContext app;
    private static Boolean deBugMode = true;

    public static AppContext getInstance() {
        return app;
    }


    @Override
    public void onCreate() {
        super.onCreate();

    }
}
