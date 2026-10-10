package com.exemplo.scanner;

import java.lang.ref.WeakReference;

/**
 * Singleton que guarda o callback (Service) por referência FRACA, para não vazar o
 * Service depois do onDestroy. (A versão anterior dizia "fraca" mas guardava forte.)
 */
public class MemoryScanner {
    private static MemoryScanner instance;
    private WeakReference<Object> callback;

    private MemoryScanner() {}

    public static synchronized MemoryScanner getInstance() {
        if (instance == null) {
            instance = new MemoryScanner();
        }
        return instance;
    }

    public synchronized void setCallback(Object callback) {
        this.callback = (callback == null) ? null : new WeakReference<>(callback);
    }

    public synchronized Object getCallback() {
        return (callback == null) ? null : callback.get();
    }

    public synchronized void clearCallback() {
        callback = null;
    }
}
