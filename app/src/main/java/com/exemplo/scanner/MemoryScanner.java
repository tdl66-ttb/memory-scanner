package com.exemplo.scanner;

/**
 * Classe singleton para gerenciar o callback JNI e evitar vazamentos.
 * Mantém uma referência fraca ao callback para permitir coleta de lixo.
 */
public class MemoryScanner {
    private static MemoryScanner instance;
    private Object callback;

    private MemoryScanner() {}

    public static MemoryScanner getInstance() {
        if (instance == null) {
            instance = new MemoryScanner();
        }
        return instance;
    }

    public void setCallback(Object callback) {
        this.callback = callback;
    }

    public Object getCallback() {
        return callback;
    }

    public void clearCallback() {
        callback = null;
    }
}