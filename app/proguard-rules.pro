# Necessário para o build release (minifyEnabled true):
# o nativo chama estes métodos pelo NOME (GetMethodID) e o Java chama os native pelo símbolo JNI.
-keepclasseswithmembernames class * {
    native <methods>;
}
-keep class com.exemplo.scanner.MemoryScannerService {
    public void onScanProgress(int);
    public void onScanBatch(long[], byte[][]);
    public void onScanCount(int);
    public void onScanComplete(int, boolean);
    public void onPointerBatch(long[], int[]);
    public void onPointerComplete(int);
    native <methods>;
}
-keep class com.exemplo.scanner.MemoryScanner { *; }
