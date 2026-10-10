package com.exemplo.scanner;

import android.app.AlertDialog;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.PixelFormat;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.provider.Settings;
import android.text.InputType;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.util.Log;
import android.util.SparseBooleanArray;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class MemoryScannerService extends Service
        implements AdapterView.OnItemClickListener, View.OnClickListener {

    private static final String TAG = "MemScannerService";
    private static final String CHANNEL_ID = "memory_scanner_channel";
    private static final int NOTIFICATION_ID = 1001;

    private static final String PREFS_NAME = "memscanner";
    private static final String PREF_POINTER_STATIC = "pointer_static_only";
    private static final String PREF_MODULE_FILTER  = "module_filter";

    // Tipos
    private static final int TYPE_BYTE   = 0;
    private static final int TYPE_SHORT  = 1;
    private static final int TYPE_INT    = 2;
    private static final int TYPE_LONG   = 3;
    private static final int TYPE_FLOAT  = 4;
    private static final int TYPE_DOUBLE = 5;

    // Condições
    private static final int COND_EXACT   = 0;
    private static final int COND_GREATER = 1;
    private static final int COND_LESS    = 2;
    private static final int COND_RANGE   = 3;

    // Filtros de região
    private static final int RF_NONE      = 0;
    private static final int RF_RW_ONLY   = 1;
    private static final int RF_SKIP_EXEC = 2;
    private static final int RF_ANON_ONLY = 4;

    // Snapshot diff modes
    private static final int DIFF_CHANGED   = 0;
    private static final int DIFF_UNCHANGED = 1;
    private static final int DIFF_INCREASED = 2;
    private static final int DIFF_DECREASED = 3;

    // String encodings
    private static final int STR_UTF8     = 0;
    private static final int STR_UTF16LE  = 1;

    private static final String[] TYPE_NAMES   = {"Byte", "Short", "Int", "Long", "Float", "Double"};
    private static final String[] COND_NAMES   = {"Exato", "Maior", "Menor", "Faixa"};
    private static final String[] REGION_NAMES = {"Tudo", "Rápido(rw)", "Anônimo", "Sem código"};
    private static final int[]    REGION_MASKS = {RF_NONE, RF_RW_ONLY, RF_ANON_ONLY, RF_SKIP_EXEC};

    // Aparelhos Go têm heap Java pequena: 50k itens bastam (o total real continua sendo contado).
    private static final int DISPLAY_LIMIT = 50_000;

    // Tamanho do ponteiro do processo (4 em 32 bits, 8 em 64 bits).
    private static final int PTR_SIZE =
            (Build.VERSION.SDK_INT >= 23 && android.os.Process.is64Bit()) ? 8 : 4;

    // Fila de entrada
    private final Object incomingLock = new Object();
    private final List<String> incomingItems = new ArrayList<>();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean drainScheduled = new AtomicBoolean(false);
    private volatile boolean scanActive = false;
    // true só quando o nativo tem uma lista de resultados que o Next Scan pode refinar
    private volatile boolean refinable = false;
    // false se o onCreate abortou (sem permissão de overlay) — evita sobrescrever o watch.txt
    private boolean ready = false;
    private boolean displayFullNotified = false;

    private final AtomicInteger totalAddresses = new AtomicInteger(0);

    private final Runnable drainTask = new Runnable() {
        @Override public void run() {
            drainScheduled.set(false);
            drainIncomingToUi();
            if (scanActive) scheduleDrain(100);
        }
    };

    private WindowManager wm;
    private View bubbleView, panelView;
    private WindowManager.LayoutParams bubbleParams, panelParams;
    private boolean expanded = false;

    private ListView listView;
    private TextView tvTitle, tvStatus, tvFilterStatus;
    private EditText editValue, editValue2;
    private Button btnType, btnCondition, btnRegion;
    private int currentType = TYPE_INT;
    private int currentCondition = COND_EXACT;
    private int currentRegion = 0;
    private int lastScanType = TYPE_INT;

    private boolean pointerStaticOnly = false;
    private String  moduleFilter = "";

    private long lastPointerTarget = 0;

    // Paths persistentes
    private static class PointerPath {
        String module;
        long   baseOffset;
        int[]  offsets; // offsets após cada deref; pelo menos 1
    }
    private final List<PointerPath> pointerPaths = new ArrayList<>();

    private Button btnScan, btnNext, btnWrite, btnFreeze, btnClear, btnCancel,
                   btnClose, btnCloseService, btnSave, btnLoad, btnVicinity,
                   btnAoB, btnPointer, btnWatchAdd, btnWatchShow, btnFollow,
                   btnString, btnSnapshot, btnModules, btnPaths,
                   btnMarkAll, btnUnmarkAll, btnSameOffset, btnFilterClear;

    private ArrayAdapter<String> adapter;
    private final List<String> displayItems = new ArrayList<>();
    private ProgressBar progressBar;

    // Watch: endereço → isPointer (true = dereferenciar)
    private final Map<Long, Boolean> watchAddrs = new LinkedHashMap<>();

    private static final int OVERLAY_TYPE =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                    : WindowManager.LayoutParams.TYPE_PHONE;

    static {
        System.loadLibrary("memscanner");
    }

    // ==================== Métodos nativos ====================
    public native void    nativeSetWorkDir(String path);
    public native void    nativeSetRegionFilter(int mask);
    public native void    nativeSetPointerStaticFilter(boolean enabled);
    public native void    nativeSetModuleFilter(String pattern);
    public native String[] nativeListModules();
    public native long    nativeGetModuleBase(String moduleName);
    public native String  nativeFindModuleForAddr(long addr);
    public native long    nativeResolvePointerPath(long baseAddr, int[] offsets);
    public native boolean nativeStartScan(long value, long value2, int type, int condition);
    public native boolean nativeNextScan(long value, long value2, int condition);
    public native boolean nativeStringScan(String text, int encoding);
    public native boolean nativeAoBScan(String pattern, int limit);
    public native boolean nativePointerScan(long targetAddr, int maxDepth);
    public native int     nativeSnapshotSave();
    public native int     nativeSnapshotDiff(int mode);
    public native void    nativeSnapshotClear();
    public native void    nativeSetDisplayFull();
    public native void    nativeCancelScan();
    public native void    nativeClearResults();
    public native long[]  nativeGetResults(int maxCount);
    public native int     nativeGetLastScanType();
    public native void    nativeShutdown();
    public native boolean nativeWriteMemory(long address, byte[] data);
    public native void    nativeToggleFreeze(long address, long value, int type, boolean enable);
    public native byte[]  nativeReadMemory(long address, int size);
    public native byte[]  nativeReadRegion(long start, int size);

    // ==================== Ciclo de vida ====================
    @Override
    public void onCreate() {
        super.onCreate();
        wm = (WindowManager) getSystemService(WINDOW_SERVICE);
        createNotificationChannel();
        // Android 8+: startForeground precisa vir logo após startForegroundService().
        startForeground(NOTIFICATION_ID, buildNotification());

        // Sem a permissão de overlay o addView lança BadTokenException (e, com serviço
        // reiniciável, entrava em crash loop).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            Toast.makeText(this, "Permita \"Sobrepor a outros apps\" para usar o scanner",
                    Toast.LENGTH_LONG).show();
            stopSelf();
            return;
        }

        nativeSetWorkDir(getCacheDir().getAbsolutePath());
        nativeSetRegionFilter(REGION_MASKS[currentRegion]);

        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        pointerStaticOnly = prefs.getBoolean(PREF_POINTER_STATIC, false);
        moduleFilter      = prefs.getString(PREF_MODULE_FILTER, "");
        nativeSetPointerStaticFilter(pointerStaticOnly);
        nativeSetModuleFilter(moduleFilter);
        Log.i(TAG, "Prefs: pointerStatic=" + pointerStaticOnly + " module=" + moduleFilter);

        loadWatch();
        createBubble();
        MemoryScanner.getInstance().setCallback(this);
        ready = true;
    }

    // NOT_STICKY: reiniciar sozinho depois de um kill só recriaria o overlay sem estado.
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) { return START_NOT_STICKY; }
    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        super.onDestroy();
        mainHandler.removeCallbacksAndMessages(null);
        MemoryScanner.getInstance().clearCallback();
        if (ready) saveWatch();
        try {
            if (bubbleView != null && bubbleView.getWindowToken() != null)
                wm.removeView(bubbleView);
        } catch (Exception ignored) {}
        try {
            if (panelView != null && panelView.getWindowToken() != null)
                wm.removeView(panelView);
        } catch (Exception ignored) {}
        // Para scan/freeze e SOLTA a referência global do Service no nativo
        // (antes ela ficava presa na instância morta e a nova nunca recebia callbacks).
        nativeShutdown();
        nativeClearResults();
        stopForeground(true);
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "Memory Scanner", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Mantém o serviço em execução");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Memory Scanner")
                .setContentText("Scanner de memória ativo")
                .setSmallIcon(android.R.drawable.ic_menu_search)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();
    }

    // ==================== Bubble ====================
    private void createBubble() {
        TextView bubble = new TextView(this);
        bubble.setText("🔍");
        bubble.setTextSize(30f);
        bubble.setPadding(32, 32, 32, 32);
        bubble.setBackgroundColor(0xCC222222);
        bubble.setTextColor(0xFFFFFFFF);
        bubble.setElevation(10f);
        bubbleView = bubble;

        bubbleParams = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                OVERLAY_TYPE,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
                PixelFormat.TRANSLUCENT);
        bubbleParams.gravity = Gravity.TOP | Gravity.START;
        bubbleParams.x = 0;
        bubbleParams.y = 200;
        wm.addView(bubbleView, bubbleParams);
        makeDraggable(bubbleView, bubbleView, bubbleParams, this::toggleExpanded);
    }

    private void makeDraggable(View touchTarget, View windowRoot,
                               WindowManager.LayoutParams params, Runnable onTap) {
        touchTarget.setOnTouchListener(new View.OnTouchListener() {
            int initialX, initialY;
            float touchX, touchY;
            boolean moved = false;
            final int SLOP = 15;

            @Override
            public boolean onTouch(View view, MotionEvent event) {
                switch (event.getAction()) {
                    case MotionEvent.ACTION_DOWN:
                        initialX = params.x;
                        initialY = params.y;
                        touchX = event.getRawX();
                        touchY = event.getRawY();
                        moved = false;
                        return true;
                    case MotionEvent.ACTION_MOVE:
                        int dx = (int) (event.getRawX() - touchX);
                        int dy = (int) (event.getRawY() - touchY);
                        if (Math.abs(dx) > SLOP || Math.abs(dy) > SLOP) {
                            moved = true;
                            params.x = initialX + dx;
                            params.y = initialY + dy;
                            try {
                                if (windowRoot.getWindowToken() != null)
                                    wm.updateViewLayout(windowRoot, params);
                            } catch (IllegalArgumentException ignored) {}
                        }
                        return true;
                    case MotionEvent.ACTION_UP:
                        if (!moved) onTap.run();
                        return true;
                }
                return false;
            }
        });
    }

    private void toggleExpanded() {
        if (!expanded) {
            if (panelView == null) createPanel();
            wm.removeView(bubbleView);
            wm.addView(panelView, panelParams);
            expanded = true;
        } else {
            wm.removeView(panelView);
            wm.addView(bubbleView, bubbleParams);
            expanded = false;
        }
    }

    private void updateTypeButton() {
        if (btnType != null) btnType.setText("Tipo: " + TYPE_NAMES[currentType]);
    }
    private void updateConditionButton() {
        if (btnCondition != null) {
            btnCondition.setText("Cond: " + COND_NAMES[currentCondition]);
            if (editValue2 != null) {
                editValue2.setVisibility(
                        currentCondition == COND_RANGE ? View.VISIBLE : View.GONE);
            }
        }
    }
    private void updateRegionButton() {
        if (btnRegion != null) btnRegion.setText("Ver: " + REGION_NAMES[currentRegion]);
    }

    private void updateFilterStatus() {
        if (tvFilterStatus == null) return;
        StringBuilder sb = new StringBuilder();
        if (!moduleFilter.isEmpty())    sb.append("📦").append(moduleFilter).append("  ");
        if (currentRegion != 0)         sb.append("🌐").append(REGION_NAMES[currentRegion]).append("  ");
        if (pointerStaticOnly)          sb.append("⭐estáticos  ");
        if (sb.length() == 0) {
            tvFilterStatus.setText("Sem filtros ativos");
            tvFilterStatus.setTextColor(0xFF888888);
        } else {
            tvFilterStatus.setText("Ativo: " + sb.toString().trim());
            tvFilterStatus.setTextColor(0xFF66FF66);
        }
    }

    // ==================== Painel ====================
    private void createPanel() {
        DisplayMetrics dm = getResources().getDisplayMetrics();
        boolean landscape = dm.widthPixels > dm.heightPixels;
        int panelWidth  = (int) (dm.widthPixels * (landscape ? 0.70f : 0.96f));
        int panelHeight = (int) (dm.heightPixels * (landscape ? 0.96f : 0.94f));

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(0xEE222222);
        scroll.setElevation(10f);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(16, 16, 16, 16);

        tvTitle = new TextView(this);
        tvTitle.setTextSize(18f);
        tvTitle.setTextColor(0xFFFFFFFF);
        tvTitle.setPadding(8, 8, 8, 8);
        tvTitle.setText("Memory Scanner");
        root.addView(tvTitle);

        // Drag bar
        LinearLayout dragBar = new LinearLayout(this);
        dragBar.setOrientation(LinearLayout.HORIZONTAL);
        dragBar.setBackgroundColor(0xFF333333);
        dragBar.setClickable(true);
        TextView dragLabel = new TextView(this);
        dragLabel.setText("⇅ Arraste");
        dragLabel.setTextColor(0xFFAAAAAA);
        dragLabel.setPadding(12, 8, 12, 8);
        dragBar.addView(dragLabel,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnCloseService = new Button(this);
        btnCloseService.setText("Fechar");
        btnCloseService.setOnClickListener(v -> stopSelf());
        dragBar.addView(btnCloseService);
        btnClose = new Button(this);
        btnClose.setText("Minim.");
        btnClose.setOnClickListener(this);
        dragBar.addView(btnClose);
        root.addView(dragBar);

        tvStatus = new TextView(this);
        tvStatus.setTextColor(0xFFFFFFFF);
        tvStatus.setPadding(8, 4, 8, 0);
        tvStatus.setText("Pronto");
        root.addView(tvStatus);

        tvFilterStatus = new TextView(this);
        tvFilterStatus.setTextColor(0xFF888888);
        tvFilterStatus.setTextSize(11f);
        tvFilterStatus.setPadding(8, 0, 8, 4);
        root.addView(tvFilterStatus);

        // Valor
        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        row1.setPadding(0, 8, 0, 8);
        TextView lblVal = new TextView(this);
        lblVal.setText("Valor:");
        lblVal.setTextColor(0xFFFFFFFF);
        lblVal.setPadding(0, 0, 8, 0);
        row1.addView(lblVal);
        editValue = new EditText(this);
        editValue.setText("0");
        editValue.setSingleLine(true);
        editValue.setTextColor(0xFFFFFFFF);
        editValue.setHint("0");
        editValue.setHintTextColor(0x88FFFFFF);
        editValue.setInputType(InputType.TYPE_CLASS_NUMBER |
                InputType.TYPE_NUMBER_FLAG_DECIMAL |
                InputType.TYPE_NUMBER_FLAG_SIGNED);
        row1.addView(editValue,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(row1);

        LinearLayout row1b = new LinearLayout(this);
        row1b.setOrientation(LinearLayout.HORIZONTAL);
        row1b.setPadding(0, 0, 0, 4);
        TextView lblVal2 = new TextView(this);
        lblVal2.setText("Máx:");
        lblVal2.setTextColor(0xFFFFFFFF);
        lblVal2.setPadding(0, 0, 8, 0);
        row1b.addView(lblVal2);
        editValue2 = new EditText(this);
        editValue2.setText("0");
        editValue2.setSingleLine(true);
        editValue2.setTextColor(0xFFFFFFFF);
        editValue2.setHint("0");
        editValue2.setHintTextColor(0x88FFFFFF);
        editValue2.setInputType(InputType.TYPE_CLASS_NUMBER |
                InputType.TYPE_NUMBER_FLAG_DECIMAL |
                InputType.TYPE_NUMBER_FLAG_SIGNED);
        row1b.addView(editValue2,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        editValue2.setVisibility(View.GONE);
        root.addView(row1b);

        // Tipo / Cond / Ver
        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        row2.setPadding(0, 4, 0, 4);
        btnType = new Button(this);
        btnType.setText("Tipo: " + TYPE_NAMES[currentType]);
        btnType.setOnClickListener(v -> {
            currentType = (currentType + 1) % TYPE_NAMES.length;
            updateTypeButton();
        });
        row2.addView(btnType,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        btnCondition = new Button(this);
        btnCondition.setText("Cond: " + COND_NAMES[currentCondition]);
        btnCondition.setOnClickListener(v -> {
            currentCondition = (currentCondition + 1) % COND_NAMES.length;
            updateConditionButton();
        });
        row2.addView(btnCondition,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        btnRegion = new Button(this);
        btnRegion.setText("Ver: " + REGION_NAMES[currentRegion]);
        btnRegion.setOnClickListener(v -> {
            currentRegion = (currentRegion + 1) % REGION_NAMES.length;
            nativeSetRegionFilter(REGION_MASKS[currentRegion]);
            updateRegionButton();
            updateFilterStatus();
        });
        row2.addView(btnRegion,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(row2);

        // Scan bar
        LinearLayout scanBar = new LinearLayout(this);
        scanBar.setOrientation(LinearLayout.HORIZONTAL);
        scanBar.setPadding(0, 8, 0, 8);
        btnScan = new Button(this);
        btnScan.setText("Novo Scan");
        btnScan.setOnClickListener(this);
        scanBar.addView(btnScan,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnNext = new Button(this);
        btnNext.setText("Next");
        btnNext.setOnClickListener(this);
        scanBar.addView(btnNext,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnCancel = new Button(this);
        btnCancel.setText("Cancelar");
        btnCancel.setOnClickListener(this);
        btnCancel.setEnabled(false);
        scanBar.addView(btnCancel,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(scanBar);

        // Actions
        LinearLayout actionBar = new LinearLayout(this);
        actionBar.setOrientation(LinearLayout.HORIZONTAL);
        actionBar.setPadding(0, 4, 0, 4);
        btnWrite = new Button(this);
        btnWrite.setText("Escrever");
        btnWrite.setOnClickListener(this);
        actionBar.addView(btnWrite,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnFreeze = new Button(this);
        btnFreeze.setText("Congelar");
        btnFreeze.setOnClickListener(this);
        actionBar.addView(btnFreeze,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnClear = new Button(this);
        btnClear.setText("Limpar");
        btnClear.setOnClickListener(this);
        actionBar.addView(btnClear,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(actionBar);

        // Extra
        LinearLayout extraBar = new LinearLayout(this);
        extraBar.setOrientation(LinearLayout.HORIZONTAL);
        extraBar.setPadding(0, 4, 0, 4);
        btnSave = new Button(this);
        btnSave.setText("Salvar");
        btnSave.setOnClickListener(this);
        extraBar.addView(btnSave,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnLoad = new Button(this);
        btnLoad.setText("Carregar");
        btnLoad.setOnClickListener(this);
        extraBar.addView(btnLoad,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnVicinity = new Button(this);
        btnVicinity.setText("Ao redor");
        btnVicinity.setOnClickListener(this);
        extraBar.addView(btnVicinity,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(extraBar);

        // Tool 1: scan varieties
        LinearLayout toolBar1 = new LinearLayout(this);
        toolBar1.setOrientation(LinearLayout.HORIZONTAL);
        toolBar1.setPadding(0, 4, 0, 4);
        btnAoB = new Button(this);
        btnAoB.setText("AoB");
        btnAoB.setOnClickListener(this);
        toolBar1.addView(btnAoB,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnString = new Button(this);
        btnString.setText("String");
        btnString.setOnClickListener(this);
        toolBar1.addView(btnString,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnPointer = new Button(this);
        btnPointer.setText("Pointer");
        btnPointer.setOnClickListener(this);
        toolBar1.addView(btnPointer,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnSnapshot = new Button(this);
        btnSnapshot.setText("Snap");
        btnSnapshot.setOnClickListener(this);
        toolBar1.addView(btnSnapshot,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(toolBar1);

        // Tool 2: tools & selection
        LinearLayout toolBar2 = new LinearLayout(this);
        toolBar2.setOrientation(LinearLayout.HORIZONTAL);
        toolBar2.setPadding(0, 4, 0, 4);
        btnFollow = new Button(this);
        btnFollow.setText("🔗");
        btnFollow.setOnClickListener(this);
        toolBar2.addView(btnFollow,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnWatchAdd = new Button(this);
        btnWatchAdd.setText("★ Add");
        btnWatchAdd.setOnClickListener(this);
        toolBar2.addView(btnWatchAdd,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnWatchShow = new Button(this);
        btnWatchShow.setText("Watch");
        btnWatchShow.setOnClickListener(this);
        toolBar2.addView(btnWatchShow,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnPaths = new Button(this);
        btnPaths.setText("Paths");
        btnPaths.setOnClickListener(this);
        toolBar2.addView(btnPaths,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnModules = new Button(this);
        btnModules.setText("Módulos");
        btnModules.setOnClickListener(this);
        toolBar2.addView(btnModules,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(toolBar2);

        // Tool 3: select all
        LinearLayout toolBar3 = new LinearLayout(this);
        toolBar3.setOrientation(LinearLayout.HORIZONTAL);
        toolBar3.setPadding(0, 4, 0, 4);
        btnMarkAll = new Button(this);
        btnMarkAll.setText("✓ Tudo");
        btnMarkAll.setOnClickListener(this);
        toolBar3.addView(btnMarkAll,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnUnmarkAll = new Button(this);
        btnUnmarkAll.setText("✗ Nada");
        btnUnmarkAll.setOnClickListener(this);
        toolBar3.addView(btnUnmarkAll,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnSameOffset = new Button(this);
        btnSameOffset.setText("↔ Offset");
        btnSameOffset.setOnClickListener(this);
        toolBar3.addView(btnSameOffset,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnFilterClear = new Button(this);
        btnFilterClear.setText("Filtros OFF");
        btnFilterClear.setOnClickListener(this);
        toolBar3.addView(btnFilterClear,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(toolBar3);

        progressBar = new ProgressBar(this);
        progressBar.setVisibility(View.GONE);
        root.addView(progressBar);

        listView = new ListView(this);
        int listHeight = (int) (dm.density * (landscape ? 140 : 220));
        listView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, listHeight));
        listView.setBackgroundColor(0xFF444444);
        listView.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE);
        listView.setNestedScrollingEnabled(true);
        listView.setOnTouchListener((v, event) -> {
            v.getParent().requestDisallowInterceptTouchEvent(true);
            return false;
        });
        root.addView(listView);

        adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_list_item_multiple_choice, displayItems);
        listView.setAdapter(adapter);
        listView.setOnItemClickListener(this);

        scroll.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        panelView = scroll;

        panelParams = new WindowManager.LayoutParams(
                panelWidth, panelHeight, OVERLAY_TYPE,
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
                PixelFormat.TRANSLUCENT);
        panelParams.gravity = Gravity.TOP | Gravity.START;
        panelParams.x = 20;
        panelParams.y = 40;
        makeDraggable(dragBar, scroll, panelParams, () -> {});

        updateFilterStatus();
    }

    // ==================== Eventos ====================
    @Override
    public void onClick(View v) {
        if (v == btnClose) {
            toggleExpanded();
        } else if (v == btnScan) {
            startScanInternal();
        } else if (v == btnNext) {
            nextScanInternal();
        } else if (v == btnCancel) {
            nativeCancelScan();
            btnCancel.setEnabled(false);
            setStatus("Cancelando...");
        } else if (v == btnWrite) {
            writeSelected();
        } else if (v == btnFreeze) {
            freezeSelected();
        } else if (v == btnClear) {
            nativeClearResults();
            resetResults();
            setStatus("Resultados limpos");
        } else if (v == btnSave) {
            saveStateToFile();
        } else if (v == btnLoad) {
            loadStateFromFile();
        } else if (v == btnVicinity) {
            showVicinity();
        } else if (v == btnAoB) {
            showAoBDialog();
        } else if (v == btnString) {
            showStringDialog();
        } else if (v == btnPointer) {
            showPointerDialog();
        } else if (v == btnSnapshot) {
            showSnapshotDialog();
        } else if (v == btnFollow) {
            followPointer();
        } else if (v == btnWatchAdd) {
            addCheckedToWatch();
        } else if (v == btnWatchShow) {
            showWatchDialog();
        } else if (v == btnPaths) {
            showPathsDialog();
        } else if (v == btnModules) {
            showModulesDialog();
        } else if (v == btnMarkAll) {
            for (int i = 0; i < displayItems.size(); i++) listView.setItemChecked(i, true);
        } else if (v == btnUnmarkAll) {
            for (int i = 0; i < displayItems.size(); i++) listView.setItemChecked(i, false);
        } else if (v == btnSameOffset) {
            filterSameOffset();
        } else if (v == btnFilterClear) {
            moduleFilter = "";
            pointerStaticOnly = false;
            currentRegion = 0;
            nativeSetModuleFilter("");
            nativeSetPointerStaticFilter(false);
            nativeSetRegionFilter(REGION_MASKS[currentRegion]);
            getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                    .putString(PREF_MODULE_FILTER, "")
                    .putBoolean(PREF_POINTER_STATIC, false)
                    .apply();
            updateRegionButton();
            updateFilterStatus();
            toast("Filtros desligados");
        }
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view, int position, long id) { }

    // ==================== Drain ====================
    private void scheduleDrain(long delayMs) {
        if (drainScheduled.compareAndSet(false, true))
            mainHandler.postDelayed(drainTask, delayMs);
    }

    private void drainIncomingToUi() {
        if (adapter == null) return;
        List<String> batch;
        synchronized (incomingLock) {
            if (incomingItems.isEmpty()) return;
            batch = new ArrayList<>(incomingItems);
            incomingItems.clear();
        }

        int room = DISPLAY_LIMIT - displayItems.size();
        int take = Math.min(room, batch.size());
        if (take > 0) {
            displayItems.addAll(batch.subList(0, take));
            adapter.notifyDataSetChanged();
        }
        updateTitle();

        if (displayItems.size() >= DISPLAY_LIMIT && !displayFullNotified) {
            displayFullNotified = true;
            try { nativeSetDisplayFull(); } catch (Throwable ignored) {}
        }
    }

    // ==================== Reset / Scan ====================
    private void resetResults() {
        refinable = false;
        totalAddresses.set(0);
        displayFullNotified = false;
        scanActive = false;
        synchronized (incomingLock) { incomingItems.clear(); }
        displayItems.clear();
        if (adapter != null) adapter.notifyDataSetChanged();
        if (tvTitle != null) tvTitle.setText("Endereços: 0");
    }

    // Faixa: compara por VALOR (os longs aqui são bits crus no caso de float/double;
    // comparar os bits invertia qualquer faixa com números negativos).
    private boolean rangeNeedsSwap(long a, long b, int type) {
        if (type == TYPE_FLOAT)  return Float.intBitsToFloat((int) a) > Float.intBitsToFloat((int) b);
        if (type == TYPE_DOUBLE) return Double.longBitsToDouble(a) > Double.longBitsToDouble(b);
        return a > b;
    }

    // Parse de hexadecimal SEM sinal (endereços podem ter o bit alto ligado).
    private static long parseHex(String str) throws NumberFormatException {
        String t = str.trim();
        if (t.isEmpty() || t.length() > 16) throw new NumberFormatException("hex: " + str);
        long v = 0;
        for (int i = 0; i < t.length(); i++) {
            int d = Character.digit(t.charAt(i), 16);
            if (d < 0) throw new NumberFormatException("hex: " + str);
            v = (v << 4) | d;
        }
        return v;
    }

    // Valor de ponteiro lido da memória (remove a tag do byte alto em 64 bits).
    private static long ptrFromBytes(byte[] data) {
        long v = toLong(data, data.length);
        if (data.length == 8) v &= 0x00FFFFFFFFFFFFFFL;
        return v;
    }

    private void beginScanUi(String status) {
        resetResults();
        scanActive = true;
        scheduleDrain(0);
        setStatus(status);
        btnCancel.setEnabled(true);
        progressBar.setVisibility(View.VISIBLE);
        progressBar.setProgress(0);
    }

    // O nativo recusou (scan em andamento / entrada inválida): destrava a UI.
    private void onScanRefused() {
        scanActive = false;
        if (progressBar != null) progressBar.setVisibility(View.GONE);
        if (btnCancel != null) btnCancel.setEnabled(false);
        setStatus("Não foi possível iniciar (scan em andamento ou entrada inválida)");
    }

    private void startScanInternal() {
        if (scanActive) { toast("Aguarde o scan atual terminar"); return; }
        if (!validateInput(currentType)) return;
        long value  = parseOne(editValue,  currentType);
        long value2 = (currentCondition == COND_RANGE)
                        ? parseOne(editValue2, currentType) : value;
        if (currentCondition == COND_RANGE && rangeNeedsSwap(value, value2, currentType)) {
            long tmp = value; value = value2; value2 = tmp;
        }

        lastScanType = currentType;
        beginScanUi("Scanneando...");
        if (!nativeStartScan(value, value2, currentType, currentCondition)) onScanRefused();
    }

    private void nextScanInternal() {
        if (scanActive) { toast("Aguarde o scan atual terminar"); return; }
        if (!refinable) {
            toast("Faça um Novo Scan antes (a lista atual não pode ser refinada).");
            return;
        }
        // O tipo do refino é SEMPRE o do último scan, vindo do nativo (evita desencontro
        // quando o botão de tipo foi trocado ou o último scan foi String/AoB).
        lastScanType = nativeGetLastScanType();
        if (!validateInput(lastScanType)) return;
        long value  = parseOne(editValue,  lastScanType);
        long value2 = (currentCondition == COND_RANGE)
                        ? parseOne(editValue2, lastScanType) : value;
        if (currentCondition == COND_RANGE && rangeNeedsSwap(value, value2, lastScanType)) {
            long tmp = value; value = value2; value2 = tmp;
        }

        beginScanUi("Refinando...");
        if (!nativeNextScan(value, value2, currentCondition)) onScanRefused();
    }

    private List<Integer> getCheckedPositions() {
        SparseBooleanArray checked = listView.getCheckedItemPositions();
        List<Integer> positions = new ArrayList<>();
        for (int i = 0; i < checked.size(); i++)
            if (checked.valueAt(i)) positions.add(checked.keyAt(i));
        return positions;
    }

    private void writeSelected() {
        List<Integer> positions = getCheckedPositions();
        if (positions.isEmpty()) { toast("Selecione pelo menos um endereço"); return; }
        // Escreve com o tipo do scan (o da lista), não com o do botão de tipo.
        final int type = lastScanType;
        if (!validateOne(editValue, type)) return;
        long value = parseOne(editValue, type);
        byte[] data = convertValueToBytes(value, type);
        if (data == null) { toast("Erro na conversão do valor"); return; }
        int okCount = 0;
        for (int pos : positions) {
            if (pos < 0 || pos >= displayItems.size()) continue;
            long addr = extractAddress(displayItems.get(pos));
            if (addr != -1 && nativeWriteMemory(addr, data)) okCount++;
        }
        toast("Escrita OK em " + okCount + "/" + positions.size());
        refreshDisplayValues();
    }

    private void freezeSelected() {
        List<Integer> positions = getCheckedPositions();
        if (positions.isEmpty()) { toast("Selecione pelo menos um endereço"); return; }
        final int type = lastScanType;
        if (!validateOne(editValue, type)) return;
        long value = parseOne(editValue, type);
        for (int pos : positions) {
            if (pos < 0 || pos >= displayItems.size()) continue;
            long addr = extractAddress(displayItems.get(pos));
            if (addr != -1) nativeToggleFreeze(addr, value, type, true);
        }
        toast("Freeze ativado para " + positions.size() + " endereço(s)");
    }

    // ============================================================
    //  AoB
    // ============================================================
    private void showAoBDialog() {
        EditText input = new EditText(this);
        input.setSingleLine(false);
        input.setHint("Ex: FF ?? AA 12 B0");
        input.setTextColor(0xFFFFFFFF);
        input.setHintTextColor(0x88FFFFFF);
        input.setText("FF ?? AA");

        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        wrap.setPadding(24, 24, 24, 24);
        wrap.setBackgroundColor(0xFF222222);
        wrap.addView(input, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("AoB Scan (wildcards = ? ou ??)")
                .setView(wrap)
                .setPositiveButton("Escanear", (d, w) -> {
                    String pat = input.getText().toString().trim();
                    if (TextUtils.isEmpty(pat)) { toast("Padrão vazio"); return; }
                    if (scanActive) { toast("Aguarde o scan atual terminar"); return; }
                    beginScanUi("AoB scan...");
                    if (!nativeAoBScan(pat, DISPLAY_LIMIT)) {
                        onScanRefused();
                        toast("Padrão inválido. Use bytes hex: FF ?? A? 12");
                    } else {
                        lastScanType = nativeGetLastScanType();
                    }
                })
                .setNegativeButton("Cancelar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();
    }

    // ============================================================
    //  String scan
    // ============================================================
    private void showStringDialog() {
        final EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setHint("Texto a buscar");
        input.setTextColor(0xFFFFFFFF);
        input.setHintTextColor(0x88FFFFFF);

        final CheckBox cbUtf16 = new CheckBox(this);
        cbUtf16.setText("UTF-16LE (senão UTF-8)");
        cbUtf16.setTextColor(0xFFFFFFFF);

        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        wrap.setPadding(24, 24, 24, 24);
        wrap.setBackgroundColor(0xFF222222);
        wrap.addView(input, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        wrap.addView(cbUtf16);

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("String Scan")
                .setView(wrap)
                .setPositiveButton("Escanear", (d, w) -> {
                    String txt = input.getText().toString();
                    if (txt.isEmpty()) { toast("Digite um texto"); return; }
                    int enc = cbUtf16.isChecked() ? STR_UTF16LE : STR_UTF8;
                    if (scanActive) { toast("Aguarde o scan atual terminar"); return; }
                    beginScanUi("String scan " + (enc == STR_UTF16LE ? "(UTF-16)" : "(UTF-8)") + "...");
                    if (!nativeStringScan(txt, enc)) onScanRefused();
                    else lastScanType = nativeGetLastScanType();
                })
                .setNegativeButton("Cancelar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();
    }

    // ============================================================
    //  Pointer scan
    // ============================================================
    private void showPointerDialog() {
        List<Integer> positions = getCheckedPositions();
        String suggestion = "";
        if (!positions.isEmpty()) {
            int pos = positions.get(0);
            if (pos >= 0 && pos < displayItems.size()) {
                long a = extractAddress(displayItems.get(pos));
                if (a != -1) suggestion = String.format("0x%X", a);
            }
        }

        final EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setHint("0x1234ABCD");
        input.setTextColor(0xFFFFFFFF);
        input.setHintTextColor(0x88FFFFFF);
        input.setText(suggestion);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);

        final EditText depthIn = new EditText(this);
        depthIn.setSingleLine(true);
        depthIn.setText("2");
        depthIn.setTextColor(0xFFFFFFFF);
        depthIn.setInputType(InputType.TYPE_CLASS_NUMBER);
        depthIn.setHint("1-4");

        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        wrap.setPadding(24, 24, 24, 24);
        wrap.setBackgroundColor(0xFF222222);

        final TextView tvFilter = new TextView(this);
        tvFilter.setTextColor(pointerStaticOnly ? 0xFF66FF66 : 0xFFAAAAAA);
        tvFilter.setTextSize(13f);
        tvFilter.setPadding(0, 0, 0, 8);
        tvFilter.setText("Filtro: " + (pointerStaticOnly
                ? "Só estáticos (libs .so + executáveis)"
                : "Universal (todas as regiões)"));
        wrap.addView(tvFilter);

        TextView l1 = new TextView(this);
        l1.setText("Endereço alvo:");
        l1.setTextColor(0xFFFFFFFF);
        wrap.addView(l1);
        wrap.addView(input, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView l2 = new TextView(this);
        l2.setText("Profundidade (níveis):");
        l2.setTextColor(0xFFFFFFFF);
        l2.setPadding(0, 16, 0, 0);
        wrap.addView(l2);
        wrap.addView(depthIn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        final CheckBox cbStatic = new CheckBox(this);
        cbStatic.setText("Só estáticos (libs .so + executáveis)");
        cbStatic.setTextColor(0xFFFFFFFF);
        cbStatic.setPadding(0, 16, 0, 0);
        cbStatic.setChecked(pointerStaticOnly);
        cbStatic.setOnCheckedChangeListener((bv, isChecked) -> {
            pointerStaticOnly = isChecked;
            nativeSetPointerStaticFilter(pointerStaticOnly);
            getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                    .edit()
                    .putBoolean(PREF_POINTER_STATIC, pointerStaticOnly)
                    .apply();
            tvFilter.setText("Filtro: " + (isChecked
                    ? "Só estáticos (libs .so + executáveis)"
                    : "Universal (todas as regiões)"));
            tvFilter.setTextColor(isChecked ? 0xFF66FF66 : 0xFFAAAAAA);
            updateFilterStatus();
        });
        wrap.addView(cbStatic);

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("Pointer Scan" + (pointerStaticOnly ? " [Só estáticos]" : ""))
                .setView(wrap)
                .setPositiveButton("Escanear", (d, w) -> {
                    String s = input.getText().toString().trim();
                    if (s.isEmpty()) { toast("Digite um endereço"); return; }
                    long target;
                    try {
                        target = s.startsWith("0x") || s.startsWith("0X")
                                ? parseHex(s.substring(2))
                                : Long.parseLong(s);
                    } catch (NumberFormatException e) {
                        toast("Endereço inválido"); return;
                    }
                    int depth;
                    try { depth = Integer.parseInt(depthIn.getText().toString().trim()); }
                    catch (Exception e) { depth = 2; }
                    if (depth < 1) depth = 1;
                    if (depth > 4) depth = 4;

                    if (scanActive) { toast("Aguarde o scan atual terminar"); return; }
                    lastPointerTarget = target;
                    beginScanUi("Pointer scan...");
                    if (!nativePointerScan(target, depth)) onScanRefused();
                })
                .setNegativeButton("Cancelar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();
    }

    // ============================================================
    //  Same-offset filter
    // ============================================================
    private void filterSameOffset() {
        if (displayItems.isEmpty()) { toast("Sem resultados"); return; }
        if (lastPointerTarget == 0) { toast("Execute um Pointer Scan primeiro"); return; }

        // Conta offsets (target - ptr)
        Map<Long, Integer> counts = new HashMap<>();
        for (String item : displayItems) {
            long addr = extractAddress(item);
            if (addr == -1) continue;
            long off = lastPointerTarget - addr;
            counts.put(off, counts.getOrDefault(off, 0) + 1);
        }
        if (counts.isEmpty()) { toast("Sem offsets"); return; }

        long bestOff = 0; int bestCount = 0;
        for (Map.Entry<Long, Integer> e : counts.entrySet()) {
            if (e.getValue() > bestCount) { bestCount = e.getValue(); bestOff = e.getKey(); }
        }

        List<String> filtered = new ArrayList<>();
        for (String item : displayItems) {
            long addr = extractAddress(item);
            if (addr == -1) continue;
            if ((lastPointerTarget - addr) == bestOff) filtered.add(item);
        }

        displayItems.clear();
        displayItems.addAll(filtered);
        adapter.notifyDataSetChanged();
        updateTitle();
        toast("Offset 0x" + Long.toHexString(bestOff) + " — " + filtered.size() + " itens");
    }

    // ============================================================
    //  Snapshot dialog
    // ============================================================
    private void showSnapshotDialog() {
        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        wrap.setPadding(24, 24, 24, 24);
        wrap.setBackgroundColor(0xFF222222);

        TextView info = new TextView(this);
        info.setTextColor(0xFFFFFFFF);
        info.setText("1) Salvar snapshot com os valores atuais.\n" +
                     "2) Mude o jogo.\n" +
                     "3) Escolha um filtro abaixo.");
        wrap.addView(info);

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("Snapshot / Diff")
                .setView(wrap)
                .setPositiveButton("Salvar snap", (d, w) -> new Thread(() -> {
                    final int saved = nativeSnapshotSave();
                    mainHandler.post(() -> toast(saved == -1
                            ? "Aguarde o scan atual terminar"
                            : saved < 0 ? "Falha ao salvar snapshot"
                                        : "Snapshot: " + saved + " valores"));
                }, "memscan-snap").start())
                .setNeutralButton("Limpar snap", (d, w) -> {
                    nativeSnapshotClear();
                    toast("Snapshot apagado");
                })
                .setNegativeButton("Fechar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();

        // Botões de diff, em linha
        LinearLayout diffRow = new LinearLayout(this);
        diffRow.setOrientation(LinearLayout.HORIZONTAL);
        wrap.addView(diffRow);

        String[] labels = {"Mudou", "Igual", "Aumentou", "Diminuiu"};
        int[] modes = {DIFF_CHANGED, DIFF_UNCHANGED, DIFF_INCREASED, DIFF_DECREASED};
        for (int i = 0; i < labels.length; i++) {
            final int mode = modes[i];
            Button b = new Button(this);
            b.setText(labels[i]);
            b.setOnClickListener(v -> {
                try { dlg.dismiss(); } catch (Exception ignored) {}
                setStatus("Aplicando diff...");
                // Fora da UI thread: com muitos resultados isto travava a tela (ANR).
                new Thread(() -> {
                    final int count = nativeSnapshotDiff(mode);
                    if (count < 0) {
                        mainHandler.post(() -> {
                            String m = (count == -1) ? "Aguarde o scan atual terminar"
                                                      : "Sem snapshot salvo";
                            setStatus(m);
                            toast(m);
                        });
                        return;
                    }
                    final long[] addrs = nativeGetResults(DISPLAY_LIMIT);
                    final int size = getTypeSize(lastScanType);
                    final List<String> items = new ArrayList<>();
                    if (addrs != null)
                        for (long a : addrs) items.add(formatItem(a, nativeReadMemory(a, size)));
                    mainHandler.post(() -> {
                        resetResults();
                        displayItems.addAll(items);
                        totalAddresses.set(count);
                        if (adapter != null) adapter.notifyDataSetChanged();
                        refinable = count > 0;
                        updateTitle();
                        setStatus("Diff: " + count + " resultados");
                        toast("Diff → " + count);
                    });
                }, "memscan-diff").start();
            });
            diffRow.addView(b, new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        }
    }

    // ============================================================
    //  Watch list — adicionar
    // ============================================================
    private void addCheckedToWatch() {
        List<Integer> positions = getCheckedPositions();
        if (positions.isEmpty()) { toast("Marque um endereço primeiro"); return; }
        int added = 0;
        for (int pos : positions) {
            if (pos < 0 || pos >= displayItems.size()) continue;
            String item = displayItems.get(pos);
            long addr = extractAddress(item);
            if (addr == -1) continue;
            boolean isPtr = isPointerResult(item);
            if (!watchAddrs.containsKey(addr)) {
                watchAddrs.put(addr, isPtr);
                added++;
            }
        }
        saveWatch();
        toast("Adicionados " + added + " | Total: " + watchAddrs.size());
    }

    // ============================================================
    //  Watch list — exibir (com live update)
    // ============================================================
    private void showWatchDialog() {
        if (watchAddrs.isEmpty()) { toast("Watch list vazia"); return; }

        final List<Long> list = new ArrayList<>(watchAddrs.keySet());

        final LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setBackgroundColor(0xFF222222);
        container.setPadding(16, 16, 16, 16);

        final int type = lastScanType;
        final int size = getTypeSize(type);

        // Linhas de UI pra atualizar depois
        final List<TextView> valueViews = new ArrayList<>();
        final List<Long>    valueAddrs = new ArrayList<>();
        final List<Boolean> valueIsPtr = new ArrayList<>();

        for (int i = 0; i < list.size(); i++) {
            final long addr = list.get(i);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);

            TextView tvAddr = new TextView(this);
            tvAddr.setText(String.format("0x%08X", addr));
            tvAddr.setTextColor(0xFFFFFFFF);
            tvAddr.setTypeface(Typeface.MONOSPACE);
            tvAddr.setPadding(0, 8, 8, 8);
            row.addView(tvAddr, new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.2f));

            final boolean isPtr = Boolean.TRUE.equals(watchAddrs.get(addr));

            TextView tvVal = new TextView(this);
            tvVal.setTextColor(0xFFFFFFFF);
            tvVal.setTypeface(Typeface.MONOSPACE);
            tvVal.setPadding(0, 8, 8, 8);
            row.addView(tvVal, new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.2f));
            valueViews.add(tvVal);
            valueAddrs.add(addr);
            valueIsPtr.add(isPtr);

            final long writeAt0;
            if (isPtr) {
                byte[] pdata = nativeReadMemory(addr, PTR_SIZE);
                writeAt0 = (pdata != null) ? ptrFromBytes(pdata) : -1;
            } else {
                writeAt0 = addr;
            }

            Button btnEdit = new Button(this);
            btnEdit.setText("✎");
            btnEdit.setMinWidth(0);
            btnEdit.setMinimumWidth(0);
            btnEdit.setPadding(4, 0, 4, 0);
            final String typeName = TYPE_NAMES[type];
            btnEdit.setOnClickListener(view -> {
                if (writeAt0 < 0) { toast("Endereço inválido"); return; }
                EditText in = new EditText(MemoryScannerService.this);
                in.setTextColor(0xFFFFFFFF);
                in.setInputType(InputType.TYPE_CLASS_NUMBER |
                        InputType.TYPE_NUMBER_FLAG_DECIMAL |
                        InputType.TYPE_NUMBER_FLAG_SIGNED);
                AlertDialog ed = new AlertDialog.Builder(MemoryScannerService.this)
                        .setTitle(String.format("Editar 0x%08X (%s)", writeAt0, typeName))
                        .setView(in)
                        .setPositiveButton("OK", (d2, w2) -> {
                            String s = in.getText().toString().trim();
                            long parsedVal;
                            try {
                                if (type == TYPE_FLOAT) {
                                    parsedVal = Float.floatToRawIntBits(Float.parseFloat(s)) & 0xFFFFFFFFL;
                                } else if (type == TYPE_DOUBLE) {
                                    parsedVal = Double.doubleToRawLongBits(Double.parseDouble(s));
                                } else {
                                    parsedVal = Long.parseLong(s);
                                }
                            } catch (Exception e) { toast("Valor inválido"); return; }
                            byte[] b = convertValueToBytes(parsedVal, type);
                            if (b != null && nativeWriteMemory(writeAt0, b))
                                toast("Escrito em " + String.format("0x%08X", writeAt0));
                            else toast("Falha");
                        })
                        .setNegativeButton("Cancelar", null)
                        .create();
                if (ed.getWindow() != null) ed.getWindow().setType(OVERLAY_TYPE);
                ed.show();
            });
            row.addView(btnEdit);

            Button btnRm = new Button(this);
            btnRm.setText("✕");
            btnRm.setMinWidth(0);
            btnRm.setMinimumWidth(0);
            btnRm.setPadding(4, 0, 4, 0);
            btnRm.setOnClickListener(view -> {
                watchAddrs.remove(addr);
                saveWatch();
                toast("Removido");
                try { ((AlertDialog) view.getTag()).dismiss(); } catch (Exception ignored) {}
            });
            row.addView(btnRm);

            container.addView(row);
        }

        // Botões freeze all / unfreeze all
        LinearLayout bulk = new LinearLayout(this);
        bulk.setOrientation(LinearLayout.HORIZONTAL);
        bulk.setPadding(0, 8, 0, 0);

        Button btnFreezeAll = new Button(this);
        btnFreezeAll.setText("❄ Congelar todos");
        btnFreezeAll.setOnClickListener(v -> {
            int n = 0;
            for (Long a : watchAddrs.keySet()) {
                boolean isPtr = Boolean.TRUE.equals(watchAddrs.get(a));
                long readAt = a;
                if (isPtr) {
                    byte[] pdata = nativeReadMemory(a, PTR_SIZE);
                    if (pdata == null) continue;
                    readAt = ptrFromBytes(pdata);
                }
                byte[] data = nativeReadMemory(readAt, size);
                if (data == null) continue;
                long val = bytesToLong(data);
                nativeToggleFreeze(readAt, val, type, true);
                n++;
            }
            toast("Congelados " + n);
        });
        bulk.addView(btnFreezeAll, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button btnUnfreezeAll = new Button(this);
        btnUnfreezeAll.setText("♨ Descon. todos");
        btnUnfreezeAll.setOnClickListener(v -> {
            int n = 0;
            for (Long a : watchAddrs.keySet()) {
                boolean isPtr = Boolean.TRUE.equals(watchAddrs.get(a));
                long readAt = a;
                if (isPtr) {
                    byte[] pdata = nativeReadMemory(a, PTR_SIZE);
                    if (pdata == null) continue;
                    readAt = ptrFromBytes(pdata);
                }
                nativeToggleFreeze(readAt, 0, type, false);
                n++;
            }
            toast("Descongelados " + n);
        });
        bulk.addView(btnUnfreezeAll, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        container.addView(bulk);

        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(0xFF222222);
        sv.addView(container);

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("Watch List (" + list.size() + ")")
                .setView(sv)
                .setPositiveButton("Fechar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();

        for (int i = 0; i < container.getChildCount(); i++) {
            View child = container.getChildAt(i);
            if (child instanceof LinearLayout) {
                LinearLayout r = (LinearLayout) child;
                for (int j = 0; j < r.getChildCount(); j++)
                    r.getChildAt(j).setTag(dlg);
            }
        }

        // ---- Live update ----
        final boolean[] running = {true};
        final Runnable update = new Runnable() {
            @Override public void run() {
                if (!running[0]) return;
                for (int i = 0; i < valueViews.size(); i++) {
                    long addr = valueAddrs.get(i);
                    boolean isPtr = valueIsPtr.get(i);
                    long readAt = addr;
                    String chain = "";
                    if (isPtr) {
                        byte[] pdata = nativeReadMemory(addr, PTR_SIZE);
                        if (pdata != null) {
                            readAt = ptrFromBytes(pdata);
                            chain = String.format("→ 0x%08X  ", readAt);
                        } else {
                            valueViews.get(i).setText("(falha ptr)");
                            continue;
                        }
                    }
                    byte[] data = nativeReadMemory(readAt, size);
                    if (data != null) {
                        valueViews.get(i).setText(chain + hexToDisplay(data, type));
                    } else {
                        valueViews.get(i).setText(chain + "--");
                    }
                }
                mainHandler.postDelayed(this, 500);
            }
        };
        mainHandler.post(update);

        dlg.setOnDismissListener(d -> running[0] = false);
    }

    // ============================================================
    //  Watch list — persistência
    // ============================================================
    private void saveWatch() {
        File f = new File(getFilesDir(), "watch.txt");
        try (FileWriter fw = new FileWriter(f)) {
            for (Map.Entry<Long, Boolean> e : watchAddrs.entrySet()) {
                fw.write(Long.toHexString(e.getKey()) + ":" +
                         (e.getValue() ? "1" : "0") + "\n");
            }
        } catch (Exception e) {
            Log.e(TAG, "saveWatch", e);
        }
    }

    private void loadWatch() {
        File f = new File(getFilesDir(), "watch.txt");
        if (!f.exists()) return;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                try {
                    String[] parts = line.split(":");
                    long a = parseHex(parts[0]);
                    boolean p = parts.length > 1 && "1".equals(parts[1]);
                    watchAddrs.put(a, p);
                } catch (NumberFormatException ignored) {}
            }
        } catch (Exception e) {
            Log.e(TAG, "loadWatch", e);
        }
    }

    // ============================================================
    //  Pointer Paths — diálogo
    // ============================================================
    private void showPathsDialog() {
        final LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setBackgroundColor(0xFF222222);
        container.setPadding(16, 16, 16, 16);

        if (pointerPaths.isEmpty()) {
            TextView tv = new TextView(this);
            tv.setText("Nenhum caminho salvo.\n\nPara criar: faça um Pointer Scan, marque um resultado L1 e toque em 🔗 → Salvar caminho.");
            tv.setTextColor(0xFFAAAAAA);
            container.addView(tv);
        }

        final int type = lastScanType;
        final int size = getTypeSize(type);

        for (int i = 0; i < pointerPaths.size(); i++) {
            final int idx = i;
            final PointerPath pp = pointerPaths.get(i);

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);

            StringBuilder sb = new StringBuilder();
            sb.append(pp.module).append("+0x").append(Long.toHexString(pp.baseOffset));
            for (int off : pp.offsets)
                sb.append(" →+0x").append(Integer.toHexString(off));

            TextView tv = new TextView(this);
            tv.setText(sb.toString());
            tv.setTextColor(0xFFFFFFFF);
            tv.setTypeface(Typeface.MONOSPACE);
            tv.setTextSize(12f);
            tv.setPadding(0, 8, 8, 8);
            row.addView(tv, new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

            Button btnResolve = new Button(this);
            btnResolve.setText("↻");
            btnResolve.setMinWidth(0);
            btnResolve.setMinimumWidth(0);
            btnResolve.setOnClickListener(v -> {
                long base = nativeGetModuleBase(pp.module);
                if (base == 0) { toast("Módulo não encontrado"); return; }
                long resolved = nativeResolvePointerPath(base + pp.baseOffset, pp.offsets);
                if (resolved == 0) { toast("Falha ao resolver"); return; }
                byte[] data = nativeReadMemory(resolved, size);
                String val = data != null ? formatAs(data, type) : "?";
                toast(String.format("→ 0x%08X = %s", resolved, val));
                // Também coloca na lista pra ficar visível
                displayItems.add(0, String.format("0x%08X  %s",
                        resolved, data != null ? bytesToHex(data) : "?"));
                adapter.notifyDataSetChanged();
            });
            row.addView(btnResolve);

            Button btnEdit = new Button(this);
            btnEdit.setText("✎");
            btnEdit.setMinWidth(0);
            btnEdit.setMinimumWidth(0);
            btnEdit.setOnClickListener(v -> editPathDialog(idx));
            row.addView(btnEdit);

            Button btnRm = new Button(this);
            btnRm.setText("✕");
            btnRm.setMinWidth(0);
            btnRm.setMinimumWidth(0);
            btnRm.setOnClickListener(v -> {
                pointerPaths.remove(idx);
                toast("Removido");
                try { ((AlertDialog) v.getTag()).dismiss(); } catch (Exception ignored) {}
            });
            row.addView(btnRm);

            container.addView(row);
        }

        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(0xFF222222);
        sv.addView(container);

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("Pointer Paths (" + pointerPaths.size() + ")")
                .setView(sv)
                .setPositiveButton("+ Novo", (d, w) -> editPathDialog(-1))
                .setNegativeButton("Fechar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();

        for (int i = 0; i < container.getChildCount(); i++) {
            View child = container.getChildAt(i);
            if (child instanceof LinearLayout) {
                LinearLayout r = (LinearLayout) child;
                for (int j = 0; j < r.getChildCount(); j++)
                    r.getChildAt(j).setTag(dlg);
            }
        }
    }

    private void editPathDialog(int editIdx) {
        PointerPath init = (editIdx >= 0 && editIdx < pointerPaths.size())
                ? pointerPaths.get(editIdx) : null;

        final EditText eModule = new EditText(this);
        eModule.setSingleLine(true);
        eModule.setHint("libil2cpp.so");
        eModule.setTextColor(0xFFFFFFFF);
        if (init != null) eModule.setText(init.module);

        final EditText eBase = new EditText(this);
        eBase.setSingleLine(true);
        eBase.setHint("0x1234");
        eBase.setTextColor(0xFFFFFFFF);
        if (init != null) eBase.setText("0x" + Long.toHexString(init.baseOffset));

        final EditText eOffsets = new EditText(this);
        eOffsets.setSingleLine(true);
        eOffsets.setHint("0x10, 0x20");
        eOffsets.setTextColor(0xFFFFFFFF);
        if (init != null) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < init.offsets.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append("0x").append(Integer.toHexString(init.offsets[i]));
            }
            eOffsets.setText(sb.toString());
        } else {
            eOffsets.setText("0x0");
        }

        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        wrap.setPadding(24, 24, 24, 24);
        wrap.setBackgroundColor(0xFF222222);

        wrap.addView(mkLabel("Módulo:"));
        wrap.addView(eModule);
        wrap.addView(mkLabel("Base offset:"));
        wrap.addView(eBase);
        wrap.addView(mkLabel("Offsets (separados por vírgula):"));
        wrap.addView(eOffsets);

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle(editIdx < 0 ? "Novo Pointer Path" : "Editar Pointer Path")
                .setView(wrap)
                .setPositiveButton("Salvar", (d, w) -> {
                    String mod = eModule.getText().toString().trim();
                    if (mod.isEmpty()) { toast("Módulo vazio"); return; }
                    long baseOff;
                    try { baseOff = parseHexOrDec(eBase.getText().toString().trim()); }
                    catch (Exception e) { toast("Base inválida"); return; }
                    String[] tokens = eOffsets.getText().toString().split(",");
                    List<Integer> offs = new ArrayList<>();
                    for (String t : tokens) {
                        t = t.trim();
                        if (t.isEmpty()) continue;
                        try { offs.add((int)parseHexOrDec(t)); }
                        catch (Exception e) { toast("Offset inválido: " + t); return; }
                    }
                    if (offs.isEmpty()) offs.add(0);
                    int[] arr = new int[offs.size()];
                    for (int i = 0; i < offs.size(); i++) arr[i] = offs.get(i);

                    PointerPath pp = new PointerPath();
                    pp.module = mod;
                    pp.baseOffset = baseOff;
                    pp.offsets = arr;

                    if (editIdx >= 0) pointerPaths.set(editIdx, pp);
                    else pointerPaths.add(pp);
                    toast("Path salvo");
                })
                .setNegativeButton("Cancelar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();
    }

    private TextView mkLabel(String txt) {
        TextView t = new TextView(this);
        t.setText(txt);
        t.setTextColor(0xFFFFFFFF);
        t.setPadding(0, 12, 0, 0);
        return t;
    }

    private static long parseHexOrDec(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) return parseHex(s.substring(2));
        return Long.parseLong(s);
    }

    // ============================================================
    //  Módulos
    // ============================================================
    private void showModulesDialog() {
        String[] mods = nativeListModules();
        if (mods == null) mods = new String[0];

        final LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setBackgroundColor(0xFF222222);
        container.setPadding(16, 16, 16, 16);

        TextView info = new TextView(this);
        info.setTextColor(0xFFAAAAAA);
        info.setText("Toque para filtrar todos os scans por este módulo.\n" +
                     "Atual: " + (moduleFilter.isEmpty() ? "(nenhum)" : moduleFilter));
        container.addView(info);

        final AlertDialog[] dlgRef = new AlertDialog[1];

        for (final String m : mods) {
            Button b = new Button(this);
            b.setText(m);
            b.setAllCaps(false);
            b.setOnClickListener(v -> {
                moduleFilter = m;
                nativeSetModuleFilter(moduleFilter);
                getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                        .putString(PREF_MODULE_FILTER, moduleFilter).apply();
                updateFilterStatus();
                toast("Filtro: " + m);
                if (dlgRef[0] != null) dlgRef[0].dismiss();
            });
            container.addView(b);
        }

        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(0xFF222222);
        sv.addView(container);

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("Módulos carregados (" + mods.length + ")")
                .setView(sv)
                .setPositiveButton("Limpar filtro", (d, w) -> {
                    moduleFilter = "";
                    nativeSetModuleFilter("");
                    getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                            .putString(PREF_MODULE_FILTER, "").apply();
                    updateFilterStatus();
                    toast("Filtro de módulo removido");
                })
                .setNegativeButton("Fechar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();
        dlgRef[0] = dlg;
    }

    // ============================================================
    //  Follow pointer
    // ============================================================
    private void followPointer() {
        List<Integer> positions = getCheckedPositions();
        if (positions.isEmpty()) {
            toast("Marque um resultado de Pointer Scan primeiro");
            return;
        }
        int pos = positions.get(0);
        if (pos < 0 || pos >= displayItems.size()) return;
        String item = displayItems.get(pos);
        if (!isPointerResult(item)) {
            toast("Selecione um resultado de Pointer Scan (L1, L2...)");
            return;
        }

        long ptrAddr = extractAddress(item);
        if (ptrAddr == -1) { toast("Endereço do pointer inválido"); return; }

        byte[] ptrData = nativeReadMemory(ptrAddr, PTR_SIZE);
        if (ptrData == null) { toast("Falha ao ler o pointer"); return; }
        final long targetAddr = ptrFromBytes(ptrData);
        if (targetAddr == 0) { toast("Pointer aponta para NULL"); return; }

        final int type = lastScanType;
        final int size = getTypeSize(type);

        byte[] targetData = nativeReadMemory(targetAddr, size);
        String preview = (targetData != null) ? formatAs(targetData, type) : "--";

        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        wrap.setPadding(24, 24, 24, 24);
        wrap.setBackgroundColor(0xFF222222);

        TextView info = new TextView(this);
        info.setText(String.format(
                "Pointer:  0x%08X\nAlvo:     0x%08X\nValor:    %s",
                ptrAddr, targetAddr, preview));
        info.setTextColor(0xFFFFFFFF);
        info.setTypeface(Typeface.MONOSPACE);
        info.setTextIsSelectable(true);
        wrap.addView(info);

        Button btnSavePath = new Button(this);
        btnSavePath.setText("💾 Salvar como Pointer Path");
        btnSavePath.setOnClickListener(v -> trySavePointerPath(ptrAddr, targetAddr));
        wrap.addView(btnSavePath);

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("🔗 Seguir Pointer")
                .setView(wrap)
                .setPositiveButton("Editar alvo", (d, w) -> {
                    EditText in = new EditText(this);
                    in.setText(preview);
                    in.setTextColor(0xFFFFFFFF);
                    in.setInputType(InputType.TYPE_CLASS_NUMBER |
                            InputType.TYPE_NUMBER_FLAG_DECIMAL |
                            InputType.TYPE_NUMBER_FLAG_SIGNED);
                    AlertDialog ed = new AlertDialog.Builder(this)
                            .setTitle(String.format("Editar 0x%08X", targetAddr))
                            .setView(in)
                            .setPositiveButton("OK", (d2, w2) -> {
                                String s = in.getText().toString().trim();
                                byte[] b = parseToBytes(s, type, size);
                                if (b == null) { toast("Valor inválido"); return; }
                                if (nativeWriteMemory(targetAddr, b)) toast("Escrito");
                                else toast("Falha");
                            })
                            .setNegativeButton("Cancelar", null)
                            .create();
                    if (ed.getWindow() != null) ed.getWindow().setType(OVERLAY_TYPE);
                    ed.show();
                })
                .setNegativeButton("Congelar alvo", (d, w) -> {
                    byte[] b = parseToBytes(preview, type, size);
                    if (b == null) { toast("Preview inválido"); return; }
                    long lv = 0;
                    for (int i = 0; i < b.length; i++)
                        lv |= ((long)(b[i] & 0xFF)) << (i * 8);
                    nativeToggleFreeze(targetAddr, lv, type, true);
                    toast("Alvo congelado");
                })
                .setNeutralButton("Ao redor", (d, w) -> showVicinityAt(targetAddr))
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();

    }

    private void trySavePointerPath(long ptrAddr, long targetAddr) {
        String mod = nativeFindModuleForAddr(ptrAddr);
        if (mod == null || mod.isEmpty()) {
            toast("Pointer não está em módulo file-backed");
            return;
        }
        long base = nativeGetModuleBase(mod);
        if (base == 0) { toast("Base do módulo não encontrada"); return; }

        PointerPath pp = new PointerPath();
        pp.module = mod;
        pp.baseOffset = ptrAddr - base;
        pp.offsets = new int[]{0};

        // Verifica se resolve igual
        long resolved = nativeResolvePointerPath(base + pp.baseOffset, pp.offsets);
        if (resolved != targetAddr) {
            toast("Path não resolve (0x" + Long.toHexString(resolved) + " ≠ 0x"
                    + Long.toHexString(targetAddr) + ")");
            return;
        }
        pointerPaths.add(pp);
        toast("Path salvo: " + mod + "+0x" + Long.toHexString(pp.baseOffset));
    }

    // ============================================================
    //  Vicinity
    // ============================================================
    private void showVicinity() {
        List<Integer> positions = getCheckedPositions();
        if (positions.isEmpty()) {
            toast("Marque um endereço para explorar");
            return;
        }
        int pos = positions.get(0);
        if (pos < 0 || pos >= displayItems.size()) return;
        long target = extractAddress(displayItems.get(pos));
        if (target == -1) { toast("Endereço inválido"); return; }
        showVicinityAt(target);
    }

    private void showVicinityAt(long target) {
        final int RANGE = 128;
        long start = Math.max(0, target - RANGE);
        int size = RANGE * 2;

        byte[] data = nativeReadRegion(start, size);
        if (data == null || data.length == 0) {
            toast("Não foi possível ler a região");
            return;
        }

        final int type = lastScanType;
        final int tsize = getTypeSize(type);

        LinearLayout titleRow = new LinearLayout(this);
        titleRow.setOrientation(LinearLayout.HORIZONTAL);
        titleRow.setBackgroundColor(0xFF222222);
        titleRow.setPadding(16, 8, 16, 8);

        TextView lblType = new TextView(this);
        lblType.setText("Ver como: ");
        lblType.setTextColor(0xFFFFFFFF);
        titleRow.addView(lblType);

        final int[] viewType = { type };
        Button btnViewType = new Button(this);
        btnViewType.setText(TYPE_NAMES[type]);
        titleRow.addView(btnViewType);

        TextView lblInfo = new TextView(this);
        lblInfo.setText(String.format("   Alvo: 0x%08X", target));
        lblInfo.setTextColor(0xFFFFAA00);
        lblInfo.setTypeface(Typeface.MONOSPACE);
        titleRow.addView(lblInfo);

        final LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setBackgroundColor(0xFF000000);
        container.setPadding(8, 8, 8, 8);

        final long fStart = start;
        final byte[] fData = data;
        final long fTarget = target;

        final MemoryScannerService svc = MemoryScannerService.this;

        Runnable rebuild = new Runnable() {
            @Override public void run() {
                container.removeAllViews();
                int step = tsize;
                int n = fData.length;

                for (int off = 0; off + step <= n; off += step) {
                    final int fOff = off;
                    long lineAddr = fStart + off;

                    LinearLayout row = new LinearLayout(svc);
                    row.setOrientation(LinearLayout.HORIZONTAL);
                    if (lineAddr <= fTarget && fTarget < lineAddr + step) {
                        row.setBackgroundColor(0x33FFAA00);
                    }

                    TextView tvA = new TextView(svc);
                    tvA.setText(String.format("0x%08X", lineAddr));
                    tvA.setTextColor(0xFFFFFFFF);
                    tvA.setTypeface(Typeface.MONOSPACE);
                    tvA.setTextSize(11f);
                    tvA.setPadding(4, 4, 8, 4);
                    row.addView(tvA);

                    final long addr = lineAddr;
                    final int vt = viewType[0];
                    final byte[] slice = new byte[step];
                    System.arraycopy(fData, off, slice, 0, step);

                    String numStr = formatAs(slice, vt);

                    TextView tvV = new TextView(svc);
                    tvV.setText(numStr);
                    tvV.setTextColor(0xFFFFCC66);
                    tvV.setTypeface(Typeface.MONOSPACE);
                    tvV.setTextSize(11f);
                    tvV.setPadding(4, 4, 8, 4);
                    row.addView(tvV, new LinearLayout.LayoutParams(
                            0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

                    Button btnE = new Button(svc);
                    btnE.setText("✎");
                    btnE.setMinWidth(0);
                    btnE.setMinimumWidth(0);
                    final String currentStr = numStr;
                    btnE.setOnClickListener(v -> {
                        EditText in = new EditText(svc);
                        in.setText(currentStr);
                        in.setTextColor(0xFFFFFFFF);
                        in.setInputType(InputType.TYPE_CLASS_NUMBER |
                                InputType.TYPE_NUMBER_FLAG_DECIMAL |
                                InputType.TYPE_NUMBER_FLAG_SIGNED);
                        AlertDialog ed = new AlertDialog.Builder(svc)
                                .setTitle(String.format("Editar 0x%08X", addr))
                                .setView(in)
                                .setPositiveButton("OK", (d2, w2) -> {
                                    String s = in.getText().toString().trim();
                                    byte[] b = parseToBytes(s, vt, step);
                                    if (b == null) { toast("Valor inválido"); return; }
                                    if (nativeWriteMemory(addr, b)) {
                                        toast("Escrito");
                                        byte[] fresh = nativeReadMemory(addr, step);
                                        if (fresh != null) {
                                            System.arraycopy(fresh, 0, fData, fOff, step);
                                            tvV.setText(formatAs(fresh, vt));
                                        }
                                    } else toast("Falha");
                                })
                                .setNegativeButton("Cancelar", null)
                                .create();
                        if (ed.getWindow() != null) ed.getWindow().setType(OVERLAY_TYPE);
                        ed.show();
                    });
                    row.addView(btnE);

                    Button btnF = new Button(svc);
                    btnF.setText("❄");
                    btnF.setMinWidth(0);
                    btnF.setMinimumWidth(0);
                    btnF.setOnClickListener(v -> {
                        String s = tvV.getText().toString();
                        byte[] b = parseToBytes(s, vt, step);
                        if (b == null) { toast("Valor inválido"); return; }
                        long lv = 0;
                        for (int i = 0; i < b.length; i++)
                            lv |= ((long)(b[i] & 0xFF)) << (i * 8);
                        nativeToggleFreeze(addr, lv, vt, true);
                        toast("Congelado");
                    });
                    row.addView(btnF);

                    container.addView(row);
                }
            }
        };

        btnViewType.setOnClickListener(v -> {
            viewType[0] = (viewType[0] + 1) % TYPE_NAMES.length;
            btnViewType.setText(TYPE_NAMES[viewType[0]]);
            rebuild.run();
        });

        rebuild.run();

        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(0xFF000000);
        sv.addView(container);

        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        wrap.addView(titleRow);
        wrap.addView(sv, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("Ao redor de " + String.format("0x%08X", target))
                .setView(wrap)
                .setPositiveButton("Fechar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();
    }

    // ==================== Conversores ====================
    private String formatAs(byte[] data, int type) {
        try {
            switch (type) {
                case TYPE_BYTE:   return String.valueOf(data[0]);
                case TYPE_SHORT:  return String.valueOf((short) toLong(data, 2));
                case TYPE_INT:    return String.valueOf((int) toLong(data, 4));
                case TYPE_LONG:   return String.valueOf(toLong(data, 8));
                case TYPE_FLOAT: {
                    int bits = (int) toLong(data, 4);
                    return String.valueOf(Float.intBitsToFloat(bits));
                }
                case TYPE_DOUBLE: {
                    long bits = toLong(data, 8);
                    return String.valueOf(Double.longBitsToDouble(bits));
                }
            }
        } catch (Exception ignored) {}
        return "--";
    }

    private byte[] parseToBytes(String s, int type, int size) {
        try {
            long v;
            switch (type) {
                case TYPE_BYTE:   v = (byte) Long.parseLong(s); break;
                case TYPE_SHORT:  v = (short) Long.parseLong(s); break;
                case TYPE_INT:    v = (int) Long.parseLong(s); break;
                case TYPE_LONG:   v = Long.parseLong(s); break;
                case TYPE_FLOAT:  v = Float.floatToRawIntBits(Float.parseFloat(s)) & 0xFFFFFFFFL; break;
                case TYPE_DOUBLE: v = Double.doubleToRawLongBits(Double.parseDouble(s)); break;
                default: return null;
            }
            byte[] b = new byte[size];
            for (int i = 0; i < size; i++) b[i] = (byte)((v >> (i * 8)) & 0xFF);
            return b;
        } catch (Exception e) { return null; }
    }

    private static long toLong(byte[] b, int n) {
        long v = 0;
        for (int i = 0; i < n && i < b.length; i++)
            v |= ((long)(b[i] & 0xFF)) << (i * 8);
        return v;
    }

    private String hexToDisplay(byte[] data, int type) {
        if (data == null) return "--";
        return bytesToHex(data);
    }

    private long bytesToLong(byte[] data) { return toLong(data, data.length); }

    // ==================== Refresh ====================
    // Fora da UI thread: antes eram até 100k chamadas JNI + String.format na main (ANR).
    private void refreshDisplayValues() {
        final List<String> snap = new ArrayList<>(displayItems);
        final int defSize = getTypeSize(lastScanType);
        new Thread(() -> {
            final List<String> out = new ArrayList<>(snap.size());
            for (String item : snap) out.add(refreshItem(item, defSize));
            mainHandler.post(() -> {
                if (adapter == null || displayItems.size() != snap.size()) return;
                displayItems.clear();
                displayItems.addAll(out);
                adapter.notifyDataSetChanged();
            });
        }, "memscan-refresh").start();
    }

    private String refreshItem(String item, int defSize) {
        long addr = extractAddress(item);
        if (addr == -1) return item;
        // mantém o tamanho exibido (AoB/String têm mais de 1 byte; pointer mostra o valor lido)
        int size = defSize;
        int sp = item.lastIndexOf(' ');
        if (sp >= 0) {
            String tok = item.substring(sp + 1);
            if (tok.length() >= 2 && tok.length() % 2 == 0 && tok.length() <= 64
                    && tok.matches("[0-9A-Fa-f]+")) size = tok.length() / 2;
        }
        byte[] data = nativeReadMemory(addr, size);
        if (data == null) return item;
        if (isPointerResult(item)) {
            int sp2 = item.indexOf(' ');
            String lvl = sp2 > 1 ? item.substring(1, sp2) : "0";
            return "L" + lvl + " 0x" + addrHex(addr) + "  →  " + bytesToHex(data);
        }
        return formatItem(addr, data);
    }

    private int getTypeSize(int type) {
        switch (type) {
            case TYPE_BYTE:   return 1;
            case TYPE_SHORT:  return 2;
            case TYPE_INT:    return 4;
            case TYPE_LONG:   return 8;
            case TYPE_FLOAT:  return 4;
            case TYPE_DOUBLE: return 8;
            default:          return 4;
        }
    }

    // ==================== Validação ====================
    private boolean validateInput(int type) {
        if (!validateOne(editValue, type)) return false;
        if (currentCondition == COND_RANGE && !validateOne(editValue2, type))
            return false;
        return true;
    }

    private boolean validateOne(EditText et, int type) {
        if (et == null) return false;
        String val = et.getText().toString().trim();
        if (TextUtils.isEmpty(val)) { toast("Digite um valor"); return false; }
        try {
            if (type == TYPE_FLOAT) {
                float f = Float.parseFloat(val);
                if (Float.isNaN(f) || Float.isInfinite(f)) throw new NumberFormatException();
            } else if (type == TYPE_DOUBLE) {
                double d = Double.parseDouble(val);
                if (Double.isNaN(d) || Double.isInfinite(d)) throw new NumberFormatException();
            } else {
                long v = Long.parseLong(val);
                long min, max;
                switch (type) {
                    case TYPE_BYTE:  min = -128;              max = 255;               break;
                    case TYPE_SHORT: min = Short.MIN_VALUE;   max = Short.MAX_VALUE;   break;
                    case TYPE_INT:   min = Integer.MIN_VALUE; max = Integer.MAX_VALUE; break;
                    default:         min = Long.MIN_VALUE;    max = Long.MAX_VALUE;    break;
                }
                if (v < min || v > max) {
                    // antes o valor era truncado em silêncio (ex.: Int 5000000000)
                    toast("Fora da faixa de " + TYPE_NAMES[type] + " (" + min + " a " + max + ")");
                    return false;
                }
            }
        } catch (NumberFormatException e) {
            toast("Valor inválido");
            return false;
        }
        return true;
    }

    private long parseOne(EditText et, int type) {
        String val = et.getText().toString().trim();
        if (type == TYPE_FLOAT) {
            float f = Float.parseFloat(val);
            return Float.floatToRawIntBits(f) & 0xFFFFFFFFL;
        } else if (type == TYPE_DOUBLE) {
            double d = Double.parseDouble(val);
            return Double.doubleToRawLongBits(d);
        } else return Long.parseLong(val);
    }

    private byte[] convertValueToBytes(long value, int type) {
        int size = getTypeSize(type);
        if (size <= 0) return null;
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) data[i] = (byte)((value >> (i * 8)) & 0xFF);
        return data;
    }

    private long extractAddress(String display) {
        if (display == null || display.isEmpty()) return -1;
        try {
            int start = display.indexOf("0x");
            if (start < 0) return -1;
            int end = start + 2;
            while (end < display.length()) {
                char c = display.charAt(end);
                if ((c >= '0' && c <= '9') ||
                    (c >= 'A' && c <= 'F') ||
                    (c >= 'a' && c <= 'f')) end++;
                else break;
            }
            if (end == start + 2) return -1;
            return parseHex(display.substring(start + 2, end));
        } catch (Exception e) { return -1; }
    }

    private boolean isPointerResult(String display) {
        if (display == null || display.length() < 2) return false;
        return display.charAt(0) == 'L' && Character.isDigit(display.charAt(1));
    }

    private void toast(String msg) { Toast.makeText(this, msg, Toast.LENGTH_SHORT).show(); }
    private void setStatus(String msg) { if (tvStatus != null) tvStatus.setText(msg); }

    private void updateTitle() {
        if (tvTitle == null) return;
        int total = totalAddresses.get();
        int shown = displayItems.size();
        if (total > shown)
            tvTitle.setText("Endereços: " + total + " (exibindo " + shown + ")");
        else
            tvTitle.setText("Endereços: " + total);
    }

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private static String addrHex(long a) {
        StringBuilder sb = new StringBuilder(16);
        boolean started = false;
        for (int shift = 60; shift >= 0; shift -= 4) {
            int d = (int) ((a >>> shift) & 0xF);
            if (d != 0) started = true;
            if (started || shift < 32) sb.append(HEX[d]);   // no mínimo 8 dígitos
        }
        return sb.toString();
    }

    private String formatItem(long addr, byte[] value) {
        StringBuilder sb = new StringBuilder(24);
        sb.append("0x").append(addrHex(addr)).append("  ");
        if (value != null) sb.append(bytesToHex(value));
        else sb.append("?");
        return sb.toString();
    }

    // ==================== Callbacks JNI ====================
    public void onScanProgress(final int percent) {
        mainHandler.post(() -> {
            if (progressBar != null) {
                progressBar.setVisibility(View.VISIBLE);
                progressBar.setProgress(percent);
            }
            setStatus("Scanneando... " + percent + "%");
        });
    }

    public void onScanCount(final int total) {
        mainHandler.post(() -> {
            totalAddresses.set(total);
            updateTitle();
        });
    }

    public void onScanBatch(final long[] batchAddrs, final byte[][] batchVals) {
        if (batchAddrs == null || batchAddrs.length == 0) return;
        totalAddresses.addAndGet(batchAddrs.length);

        if (displayItems.size() >= DISPLAY_LIMIT) return;

        synchronized (incomingLock) {
            int bound = Math.max(0, DISPLAY_LIMIT - incomingItems.size());
            int n = Math.min(batchAddrs.length, bound);
            for (int i = 0; i < n; i++) {
                byte[] v = (batchVals != null && i < batchVals.length) ? batchVals[i] : null;
                incomingItems.add(formatItem(batchAddrs[i], v));
            }
        }
        scheduleDrain(0);
    }

    public void onPointerBatch(final long[] addrs, final int[] levels) {
        if (addrs == null || addrs.length == 0) return;
        totalAddresses.addAndGet(addrs.length);

        if (displayItems.size() >= DISPLAY_LIMIT) return;

        synchronized (incomingLock) {
            int bound = Math.max(0, DISPLAY_LIMIT - incomingItems.size());
            int n = Math.min(addrs.length, bound);
            for (int i = 0; i < n; i++) {
                int lvl = (levels != null && i < levels.length) ? levels[i] : 0;
                byte[] v = nativeReadMemory(addrs[i], 4);
                incomingItems.add(String.format("L%d 0x%08X  →  %s",
                        lvl, addrs[i], v != null ? bytesToHex(v) : "?"));
            }
        }
        scheduleDrain(0);
    }

    public void onPointerComplete(final int totalCount) {
        mainHandler.post(() -> {
            scanActive = false;
            drainIncomingToUi();
            totalAddresses.set(totalCount);
            refinable = false;   // resultado de pointer scan não é refinável pelo Next Scan
            if (progressBar != null) progressBar.setVisibility(View.GONE);
            if (btnCancel != null) btnCancel.setEnabled(false);
            setStatus("Pointer concluído — " + totalCount + " hits"
                    + (pointerStaticOnly ? " [estáticos]" : ""));
            updateTitle();
        });
    }

    public void onScanComplete(final int totalCount, final boolean memoryExhausted) {
        mainHandler.post(() -> {
            scanActive = false;
            drainIncomingToUi();
            totalAddresses.set(totalCount);
            lastScanType = nativeGetLastScanType();
            refinable = totalCount > 0;
            if (progressBar != null) progressBar.setVisibility(View.GONE);
            if (btnCancel != null) btnCancel.setEnabled(false);
            String msg = memoryExhausted
                    ? "Parcial (sem espaço/memória) — " + totalCount + " resultados"
                    : "Scan concluído — " + totalCount + " resultados";
            setStatus(msg);
            updateTitle();
        });
    }

    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "?";
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2]     = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    // ==================== State JSON ====================
    private void saveStateToFile() {
        // Copia na UI thread e grava em outra thread (antes: JSON grande na main, sem atomicidade).
        final List<String> resultsCopy = new ArrayList<>(displayItems);
        final Map<Long, Boolean> watchCopy = new LinkedHashMap<>(watchAddrs);
        final List<PointerPath> pathsCopy = new ArrayList<>(pointerPaths);
        new Thread(() -> {
            try {
                JSONObject root = new JSONObject();
                root.put("version", 2);

                JSONArray results = new JSONArray();
                for (String it : resultsCopy) results.put(it);
                root.put("results", results);

                JSONArray watchArr = new JSONArray();
                for (Map.Entry<Long, Boolean> e : watchCopy.entrySet()) {
                    JSONObject w = new JSONObject();
                    w.put("addr", Long.toHexString(e.getKey()));
                    w.put("ptr", e.getValue());
                    watchArr.put(w);
                }
                root.put("watch", watchArr);

                JSONArray pathsArr = new JSONArray();
                for (PointerPath p : pathsCopy) {
                    JSONObject o = new JSONObject();
                    o.put("module", p.module == null ? "" : p.module);
                    o.put("base", Long.toHexString(p.baseOffset));
                    JSONArray offs = new JSONArray();
                    for (int oo : p.offsets) offs.put(oo);
                    o.put("offsets", offs);
                    pathsArr.put(o);
                }
                root.put("paths", pathsArr);

                File f   = new File(getFilesDir(), "state.json");
                File tmp = new File(getFilesDir(), "state.json.tmp");
                try (java.io.Writer fw = new java.io.OutputStreamWriter(
                        new java.io.FileOutputStream(tmp), java.nio.charset.StandardCharsets.UTF_8)) {
                    fw.write(root.toString());
                }
                if (!tmp.renameTo(f)) {
                    f.delete();
                    if (!tmp.renameTo(f)) throw new java.io.IOException("não foi possível gravar state.json");
                }
                final String msg = "Salvo: " + resultsCopy.size() + " resultados, "
                        + watchCopy.size() + " watch, " + pathsCopy.size() + " paths";
                mainHandler.post(() -> toast(msg));
            } catch (Exception e) {
                Log.e(TAG, "saveState", e);
                final String m = "Erro: " + e.getMessage();
                mainHandler.post(() -> toast(m));
            }
        }, "memscan-save").start();
    }

    private void loadStateFromFile() {
        if (scanActive) { toast("Aguarde o scan atual terminar"); return; }
        new Thread(() -> {
            try {
                File f = new File(getFilesDir(), "state.json");
                if (!f.exists()) { mainHandler.post(() -> toast("state.json não encontrado")); return; }
                StringBuilder sb = new StringBuilder();
                try (BufferedReader br = new BufferedReader(new java.io.InputStreamReader(
                        new java.io.FileInputStream(f), java.nio.charset.StandardCharsets.UTF_8))) {
                    char[] buf = new char[8192];
                    int n;
                    while ((n = br.read(buf)) > 0) sb.append(buf, 0, n);
                }
                JSONObject root = new JSONObject(sb.toString());

                final List<String> items = new ArrayList<>();
                JSONArray results = root.optJSONArray("results");
                if (results != null) {
                    for (int i = 0; i < results.length() && items.size() < DISPLAY_LIMIT; i++)
                        items.add(results.getString(i));
                }

                Map<Long, Boolean> watchLoaded = null;
                JSONArray watchArr = root.optJSONArray("watch");
                if (watchArr != null) {
                    watchLoaded = new LinkedHashMap<>();
                    for (int i = 0; i < watchArr.length(); i++) {
                        JSONObject w = watchArr.getJSONObject(i);
                        watchLoaded.put(parseHex(w.getString("addr")), w.optBoolean("ptr", false));
                    }
                }

                List<PointerPath> pathsLoaded = null;
                JSONArray pathsArr = root.optJSONArray("paths");
                if (pathsArr != null) {
                    pathsLoaded = new ArrayList<>();
                    for (int i = 0; i < pathsArr.length(); i++) {
                        JSONObject o = pathsArr.getJSONObject(i);
                        PointerPath p = new PointerPath();
                        p.module = o.optString("module", "");
                        p.baseOffset = parseHex(o.getString("base"));
                        JSONArray offs = o.getJSONArray("offsets");
                        p.offsets = new int[offs.length()];
                        for (int j = 0; j < offs.length(); j++) p.offsets[j] = offs.getInt(j);
                        pathsLoaded.add(p);
                    }
                }

                final Map<Long, Boolean> fw = watchLoaded;
                final List<PointerPath> fp = pathsLoaded;
                mainHandler.post(() -> {
                    resetResults();
                    displayItems.addAll(items);
                    totalAddresses.set(items.size());
                    if (adapter != null) adapter.notifyDataSetChanged();
                    // A lista carregada é só visual: o nativo não tem esses endereços,
                    // então o Next Scan fica desabilitado até um Novo Scan.
                    refinable = false;
                    updateTitle();
                    if (fw != null) { watchAddrs.clear(); watchAddrs.putAll(fw); saveWatch(); }
                    if (fp != null) { pointerPaths.clear(); pointerPaths.addAll(fp); }
                    toast("Carregado: " + items.size() + " resultados, "
                            + watchAddrs.size() + " watch, " + pointerPaths.size() + " paths");
                });
            } catch (Exception e) {
                Log.e(TAG, "loadState", e);
                final String m = "Erro: " + e.getMessage();
                mainHandler.post(() -> toast(m));
            }
        }, "memscan-load").start();
    }

    // ==================== API pública ====================
    public static void start(Context context) {
        ContextCompat.startForegroundService(context, new Intent(context, MemoryScannerService.class));
    }
    public static void stop(Context context) {
        context.stopService(new Intent(context, MemoryScannerService.class));
    }
}