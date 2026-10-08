package com.exemplo.scanner;

import android.app.AlertDialog;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.PixelFormat;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
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
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.core.app.NotificationCompat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
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

    // Tipos (espelham enum C++ DataType)
    private static final int TYPE_BYTE   = 0;
    private static final int TYPE_SHORT  = 1;
    private static final int TYPE_INT    = 2;
    private static final int TYPE_LONG   = 3;
    private static final int TYPE_FLOAT  = 4;
    private static final int TYPE_DOUBLE = 5;

    // Condições (espelham enum C++ ScanCondition)
    private static final int COND_EXACT   = 0;
    private static final int COND_GREATER = 1;
    private static final int COND_LESS    = 2;
    private static final int COND_RANGE   = 3;

    // Filtros (espelham RegionFilterFlags)
    private static final int RF_NONE      = 0;
    private static final int RF_RW_ONLY   = 1;
    private static final int RF_SKIP_EXEC = 2;
    private static final int RF_ANON_ONLY = 4;

    private static final String[] TYPE_NAMES   = {"Byte", "Short", "Int", "Long", "Float", "Double"};
    private static final String[] COND_NAMES   = {"Exato", "Maior", "Menor", "Faixa"};
    private static final String[] REGION_NAMES = {"Tudo", "Rápido(rw)", "Anônimo", "Sem código"};
    private static final int[]    REGION_MASKS = {RF_NONE, RF_RW_ONLY, RF_ANON_ONLY, RF_SKIP_EXEC};

    private static final int DISPLAY_LIMIT = 100_000;

    // Fila de entrada (callbacks JNI) + drain coalescido
    private final Object incomingLock = new Object();
    private final List<String> incomingItems = new ArrayList<>();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean drainScheduled = new AtomicBoolean(false);
    private volatile boolean scanActive = false;
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
    private TextView tvTitle, tvStatus;
    private EditText editValue, editValue2;
    private Button btnType, btnCondition, btnRegion;
    private int currentType = TYPE_INT;
    private int currentCondition = COND_EXACT;
    private int currentRegion = 0;
    private int lastScanType = TYPE_INT;

    private Button btnScan, btnNext, btnWrite, btnFreeze, btnClear, btnCancel,
                   btnClose, btnCloseService, btnSave, btnLoad, btnVicinity,
                   btnAoB, btnPointer, btnWatchAdd, btnWatchShow, btnFollow;
    private ArrayAdapter<String> adapter;
    private final List<String> displayItems = new ArrayList<>();
    private ProgressBar progressBar;

    // Watch list persistente
    // Mapa: endereço → isPointer (true = dereferenciar antes de ler/escrever)
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
    public native void    nativeStartScan(long value, long value2, int type, int condition);
    public native void    nativeNextScan(long value, long value2, int condition);
    public native void    nativeAoBScan(String pattern, int limit);
    public native void    nativePointerScan(long targetAddr, int maxDepth);
    public native void    nativeSetDisplayFull();
    public native void    nativeCancelScan();
    public native void    nativeClearResults();
    public native long[]  nativeGetResults();
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
        nativeSetWorkDir(getCacheDir().getAbsolutePath());
        nativeSetRegionFilter(REGION_MASKS[currentRegion]);
        loadWatch();
        startForeground(NOTIFICATION_ID, buildNotification());
        createBubble();
        MemoryScanner.getInstance().setCallback(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) { return START_STICKY; }
    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        super.onDestroy();
        MemoryScanner.getInstance().clearCallback();
        saveWatch();
        try {
            if (bubbleView != null && bubbleView.getWindowToken() != null)
                wm.removeView(bubbleView);
            if (panelView != null && panelView.getWindowToken() != null)
                wm.removeView(panelView);
        } catch (Exception ignored) {}
        nativeCancelScan();
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

    // ==================== Bubble flutuante ====================
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

    // ==================== Painel principal ====================
    private void createPanel() {
        DisplayMetrics dm = getResources().getDisplayMetrics();
        boolean landscape = dm.widthPixels > dm.heightPixels;
        int panelWidth  = (int) (dm.widthPixels * (landscape ? 0.66f : 0.94f));
        int panelHeight = (int) (dm.heightPixels * (landscape ? 0.96f : 0.92f));

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

        // Barra de arraste
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
        tvStatus.setPadding(8, 8, 8, 8);
        tvStatus.setText("Pronto");
        root.addView(tvStatus);

        // Valor principal
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

        // Valor máximo (modo Faixa)
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

        // Tipo / Cond / Região
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
        });
        row2.addView(btnRegion,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(row2);

        // Novo Scan / Next / Cancelar
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

        // Escrever / Congelar / Limpar
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

        // Salvar / Carregar / Ao redor
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

        // AoB / Pointer / Follow / Watch+ / Watch
        LinearLayout toolBar = new LinearLayout(this);
        toolBar.setOrientation(LinearLayout.HORIZONTAL);
        toolBar.setPadding(0, 4, 0, 4);
        btnAoB = new Button(this);
        btnAoB.setText("AoB");
        btnAoB.setOnClickListener(this);
        toolBar.addView(btnAoB,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnPointer = new Button(this);
        btnPointer.setText("Pointer");
        btnPointer.setOnClickListener(this);
        toolBar.addView(btnPointer,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnFollow = new Button(this);
        btnFollow.setText("🔗");
        btnFollow.setOnClickListener(this);
        toolBar.addView(btnFollow,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnWatchAdd = new Button(this);
        btnWatchAdd.setText("★ Add");
        btnWatchAdd.setOnClickListener(this);
        toolBar.addView(btnWatchAdd,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnWatchShow = new Button(this);
        btnWatchShow.setText("Watch");
        btnWatchShow.setOnClickListener(this);
        toolBar.addView(btnWatchShow,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(toolBar);

        progressBar = new ProgressBar(this);
        progressBar.setVisibility(View.GONE);
        root.addView(progressBar);

        // ListView com altura adaptativa à orientação
        listView = new ListView(this);
        int listHeight = (int) (dm.density * (landscape ? 150 : 240));
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
            saveResultsToFile();
        } else if (v == btnLoad) {
            loadResultsFromFile();
        } else if (v == btnVicinity) {
            showVicinity();
        } else if (v == btnAoB) {
            showAoBDialog();
        } else if (v == btnPointer) {
            showPointerDialog();
        } else if (v == btnFollow) {
            followPointer();
        } else if (v == btnWatchAdd) {
            addCheckedToWatch();
        } else if (v == btnWatchShow) {
            showWatchDialog();
        }
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view, int position, long id) { }

    // ==================== Drain coalescido ====================
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
        totalAddresses.set(0);
        displayFullNotified = false;
        scanActive = false;
        synchronized (incomingLock) { incomingItems.clear(); }
        displayItems.clear();
        if (adapter != null) adapter.notifyDataSetChanged();
        if (tvTitle != null) tvTitle.setText("Endereços: 0");
    }

    private void startScanInternal() {
        if (!validateInput()) return;
        long value  = parseOne(editValue,  currentType);
        long value2 = (currentCondition == COND_RANGE)
                        ? parseOne(editValue2, currentType) : value;
        if (currentCondition == COND_RANGE && value2 < value) {
            long tmp = value; value = value2; value2 = tmp;
        }

        lastScanType = currentType;
        resetResults();
        scanActive = true;
        scheduleDrain(0);

        setStatus("Scanneando...");
        btnCancel.setEnabled(true);
        progressBar.setVisibility(View.VISIBLE);
        progressBar.setIndeterminate(false);
        progressBar.setProgress(0);

        Log.i(TAG, String.format("startScan v1=%d v2=%d tipo=%d cond=%d reg=%d",
                value, value2, currentType, currentCondition, currentRegion));
        nativeStartScan(value, value2, currentType, currentCondition);
    }

    private void nextScanInternal() {
        if (!validateInput()) return;
        if (totalAddresses.get() == 0) {
            toast("Nenhum resultado. Faça um Novo Scan primeiro.");
            return;
        }
        long value  = parseOne(editValue,  lastScanType);
        long value2 = (currentCondition == COND_RANGE)
                        ? parseOne(editValue2, lastScanType) : value;
        if (currentCondition == COND_RANGE && value2 < value) {
            long tmp = value; value = value2; value2 = tmp;
        }

        resetResults();
        scanActive = true;
        scheduleDrain(0);

        setStatus("Refinando...");
        btnCancel.setEnabled(true);
        progressBar.setVisibility(View.VISIBLE);
        progressBar.setIndeterminate(false);
        progressBar.setProgress(0);

        Log.i(TAG, String.format("nextScan v1=%d v2=%d cond=%d",
                value, value2, currentCondition));
        nativeNextScan(value, value2, currentCondition);
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
        if (!validateInput()) return;
        int type = currentType;
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
        if (!validateInput()) return;
        int type = currentType;
        long value = parseOne(editValue, type);
        for (int pos : positions) {
            if (pos < 0 || pos >= displayItems.size()) continue;
            long addr = extractAddress(displayItems.get(pos));
            if (addr != -1) nativeToggleFreeze(addr, value, type, true);
        }
        toast("Freeze ativado para " + positions.size() + " endereço(s)");
    }

    // ============================================================
    //  AoB — diálogo e disparo
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
                    resetResults();
                    scanActive = true;
                    scheduleDrain(0);
                    setStatus("AoB scan...");
                    btnCancel.setEnabled(true);
                    progressBar.setVisibility(View.VISIBLE);
                    progressBar.setProgress(0);
                    Log.i(TAG, "AoB pattern: " + pat);
                    nativeAoBScan(pat, DISPLAY_LIMIT);
                })
                .setNegativeButton("Cancelar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();
    }

    // ============================================================
    //  Pointer scan — diálogo e disparo
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
        input.setInputType(InputType.TYPE_CLASS_TEXT |
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);

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

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("Pointer Scan")
                .setView(wrap)
                .setPositiveButton("Escanear", (d, w) -> {
                    String s = input.getText().toString().trim();
                    if (s.isEmpty()) { toast("Digite um endereço"); return; }
                    long target;
                    try {
                        target = s.startsWith("0x") || s.startsWith("0X")
                                ? Long.parseLong(s.substring(2), 16)
                                : Long.parseLong(s);
                    } catch (NumberFormatException e) {
                        toast("Endereço inválido"); return;
                    }
                    int depth;
                    try { depth = Integer.parseInt(depthIn.getText().toString().trim()); }
                    catch (Exception e) { depth = 2; }
                    if (depth < 1) depth = 1;
                    if (depth > 4) depth = 4;

                    resetResults();
                    scanActive = true;
                    scheduleDrain(0);
                    setStatus("Pointer scan...");
                    btnCancel.setEnabled(true);
                    progressBar.setVisibility(View.VISIBLE);
                    progressBar.setProgress(0);
                    Log.i(TAG, "Pointer target=0x" + Long.toHexString(target) + " depth=" + depth);
                    nativePointerScan(target, depth);
                })
                .setNegativeButton("Cancelar", null)
                .create();
        if (dlg.getWindow() != null) dlg.getWindow().setType(OVERLAY_TYPE);
        dlg.show();
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
    //  Watch list — exibir
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

            boolean isPtr = Boolean.TRUE.equals(watchAddrs.get(addr));
            long readAt = addr;
            String chain = "";

            if (isPtr) {
                byte[] pdata = nativeReadMemory(addr, 4);
                if (pdata != null) {
                    long targetAddr = bytesToLong(pdata);
                    readAt = targetAddr;
                    chain = String.format("→ 0x%08X  ", targetAddr);
                } else {
                    chain = "(falha ptr) ";
                    readAt = -1;
                }
            }

            byte[] data = (readAt >= 0) ? nativeReadMemory(readAt, size) : null;
            String valStr = chain;
            long currentVal = 0;
            if (data != null) {
                valStr += hexToDisplay(data, type);
                currentVal = bytesToLong(data);
            } else {
                valStr += "--";
            }
            final long curVal = currentVal;
            final long writeAt = (isPtr ? readAt : addr);
            final String typeName = TYPE_NAMES[type];

            TextView tvVal = new TextView(this);
            tvVal.setText(valStr);
            tvVal.setTextColor(0xFFFFFFFF);
            tvVal.setTypeface(Typeface.MONOSPACE);
            tvVal.setPadding(0, 8, 8, 8);
            row.addView(tvVal, new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.2f));

            Button btnEdit = new Button(this);
            btnEdit.setText("✎");
            btnEdit.setMinWidth(0);
            btnEdit.setMinimumWidth(0);
            btnEdit.setPadding(4, 0, 4, 0);
            btnEdit.setOnClickListener(view -> {
                if (writeAt < 0) { toast("Endereço inválido"); return; }
                EditText in = new EditText(MemoryScannerService.this);
                in.setText(String.valueOf(curVal));
                in.setTextColor(0xFFFFFFFF);
                in.setInputType(InputType.TYPE_CLASS_NUMBER |
                        InputType.TYPE_NUMBER_FLAG_DECIMAL |
                        InputType.TYPE_NUMBER_FLAG_SIGNED);
                AlertDialog ed = new AlertDialog.Builder(MemoryScannerService.this)
                        .setTitle(String.format("Editar 0x%08X (%s)", writeAt, typeName))
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
                            } catch (Exception e) {
                                toast("Valor inválido"); return;
                            }
                            byte[] b = convertValueToBytes(parsedVal, type);
                            if (b != null && nativeWriteMemory(writeAt, b))
                                toast("Escrito em " + String.format("0x%08X", writeAt));
                            else toast("Falha ao escrever");
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
                for (int j = 0; j < r.getChildCount(); j++) {
                    r.getChildAt(j).setTag(dlg);
                }
            }
        }
    }

    // ============================================================
    //  Watch list — persistência
    // ============================================================
    private void saveWatch() {
        try {
            File f = new File(getFilesDir(), "watch.txt");
            FileWriter fw = new FileWriter(f);
            for (Map.Entry<Long, Boolean> e : watchAddrs.entrySet()) {
                fw.write(Long.toHexString(e.getKey()) + ":" +
                         (e.getValue() ? "1" : "0") + "\n");
            }
            fw.close();
        } catch (IOException e) {
            Log.e(TAG, "saveWatch", e);
        }
    }

    private void loadWatch() {
        try {
            File f = new File(getFilesDir(), "watch.txt");
            if (!f.exists()) return;
            BufferedReader br = new BufferedReader(new FileReader(f));
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                try {
                    String[] parts = line.split(":");
                    long a = Long.parseLong(parts[0], 16);
                    boolean p = parts.length > 1 && "1".equals(parts[1]);
                    watchAddrs.put(a, p);
                } catch (NumberFormatException ignored) {}
            }
            br.close();
            Log.i(TAG, "Watch carregada: " + watchAddrs.size());
        } catch (IOException e) {
            Log.e(TAG, "loadWatch", e);
        }
    }

    // ============================================================
    //  Seguir pointer — dereferencia e oferece ações no alvo
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

        byte[] ptrData = nativeReadMemory(ptrAddr, 4);
        if (ptrData == null) { toast("Falha ao ler o pointer"); return; }
        final long targetAddr = bytesToLong(ptrData);
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

        TextView infoTipo = new TextView(this);
        infoTipo.setText("\nTipo: " + TYPE_NAMES[type]);
        infoTipo.setTextColor(0xFFAAAAAA);
        wrap.addView(infoTipo);

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

    // ============================================================
    //  Ao redor (vicinity)
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
                    btnE.setPadding(6, 0, 6, 0);
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
                    btnF.setPadding(6, 0, 6, 0);
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

    // ==================== Conversores para a UI ====================
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
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private long bytesToLong(byte[] data) { return toLong(data, data.length); }

    // ==================== Refresh da lista ====================
    private void refreshDisplayValues() {
        List<String> newItems = new ArrayList<>(displayItems.size());
        int type = lastScanType;
        int size = getTypeSize(type);
        for (String item : displayItems) {
            long addr = extractAddress(item);
            if (addr != -1) {
                byte[] data = nativeReadMemory(addr, size);
                if (data != null)
                    newItems.add(String.format("0x%08X  %s", addr, bytesToHex(data)));
                else newItems.add(item);
            } else newItems.add(item);
        }
        displayItems.clear();
        displayItems.addAll(newItems);
        adapter.notifyDataSetChanged();
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
    private boolean validateInput() {
        if (!validateOne(editValue, currentType)) return false;
        if (currentCondition == COND_RANGE && !validateOne(editValue2, currentType))
            return false;
        return true;
    }

    private boolean validateOne(EditText et, int type) {
        if (et == null) return false;
        String val = et.getText().toString().trim();
        if (TextUtils.isEmpty(val)) { toast("Digite um valor"); return false; }
        try {
            if (type == TYPE_FLOAT)        Float.parseFloat(val);
            else if (type == TYPE_DOUBLE)  Double.parseDouble(val);
            else                            Long.parseLong(val);
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
                    (c >= 'a' && c <= 'f')) {
                    end++;
                } else break;
            }
            if (end == start + 2) return -1;
            return Long.parseLong(display.substring(start + 2, end), 16);
        } catch (Exception e) { return -1; }
    }

    private boolean isPointerResult(String display) {
        if (display == null || display.length() < 2) return false;
        return display.charAt(0) == 'L' &&
               Character.isDigit(display.charAt(1));
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

    private String formatItem(long addr, byte[] value) {
        StringBuilder sb = new StringBuilder(24);
        sb.append(String.format("0x%08X", addr)).append("  ");
        if (value != null) for (byte b : value) sb.append(String.format("%02X", b));
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
            int bound = Math.max(0, DISPLAY_LIMIT * 2 - incomingItems.size());
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
            int bound = Math.max(0, DISPLAY_LIMIT * 2 - incomingItems.size());
            int n = Math.min(addrs.length, bound);
            for (int i = 0; i < n; i++) {
                int lvl = (levels != null && i < levels.length) ? levels[i] : 0;
                byte[] v = nativeReadMemory(addrs[i], 4);
                incomingItems.add(String.format("L%d 0x%08X  →  %s",
                        lvl, addrs[i],
                        v != null ? bytesToHex(v) : "?"));
            }
        }
        scheduleDrain(0);
    }

    public void onPointerComplete(final int totalCount) {
        mainHandler.post(() -> {
            scanActive = false;
            drainIncomingToUi();
            totalAddresses.set(totalCount);
            if (progressBar != null) progressBar.setVisibility(View.GONE);
            if (btnCancel != null) btnCancel.setEnabled(false);
            setStatus("Pointer concluído — " + totalCount + " hits");
            updateTitle();
        });
    }

    public void onScanComplete(final int totalCount, final boolean memoryExhausted) {
        mainHandler.post(() -> {
            scanActive = false;
            drainIncomingToUi();
            totalAddresses.set(totalCount);
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
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    // ==================== Salvar / carregar resultados ====================
    private void saveResultsToFile() {
        try {
            File file = new File(getFilesDir(), "results.txt");
            FileWriter fw = new FileWriter(file);
            for (String item : displayItems) fw.write(item + "\n");
            fw.close();
            toast("Salvos " + displayItems.size());
        } catch (IOException e) {
            Log.e(TAG, "Erro ao salvar", e);
            toast("Erro: " + e.getMessage());
        }
    }

    private void loadResultsFromFile() {
        try {
            File file = new File(getFilesDir(), "results.txt");
            if (!file.exists()) { toast("Arquivo não encontrado"); return; }
            BufferedReader br = new BufferedReader(new FileReader(file));
            displayItems.clear();
            String line;
            while ((line = br.readLine()) != null) displayItems.add(line);
            br.close();
            totalAddresses.set(displayItems.size());
            adapter.notifyDataSetChanged();
            updateTitle();
            toast("Carregados " + displayItems.size());
        } catch (IOException e) {
            Log.e(TAG, "Erro ao carregar", e);
            toast("Erro: " + e.getMessage());
        }
    }

    // ==================== API pública ====================
    public static void start(Context context) {
        context.startService(new Intent(context, MemoryScannerService.class));
    }
    public static void stop(Context context) {
        context.stopService(new Intent(context, MemoryScannerService.class));
    }
}