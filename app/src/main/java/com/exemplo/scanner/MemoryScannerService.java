package com.exemplo.scanner;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.PixelFormat;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import android.util.SparseBooleanArray;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.*;
import androidx.core.app.NotificationCompat;
import com.google.android.material.snackbar.Snackbar;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class MemoryScannerService extends Service
        implements AdapterView.OnItemClickListener, View.OnClickListener {

    private static final String TAG = "MemScannerService";
    private static final String CHANNEL_ID = "memory_scanner_channel";
    private static final int NOTIFICATION_ID = 1001;

    private WindowManager wm;
    private View bubbleView, panelView;
    private WindowManager.LayoutParams bubbleParams, panelParams;
    private boolean expanded = false;

    private ListView listView;
    private TextView tvTitle, tvStatus;
    private EditText editValue;
    private Spinner spinnerType, spinnerCondition;
    private Button btnScan, btnNext, btnWrite, btnFreeze, btnClear, btnCancel, btnClose, btnCloseService, btnSave, btnLoad;
    private ArrayAdapter<String> adapter;
    private List<String> displayItems = new ArrayList<>();
    private ProgressBar progressBar;

    private static final int OVERLAY_TYPE =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                    : WindowManager.LayoutParams.TYPE_PHONE;

    static {
        System.loadLibrary("memscanner");
    }

    // Métodos nativos
    public native void nativeStartScan(int value, int type, int condition);
    public native void nativeNextScan(int value, int condition);
    public native void nativeCancelScan();
    public native void nativeClearResults();
    public native long[] nativeGetResults();
    public native boolean nativeWriteMemory(long address, byte[] data);
    public native void nativeToggleFreeze(long address, int value, int type, boolean enable);
    public native byte[] nativeReadMemory(long address, int size);

    @Override
    public void onCreate() {
        super.onCreate();
        wm = (WindowManager) getSystemService(WINDOW_SERVICE);
        createNotificationChannel();
        startForeground(NOTIFICATION_ID, buildNotification());
        createBubble();
        MemoryScanner.getInstance().setCallback(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        MemoryScanner.getInstance().clearCallback();
        if (bubbleView != null && bubbleView.getWindowToken() != null)
            wm.removeView(bubbleView);
        if (panelView != null && panelView.getWindowToken() != null)
            wm.removeView(panelView);
        nativeCancelScan();
        nativeClearResults(); // também para o freeze
        stopForeground(true);
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Memory Scanner",
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Mantém o serviço em execução");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
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

    // ======================== INTERFACE ========================

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
        makeDraggable(bubbleView, bubbleParams, this::toggleExpanded);
    }

    private void makeDraggable(View v, WindowManager.LayoutParams params, Runnable onTap) {
        v.setOnTouchListener(new View.OnTouchListener() {
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
                            wm.updateViewLayout(v, params);
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

    private void createPanel() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(16, 16, 16, 16);
        root.setBackgroundColor(0xEE222222);
        root.setElevation(10f);

        // Título
        tvTitle = new TextView(this);
        tvTitle.setTextSize(18f);
        tvTitle.setTextColor(0xFFFFFFFF);
        tvTitle.setPadding(8, 8, 8, 8);
        tvTitle.setText("Memory Scanner");
        root.addView(tvTitle);

        // Barra de arrasto e fechamento
        LinearLayout dragBar = new LinearLayout(this);
        dragBar.setOrientation(LinearLayout.HORIZONTAL);
        dragBar.setBackgroundColor(0xFF333333);
        TextView dragLabel = new TextView(this);
        dragLabel.setText("⇅ Arraste");
        dragLabel.setTextColor(0xFFAAAAAA);
        dragLabel.setPadding(12, 8, 12, 8);
        dragBar.addView(dragLabel, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnCloseService = new Button(this);
        btnCloseService.setText("Fechar");
        btnCloseService.setOnClickListener(v -> stopSelf());
        dragBar.addView(btnCloseService);
        btnClose = new Button(this);
        btnClose.setText("Minimizar");
        btnClose.setOnClickListener(this);
        dragBar.addView(btnClose);
        root.addView(dragBar);

        // Status
        tvStatus = new TextView(this);
        tvStatus.setTextColor(0xFFFFFFFF);
        tvStatus.setPadding(8, 8, 8, 8);
        tvStatus.setText("Pronto");
        root.addView(tvStatus);

        // Input: Valor
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
        row1.addView(editValue, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(row1);

        // Tipo e condição
        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        row2.setPadding(0, 4, 0, 4);
        TextView lblTipo = new TextView(this);
        lblTipo.setText("Tipo:");
        lblTipo.setTextColor(0xFFFFFFFF);
        lblTipo.setPadding(0, 0, 8, 0);
        row2.addView(lblTipo);
        spinnerType = new Spinner(this);
        String[] types = {"Byte", "Short", "Int", "Long", "Float", "Double"};
        ArrayAdapter<String> typeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, types);
        typeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerType.setAdapter(typeAdapter);
        spinnerType.setSelection(2);
        row2.addView(spinnerType, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f));

        TextView lblCond = new TextView(this);
        lblCond.setText("  Cond:");
        lblCond.setTextColor(0xFFFFFFFF);
        lblCond.setPadding(8, 0, 8, 0);
        row2.addView(lblCond);
        spinnerCondition = new Spinner(this);
        String[] conds = {"Exato", "Maior", "Menor"};
        ArrayAdapter<String> condAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, conds);
        condAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerCondition.setAdapter(condAdapter);
        row2.addView(spinnerCondition, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f));
        root.addView(row2);

        // Botões de scan
        LinearLayout scanBar = new LinearLayout(this);
        scanBar.setOrientation(LinearLayout.HORIZONTAL);
        scanBar.setPadding(0, 8, 0, 8);
        btnScan = new Button(this);
        btnScan.setText("Novo Scan");
        btnScan.setOnClickListener(this);
        scanBar.addView(btnScan, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnNext = new Button(this);
        btnNext.setText("Next");
        btnNext.setOnClickListener(this);
        scanBar.addView(btnNext, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnCancel = new Button(this);
        btnCancel.setText("Cancelar");
        btnCancel.setOnClickListener(this);
        btnCancel.setEnabled(false);
        scanBar.addView(btnCancel, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(scanBar);

        // Botões de ação
        LinearLayout actionBar = new LinearLayout(this);
        actionBar.setOrientation(LinearLayout.HORIZONTAL);
        actionBar.setPadding(0, 4, 0, 8);
        btnWrite = new Button(this);
        btnWrite.setText("Escrever");
        btnWrite.setOnClickListener(this);
        actionBar.addView(btnWrite, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnFreeze = new Button(this);
        btnFreeze.setText("Congelar");
        btnFreeze.setOnClickListener(this);
        actionBar.addView(btnFreeze, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnClear = new Button(this);
        btnClear.setText("Limpar");
        btnClear.setOnClickListener(this);
        actionBar.addView(btnClear, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(actionBar);

        // Botões extras: salvar/carregar
        LinearLayout extraBar = new LinearLayout(this);
        extraBar.setOrientation(LinearLayout.HORIZONTAL);
        btnSave = new Button(this);
        btnSave.setText("Salvar");
        btnSave.setOnClickListener(this);
        extraBar.addView(btnSave, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnLoad = new Button(this);
        btnLoad.setText("Carregar");
        btnLoad.setOnClickListener(this);
        extraBar.addView(btnLoad, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(extraBar);

        progressBar = new ProgressBar(this);
        progressBar.setVisibility(View.GONE);
        root.addView(progressBar);

        // ListView
        listView = new ListView(this);
        listView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 500));
        listView.setBackgroundColor(0xFF444444);
        listView.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE);
        root.addView(listView);

        adapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_multiple_choice, displayItems);
        listView.setAdapter(adapter);
        listView.setOnItemClickListener(this);

        panelView = root;

        panelParams = new WindowManager.LayoutParams(
                (int) (getResources().getDisplayMetrics().widthPixels * 0.92f),
                WindowManager.LayoutParams.WRAP_CONTENT,
                OVERLAY_TYPE,
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
                PixelFormat.TRANSLUCENT);
        panelParams.gravity = Gravity.TOP | Gravity.START;
        panelParams.x = 20;
        panelParams.y = 150;

        makeDraggable(dragLabel, panelParams, () -> {});
    }

    // ======================== EVENTOS ========================

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
            displayItems.clear();
            adapter.notifyDataSetChanged();
            tvTitle.setText("Endereços: 0");
            setStatus("Resultados limpos");
            // (Opcional: limpar arquivo salvo se desejar)
        } else if (v == btnSave) {
            saveResultsToFile();
        } else if (v == btnLoad) {
            loadResultsFromFile();
        }
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
        listView.setItemChecked(position, !listView.isItemChecked(position));
    }

    // ======================== LÓGICA INTERNA ========================

    private void startScanInternal() {
        if (!validateInput()) return;
        int value = parseValue();
        int type = spinnerType.getSelectedItemPosition();
        int condition = spinnerCondition.getSelectedItemPosition();

        setStatus("Scanneando...");
        btnCancel.setEnabled(true);
        progressBar.setVisibility(View.VISIBLE);
        progressBar.setIndeterminate(false);
        progressBar.setProgress(0);

        nativeStartScan(value, type, condition);
    }

    private void nextScanInternal() {
        if (!validateInput()) return;
        int value = parseValue();
        int condition = spinnerCondition.getSelectedItemPosition();

        setStatus("Refinando...");
        btnCancel.setEnabled(true);
        progressBar.setVisibility(View.VISIBLE);
        progressBar.setIndeterminate(false);
        progressBar.setProgress(0);

        nativeNextScan(value, condition);
    }

    private List<Integer> getCheckedPositions() {
        SparseBooleanArray checked = listView.getCheckedItemPositions();
        List<Integer> positions = new ArrayList<>();
        for (int i = 0; i < checked.size(); i++) {
            if (checked.valueAt(i)) {
                positions.add(checked.keyAt(i));
            }
        }
        return positions;
    }

    private void writeSelected() {
        List<Integer> positions = getCheckedPositions();
        if (positions.isEmpty()) {
            toast("Selecione pelo menos um endereço");
            return;
        }
        if (!validateInput()) return;
        int type = spinnerType.getSelectedItemPosition();
        byte[] data = convertValueToBytes(parseValue(), type);
        if (data == null) {
            toast("Erro na conversão do valor");
            return;
        }

        for (int pos : positions) {
            String item = displayItems.get(pos);
            long addr = extractAddress(item);
            if (addr != -1) {
                nativeWriteMemory(addr, data);
            }
        }
        toast("Escrita concluída para " + positions.size() + " endereço(s)");
        // Atualiza a lista com os novos valores (opcional)
        refreshDisplayValues();
    }

    private void freezeSelected() {
        List<Integer> positions = getCheckedPositions();
        if (positions.isEmpty()) {
            toast("Selecione pelo menos um endereço");
            return;
        }
        if (!validateInput()) return;
        int type = spinnerType.getSelectedItemPosition();
        int value = parseValue();

        for (int pos : positions) {
            String item = displayItems.get(pos);
            long addr = extractAddress(item);
            if (addr != -1) {
                nativeToggleFreeze(addr, value, type, true);
            }
        }
        toast("Freeze ativado para " + positions.size() + " endereço(s)");
    }

    private void refreshDisplayValues() {
        // Lê os valores atuais de todos os endereços e atualiza a lista
        List<String> newItems = new ArrayList<>();
        for (String item : displayItems) {
            long addr = extractAddress(item);
            if (addr != -1) {
                int type = spinnerType.getSelectedItemPosition();
                byte[] data = nativeReadMemory(addr, getTypeSize(type));
                if (data != null) {
                    String hexAddr = String.format("0x%08X", addr);
                    String val = bytesToHex(data);
                    newItems.add(hexAddr + "  " + val);
                } else {
                    newItems.add(item); // mantém antigo se falhar
                }
            } else {
                newItems.add(item);
            }
        }
        displayItems.clear();
        displayItems.addAll(newItems);
        adapter.notifyDataSetChanged();
    }

    private int getTypeSize(int type) {
        switch (type) {
            case TYPE_BYTE: return 1;
            case TYPE_SHORT: return 2;
            case TYPE_INT: return 4;
            case TYPE_LONG: return 8;
            case TYPE_FLOAT: return 4;
            case TYPE_DOUBLE: return 8;
            default: return 4;
        }
    }

    private boolean validateInput() {
        String val = editValue.getText().toString().trim();
        if (TextUtils.isEmpty(val)) {
            toast("Digite um valor");
            return false;
        }
        int type = spinnerType.getSelectedItemPosition();
        if (type == TYPE_FLOAT || type == TYPE_DOUBLE) {
            try {
                Double.parseDouble(val);
            } catch (NumberFormatException e) {
                toast("Valor inválido para float/double");
                return false;
            }
        } else {
            try {
                Long.parseLong(val);
            } catch (NumberFormatException e) {
                toast("Valor inteiro inválido");
                return false;
            }
        }
        return true;
    }

    private int parseValue() {
        String val = editValue.getText().toString().trim();
        int type = spinnerType.getSelectedItemPosition();
        if (type == TYPE_FLOAT || type == TYPE_DOUBLE) {
            double d = Double.parseDouble(val);
            return (int) Double.doubleToLongBits(d);
        } else {
            return (int) Long.parseLong(val);
        }
    }

    private byte[] convertValueToBytes(long value, int type) {
        byte[] data = null;
        switch (type) {
            case TYPE_BYTE:
                data = new byte[]{(byte) value};
                break;
            case TYPE_SHORT:
                data = new byte[2];
                for (int i = 0; i < 2; i++) data[i] = (byte) ((value >> (i * 8)) & 0xFF);
                break;
            case TYPE_INT:
                data = new byte[4];
                for (int i = 0; i < 4; i++) data[i] = (byte) ((value >> (i * 8)) & 0xFF);
                break;
            case TYPE_LONG:
                data = new byte[8];
                for (int i = 0; i < 8; i++) data[i] = (byte) ((value >> (i * 8)) & 0xFF);
                break;
            case TYPE_FLOAT:
            case TYPE_DOUBLE:
                int intVal = (int) value;
                data = new byte[4];
                for (int i = 0; i < 4; i++) data[i] = (byte) ((intVal >> (i * 8)) & 0xFF);
                break;
        }
        return data;
    }

    private long extractAddress(String display) {
        if (display == null || display.length() < 10) return -1;
        try {
            String hex = display.substring(0, display.indexOf(' '));
            return Long.parseLong(hex.substring(2), 16);
        } catch (Exception e) {
            return -1;
        }
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    private void setStatus(String msg) {
        tvStatus.setText(msg);
    }

    // ======================== CALLBACKS JNI ========================

    public void onScanProgress(final int percent) {
        new Handler(Looper.getMainLooper()).post(() -> {
            progressBar.setProgress(percent);
            setStatus("Scanneando... " + percent + "%");
        });
    }

    public void onScanComplete(final long[] addresses, final byte[][] values) {
        new Handler(Looper.getMainLooper()).post(() -> {
            progressBar.setVisibility(View.GONE);
            btnCancel.setEnabled(false);
            displayItems.clear();

            if (addresses != null) {
                for (int i = 0; i < addresses.length; i++) {
                    String hex = String.format("0x%08X", addresses[i]);
                    String val = (values != null && i < values.length) ? bytesToHex(values[i]) : "?";
                    displayItems.add(hex + "  " + val);
                }
            }
            adapter.notifyDataSetChanged();
            tvTitle.setText("Endereços: " + displayItems.size());
            setStatus("Scan concluído - " + displayItems.size() + " resultados");
        });
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // ======================== SALVAR/CARREGAR ========================

    private void saveResultsToFile() {
        try {
            File file = new File(getFilesDir(), "results.txt");
            FileWriter fw = new FileWriter(file);
            for (String item : displayItems) {
                fw.write(item + "\n");
            }
            fw.close();
            toast("Resultados salvos em " + file.getAbsolutePath());
        } catch (IOException e) {
            Log.e(TAG, "Erro ao salvar", e);
            toast("Erro ao salvar: " + e.getMessage());
        }
    }

    private void loadResultsFromFile() {
        try {
            File file = new File(getFilesDir(), "results.txt");
            if (!file.exists()) {
                toast("Arquivo não encontrado");
                return;
            }
            BufferedReader br = new BufferedReader(new FileReader(file));
            displayItems.clear();
            String line;
            while ((line = br.readLine()) != null) {
                displayItems.add(line);
            }
            br.close();
            adapter.notifyDataSetChanged();
            tvTitle.setText("Endereços: " + displayItems.size());
            toast("Resultados carregados: " + displayItems.size() + " endereços");
        } catch (IOException e) {
            Log.e(TAG, "Erro ao carregar", e);
            toast("Erro ao carregar: " + e.getMessage());
        }
    }

    // ======================== CONSTANTES ========================

    private static final int TYPE_BYTE = 0;
    private static final int TYPE_SHORT = 1;
    private static final int TYPE_INT = 2;
    private static final int TYPE_LONG = 3;
    private static final int TYPE_FLOAT = 4;
    private static final int TYPE_DOUBLE = 5;

    // ======================== MÉTODOS PÚBLICOS ========================

    public static void start(Context context) {
        context.startService(new Intent(context, MemoryScannerService.class));
    }

    public static void stop(Context context) {
        context.stopService(new Intent(context, MemoryScannerService.class));
    }
}