package com.exemplo.scanner;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Toast;

public class OverlayPermissionActivity extends Activity {

    private static final int REQ_OVERLAY = 9001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        checkAndProceed();
    }

    private void checkAndProceed() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            Toast.makeText(this,
                    "Permissão de sobreposição necessária para a bolha flutuante.",
                    Toast.LENGTH_LONG).show();
            Intent intent = new Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + getPackageName()));
            startActivityForResult(intent, REQ_OVERLAY);
        } else {
            launchOverlayAndFinish();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_OVERLAY) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M || Settings.canDrawOverlays(this)) {
                launchOverlayAndFinish();
            } else {
                Toast.makeText(this, "Permissão negada. A bolha não será exibida.",
                        Toast.LENGTH_LONG).show();
                finish();
            }
        }
    }

    private void launchOverlayAndFinish() {
        MemoryScannerService.start(this);
        finish();
    }
}