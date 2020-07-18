package com.av.aav;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import android.app.Activity;
import android.content.res.AssetManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Toast;

public class MainActivity extends Activity implements OnClickListener {

    private static final String TAG = "aav";

    private Engine engine_;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewById(R.id.init).setOnClickListener(this);
        findViewById(R.id.uninit).setOnClickListener(this);
        findViewById(R.id.scan).setOnClickListener(this);

        engine_ = new Engine();
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        if (id == R.id.init) {
            onInit();
        } else if (id == R.id.uninit) {
            onUninit();
        } else if (id == R.id.scan) {
            onScan();
        }
    }

    // The facade's init loads the signature database, so init takes its path.
    private void onInit() {
        try {
            String sigDbPath = extractAsset("signatures.aav");
            int code = engine_.init(sigDbPath);
            Log.d(TAG, "init(" + sigDbPath + ") = " + code);
            toast("init: " + code);
        } catch (IOException e) {
            Log.e(TAG, "failed to extract signature db", e);
            toast("init failed: " + e.getMessage());
        }
    }

    private void onUninit() {
        engine_.uninit();
        Log.d(TAG, "uninit");
        toast("uninit");
    }

    private void onScan() {
        try {
            String path = extractAsset("classes.dex");
            ScanResult[] results = engine_.scan(path);
            if (results == null) {
                Log.d(TAG, "scan failed for " + path);
                toast("scan failed");
                return;
            }
            Log.d(TAG, "scanned " + results.length + " file(s)");
            for (ScanResult r : results) {
                Log.d(TAG, "file: " + r.path + " isMalware=" + r.isMalware
                        + " isWhite=" + r.isWhite);
                for (int i = 0; i < r.sigIds.length; i++) {
                    String name = (r.names != null && i < r.names.length)
                            ? r.names[i] : "";
                    Log.d(TAG, "  sigID " + r.sigIds[i] + ": " + name);
                }
            }
            toast("scanned " + results.length + " file(s)");
        } catch (IOException e) {
            Log.e(TAG, "failed to extract sample", e);
            toast("scan failed: " + e.getMessage());
        }
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    // Copy an asset into the app's files dir and return its absolute path.
    private String extractAsset(String name) throws IOException {
        AssetManager assetManager = getAssets();
        File file = new File(getFilesDir(), name);
        try (InputStream is = assetManager.open(name);
             FileOutputStream fos = new FileOutputStream(file)) {
            byte[] buffer = new byte[4096];
            int n;
            while ((n = is.read(buffer)) != -1) {
                fos.write(buffer, 0, n);
            }
        }
        Log.d(TAG, "extractAsset: " + file.getAbsolutePath());
        return file.getAbsolutePath();
    }
}
