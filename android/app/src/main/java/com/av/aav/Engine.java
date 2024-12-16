package com.av.aav;

import java.lang.String;

// Thin Java wrapper over the native aav SDK facade (aav::IEngine). The bridge
// (libaavjni) creates the engine, loads the signature DB, scans, and destroys.
public class Engine {
    static {
        System.loadLibrary("aavjni");
    }

    // Create the engine and load the signature database. Returns 0 on success.
    public native int init(String sigDbPath);

    // Release the engine.
    public native void uninit();

    // Scan a file or directory. Returns one ScanResult per scanned APK/DEX
    // (an empty array when nothing was scannable), or null on error.
    public native ScanResult[] scan(String path);
}
