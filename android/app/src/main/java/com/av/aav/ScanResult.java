package com.av.aav;

// One scanned file's result, mirroring the native aav::ScanReport delivered
// through IEngine::Scan.
public class ScanResult {
    public final String path;
    public final boolean isMalware;
    public final boolean isWhite;
    public final int[] sigIds;
    public final String[] names;  // names[i] describes sigIds[i]

    public ScanResult(String path, boolean isMalware, boolean isWhite,
                      int[] sigIds, String[] names) {
        this.path = path;
        this.isMalware = isMalware;
        this.isWhite = isWhite;
        this.sigIds = sigIds;
        this.names = names;
    }
}
