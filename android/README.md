# aav Android app

A small demo app (`com.av.aav`) that drives the `aav` engine on-device through
JNI — the port of the standalone `aav_app` onto the modernized engine.

- **Java UI** (`app/src/main/java/com/av/aav/`): `MainActivity` with buttons for
  init / scan / uninit, plus `Engine` (the `native` methods) and `ScanResult`.
- **JNI bridge** (`app/src/main/cpp/aavjni.cc`): implements the `Engine` native
  methods against the **public SDK facade** (`aav::IEngine` — `MakeEngine` →
  `Init(sig_db)` → `Scan` with a result callback → `Destroy`). It **statically
  links `libaav`** and uses only the public `aav/engine_interface.h` — no engine
  internals and no `dlopen`. File identification, APK unpacking and directory
  traversal all happen inside the engine.
- **Native build** (`app/src/main/cpp/CMakeLists.txt`): `add_subdirectory`s the
  repo root to build `libaav` (with APK/miniz support; CLI/tools/tests off) and
  links it into `libaavjni.so`.
- **Assets** (`app/src/main/assets/`): `signatures.aav` (a `sigtool`-generated
  sample signature DB) and `classes.dex` (the matching sample). Out of the box,
  *Init* (which loads the DB) → *Scan* detects
  `Trojan!SampleFam.a@Android.Dex`.

## Requirements

- Android Studio (or command-line Gradle), **JDK 17**
- Android **SDK 36**, **NDK 29.0.14206865**, CMake ≥ 3.22

## Build

```bash
# From this directory:
./gradlew :app:assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Or open the `android/` folder in Android Studio and Run.

> If the Gradle wrapper JAR is missing on your machine, run `gradle wrapper`
> once, or let Android Studio repair it on first sync.

## Regenerating the sample assets

The bundled `signatures.aav` / `classes.dex` are produced by `sigtool` (built
from the repo root) and must be regenerated together if the signature-DB format
changes:

```bash
# From the repo root, after building sigtool:
./build/<preset>/bin/sigtool gen-sample /tmp/s
cp /tmp/s/sample.sig android/app/src/main/assets/signatures.aav
cp /tmp/s/sample.dex  android/app/src/main/assets/classes.dex
```
