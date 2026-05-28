# Config-Extractors

Static configuration extractors for malware families. Each family lives in its own folder with scripts, dependencies, and sample files.

## janelaRAT

Works on **deobfuscated JanelaRAT** samples (e.g. after de4dot / dnSpy cleanup) that still expose the Class55 static constructor config initializer in IL.

### Setup

```bash
cd janelaRAT
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

### Usage

```bash
python extracto2.py samples/PixelPaint_Slayed.dll
python extracto2.py /path/to/sample/or/directory
```

Output is JSON with `sample`, `key`, and `strings` (indexed decrypted config values).

### Sample

`janelaRAT/samples/PixelPaint_Slayed.dll` — reference deobfuscated build included for testing.
