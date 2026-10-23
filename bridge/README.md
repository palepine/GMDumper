# GMDumper native bridge

The bridge is used for operations that cannot safely run on an external worker (`StructGetKeys`, `StructGetMember`, etc).

## Build

Build on Windows with Visual Studio 2022 or newer:

```powershell
cmake -S bridge -B bridge/build -A x64
cmake --build bridge/build --config Release
```

Copy `bridge/build/GMDumperBridge.dll` to `autorun/GMDumperModules`.

The bridge and GMDumper are GPL-3.0-or-later. Other licenes can be found in the source file.