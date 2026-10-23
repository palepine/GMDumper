# Cheat Engine Runtime GameMaker Dumper

Cheat Engine GameMaker Dumper is a [Cheat Engine](https://github.com/cheat-engine/cheat-engine) script that let's you inspect & dump runtime GameMaker targets via Cheat Engine API. It targets Windows x86/x64 targets. The compatibility and support is limited. The project is designed for researching, debugging, modding.

The public [API](docs/API.md).

## Install and use

1. Copy & merge the `autorun` directory into the Cheat Engine root directory.
2. Start CE and attach to a Windows GameMaker target.
3. `GMDumper` menu should appear after attaching
4. Enable `GMDumper → Init runtime`

## Current state

The tool is under development at its early stage. Not guaranteed to work on any target.

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).