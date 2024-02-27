# Mitre 2024 eCTF Code

This repo will host all of our code for the 2024 Mitre eCTF competition.

## Daily Routine

1. Make code changes / implement new features
2. Commit changes with a short message *and emoji* describing what we did
3. Add TODOs to TODOs.md *1 per line*
4. Push to remote repo

### Emoji codes

- Added new feature "✨"
- Removed feature "⏮️"
- Fixed bug "🐛"
- Formatting "🖌️"
- Moving code "🚚"

### Example commit messages

- ✨ Added password authentication
- ⏮️ Removed insecure access method
- 🐛 Patched password bypass
- 🖌️ Formatted main.cpp
- 🚚 Reorganized project

#### Project structure

```tree
├── analog_openocd.nix      # Used in the default build system to support debugging
├── application_processor/  # Contains files for the Application Processor  
├── bootflag.cpp            # Source code to deobfuscate the boot reference design flag
├── build/                  # Temporary build files
├── compile_commands.json   # Assists vscode intellisense
├── component/              # Contains files for the Components
├── deployment/             # Contains global secrets shared across a deployment
├── docs/                   # Contains documentation for our design
├── ectf_tools/             # Organizer-provided host and build tools
├── gdb_challenge.elf       # Debugger challenge binary
├── insecure.bin            # Insecure eCTF bootloader
├── lib/                    # Contains third-party libraries
├── msdk/                   # Contains the unmodified MaximSDK
├── poetry.lock             # Poetry lockfile
├── pyproject.toml          # Packages to be installed with Poetry
├── shell.nix               # Main build system definitions
└── TODOs.md                # Future todo list
```
