# Antichamber Graphics Patch

Adds every resolution reported by the active display to Antichamber's graphics settings. A new configuration starts at the desktop resolution, the replacement resolution labels are enlarged, and the game's original fullscreen and windowed controls remain unchanged.

## Install

1. Close Antichamber.
2. In Steam, right-click **Antichamber**, select **Manage > Browse local files**, and note the folder containing `Binaries` and `UDKGame`.
3. Open PowerShell in this folder and run:

```powershell
.\dist\AntichamberGraphicsPatch.exe "<Antichamber folder>" --install
```

Launch the game normally. On the graphics options wall, use **LAST** and **NEXT** to browse the detected resolutions.

## Check or remove

```powershell
.\dist\AntichamberGraphicsPatch.exe "<Antichamber folder>" --check
.\dist\AntichamberGraphicsPatch.exe "<Antichamber folder>" --remove
```

`--check` reports compatibility and installation state. `--remove` performs the normal verified removal. If `UDK.exe` needs recovery, use `--unpatch` instead; it removes the patch only after parity recovery reproduces the verified original file.

The installer refuses unrecognized game files. It keeps recovery copies and saved graphics preferences when removing the patch. If the UDK 3 license was already accepted, installation also repairs the stale acceptance record that can cause the Accept/Deny prompt to reappear.

The executable is not digitally signed, so Windows may identify its publisher as unknown. If Windows reports an access error, reopen PowerShell as Administrator.
