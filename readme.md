# Antichamber Graphics Patch

Adds every resolution reported by the active display to Antichamber's graphics settings. A new configuration starts at the desktop resolution, the replacement resolution labels are enlarged, and the game's original fullscreen and windowed controls remain unchanged.

## Install

1. Close Antichamber.
2. In Steam, right-click **Antichamber**, select **Manage > Browse local files**, and note the folder containing `Binaries` and `UDKGame`.
3. Open PowerShell in this folder and run:

```powershell
.\AntichamberGraphicsPatch.exe "<Antichamber folder>" --install
```

Launch the game normally. On the graphics options wall, use **LAST** and **NEXT** to browse the detected resolutions.

## Check or remove

```powershell
.\AntichamberGraphicsPatch.exe "<Antichamber folder>" --check
.\AntichamberGraphicsPatch.exe "<Antichamber folder>" --remove
```

`--check` reports compatibility and installation state. `--remove` removes the patches and restores the game files to their original state. The installer refuses unrecognized game files. It keeps recovery copies and saved graphics preferences when removing the patch.

You may need to run this executable as administrator depending on your file location. Windows Defender may flag the executable as it is unsigned and modifies another program, requiring you to exclude it from scanning.
