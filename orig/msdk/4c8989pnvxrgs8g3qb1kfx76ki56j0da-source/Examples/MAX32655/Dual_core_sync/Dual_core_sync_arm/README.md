## Description

Projects Dual_core_sync_arm and Dual_core_sync_riscv demonstrates loading the RISC-V core program from the ARM core and synchronizing these two cores by hardware semaphores. 

Dual_core_sync_arm runs on the ARM core (CM4) to load the RISC-V core (RV32) code space, setup the RISC-V debugger pins, and start the RISC-V core.

The Dual_core_sync_riscv example runs on the the RISC-V core.

Please refer to the App Note [The MAX32655: Why Two Cores Are Better Than One](https://www.maximintegrated.com/en/design/technical-documents/app-notes/7/7336.html) for more information.


## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

* This project comes pre-configured for the MAX32655EVKIT.  See [Board Support Packages](https://analog-devices-msdk.github.io/msdk/USERGUIDE/#board-support-packages) in the MSDK User Guide for instructions on changing the target board.

## Setup

### Required Connections
If using the Standard EV Kit (EvKit\_V1):
-   Connect a USB cable between the PC and the CN1 (USB/PWR) connector.
-   Connect pins JP4(RX_SEL) and JP5(TX_SEL) to RX0 and TX0  header.
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.
-   Close jumper JP2 (LED0 EN).
-   Close jumper JP3 (LED1 EN).

If using the Featherboard (FTHR\_Apps\_P1):
-   Connect a USB cable between the PC and the J4 (USB/PWR) connector.
-   Open an terminal application on the PC and connect to the board's console UART at 115200, 8-N-1.
-   
## Expected Output

The Console UART of the device will output these messages:

```
-----------------------------------␍␊
ARM   : Start.␍␊
ARM   : After init, CheckSema(0) returned NOT BUSY.␍␊
ARM   : GetSema returned NOT BUSY with previous semaphore value 1.␍␊
ARM   : Wait 2 secs then start the RISC-V core.␍␊
␍␊
RISC-V: Start.␍␊
RISC-V: After init, CheckSema(1) returned NOT BUSY.␍␊
RISC-V: GetSema returned NOT BUSY with previous semaphore value 1.␍␊
RISC-V: Do initialization works here.␍␊
RISC-V: Signal ARM.␍␊
ARM   : Do initialization works here.␍␊
ARM   : Signal RISC-V.␍␊
RISC-V: cnt=0␍␊
ARM   : cnt=1␍␊
RISC-V: cnt=2␍␊
ARM   : cnt=3␍␊
RISC-V: cnt=4␍␊
```

## Synchronization Between ARM Core And RISC-V Core
In the MAX32655, there are two CPU cores: the ARM core and the RISC-V core. Application Note [The MAX32655: Why Two Cores Are Better Than One](https://www.maximintegrated.com/en/design/technical-documents/app-notes/7/7336.html) introduces the advantages of using these two cores.

This program demonstrates how to synchronize the two cores and how to properly use the shared resources like UART and memories between the two cores.

The multicore synchronization is implemented by the hardware semaphores provided by the MAX32655. [Data Sheet of MAX32655](https://www.maximintegrated.com/en/products/MAX32655) Chapter 8 introduces the details of the eight semaphore registers that allows mulitple cores to cooperate when access shared resources.

In this program, semaphore 0 is used by the ARM core as a mutex/lock. The **Semaphore 0 Register** status field indicates the lock status. 0: semaphore is available, the ARM core is unlocked. 1: semaphore is taken, the ARM core is locked. Note that this status field in Semaphore 0 Register is also mirrored to the **Semaphore Status Register** field status0. The Semaphore Status Register field status0 is read-only. Reads from this field do not affect the corresponding semaphore's status. Reading operation on the Semaphore 0 Register status field is different. Reading this field "returns its current value and if 0, automatically sets the field to 1.".

Function MXC_SEMA_CheckSema(0) will read the Semaphore Status Register field status0. From this field status, the program knows if the ARM core is locked (1) or unlocked (0).

Function MXC_SEMA_GetSema(0) will read the Semaphore 0 Register status field. And if it is 0, automatically sets the field to 1 by hardware.

Function MXC_SEMA_FreeSema(0) on the RV32 core will release the lock of CM4 core.

By useing the Semaphore 0 for CM4 and Semaphore 1 for RV32, the two cores are synchronized.

## Shared Memory Between CM4 and RV32 Cores
According to the MAX32655 Data Sheet, Table 3-101, The RV32 Control Register, field memsel determines if sysram2 and sysram3 are shared between the CM4 and RV32 cores.

![System SRAM Configuration](https://user-images.githubusercontent.com/110848915/193666965-7231d813-7270-4cb5-988a-2aafca4e19d2.png)
If RV32 Control Register field memsel is 0, the sysram2 and sysram3 are shared can accessible by both the CM4 and RV32 cores. When programs modify the data in these spaces, it must be careful. 

In this demo program, the operations on the semaphore 0 and semaphore 1 make sure at a time, there is only one core can modify the data in the mxcSemaBox0 and mxcSemaBox1 which are located in the sysram2.

## How to debug CM4 and RV32 cores at the same time
The document https://github.com/Analog-Devices-MSDK/VSCode-Maxim#debugging introduces how to debug both ARM and RISC-V cores using VSCode.

This document will show how to debug both cores by sending commands in terminals.

(1) Setup the RISC-V debugger according to [RISC-V-Debugging-Guide](https://github.com/Analog-Devices-MSDK/VSCode-Maxim/wiki/RISC-V-Debugging-Guide).
Note that doc is for MAX78000. For MAX32655EVKIT, in the folder of MaximSDK/Tools/OpenOCD/scripts/target, run command:
`ln -s max78000_riscv.cfg MAX32655_riscv.cfg`.

(2) Build the project
Open Examples/MAX32655/Dual_core_sync_arm in VSCode.
In Menu, File, Add Folder to Workspace..., add "Dual_core_sync_riscv".
open Dual_core_sync_arm/Makefile, verify:
```
# Load and start the RISCV core
RISCV_LOAD=1

# Directory for RISCV code
RISCV_APP_DIR=../Dual_core_sync_riscv
```
In menu, Terminal, Run Task..., Build (Dual_core_sync_arm).

(3) Run openocd for ARM core
In a terminal, run `$MSDK_REPO/Tools/OpenOCD/openocd -s $MSDK_REPO/Tools/OpenOCD/scripts -f interface/cmsis-dap.cfg -f target/MAX32655.cfg`.
```
Open On-Chip Debugger 0.11.0+dev-g2de3186d7 (2022-06-17-06:44)
Licensed under GNU GPL v2
For bug reports, read
	http://openocd.org/doc/doxygen/bugs.html
DEPRECATED! use 'adapter driver' not 'interface'
Info : Listening on port 6666 for tcl connections
Info : Listening on port 4444 for telnet connections
Info : CMSIS-DAP: SWD  supported
Info : CMSIS-DAP: Atomic commands supported
Info : CMSIS-DAP: Test domain timer supported
Info : CMSIS-DAP: FW Version = 0256
Info : CMSIS-DAP: Serial# = 0444170169c5c14600000000000000000000000097969906
Info : CMSIS-DAP: Interface Initialised (SWD)
Info : SWCLK/TCK = 1 SWDIO/TMS = 1 TDI = 0 TDO = 0 nTRST = 0 nRESET = 1
Info : CMSIS-DAP: Interface ready
Info : clock speed 2000 kHz
Info : SWD DPIDR 0x2ba01477
Info : max32xxx.cpu: Cortex-M4 r0p1 processor detected
Info : max32xxx.cpu: target has 6 breakpoints, 4 watchpoints
Info : starting gdb server for max32xxx.cpu on 3333
Info : Listening on port 3333 for gdb connections
```
Note that the tcl port is 6666, telnet port is 4444, and the gdb port is 3333.

(4) run gdb for ARM core
In another terminal, run:
```
cd $MSDK_REPO/Examples/MAX32655/Dual_core_sync_arm
arm-none-eabi-gdb build/Dual_core_sync_arm.elf
```

In gdb, run:
```
target extended-remote :3333
load
continue
```

Now, if connect to the Serial port, it will show that both cores have been started to run.
![Both cores are running.](https://user-images.githubusercontent.com/110848915/193679444-546a0e31-8728-4701-ae1b-68553e62d46f.png)

In gdb, use Ctrl+c to stop the ARM core.
Then:
```
load
b main
continue
```
It will stop at the beginning of the ARM program. Then use gdb command `next` to run the ARM code step by step until after run function "MXC_SYS_RISCVRun();".

Now the ARM core is ready.

(5) run another openocd server for RISC-V core
In another terminal, run command `~/MaximSDK/Tools/OpenOCD/openocd -s ~/MaximSDK/Tools/OpenOCD/scripts -f interface/ftdi/olimex-arm-usb-ocd-h.cfg -f target/MAX32655_riscv.cfg -c "gdb_port 3334" -c "telnet_port 4445" -c "tcl_port 6667"`.
```
Open On-Chip Debugger 0.11.0+dev-g2de3186d7 (2022-06-17-06:44)
Licensed under GNU GPL v2
For bug reports, read
	http://openocd.org/doc/doxygen/bugs.html
DEPRECATED! use 'adapter driver' not 'interface'
DEPRECATED! use 'ftdi device_desc' not 'ftdi_device_desc'
DEPRECATED! use 'ftdi vid_pid' not 'ftdi_vid_pid'
DEPRECATED! use 'ftdi layout_init' not 'ftdi_layout_init'
DEPRECATED! use 'ftdi layout_signal' not 'ftdi_layout_signal'
DEPRECATED! use 'ftdi layout_signal' not 'ftdi_layout_signal'
DEPRECATED! use 'ftdi layout_signal' not 'ftdi_layout_signal'
Info : auto-selecting first available session transport "jtag". To override use 'transport select <transport>'.
Info : Listening on port 6667 for tcl connections
Info : Listening on port 4445 for telnet connections
Info : adv debug unit selected
Info : mohor tap selected
Info : clock speed 4000 kHz
Info : JTAG tap: max32xxx_riscv.cpu tap/device found: 0x16210197 (mfg: 0x0cb (Maxim Integrated Product), part: 0x6210, ver: 0x1)
Info : starting gdb server for max32xxx_riscv.cpu on 3334
Info : Listening on port 3334 for gdb connections
```
Note that the tcl port is 6667 now, telnet port is 4445, and the gdb port is 3334.

(6) run gdb for the RISC-V core
In a new terminal, run:
```
cd $MSDK_REPO/Examples/MAX32655/Dual_core_sync_riscv
~/MaximSDK/Tools/xPack/riscv-none-embed-gcc/10.2.0-1.2/bin/riscv-none-embed-gdb buildrv/Dual_core_sync_arm.elf
```
In gdb:
```
target extended-remote :3334
load
continue
```
Now the RISC-V core is started and blocked to wait for the ARM core to run.


