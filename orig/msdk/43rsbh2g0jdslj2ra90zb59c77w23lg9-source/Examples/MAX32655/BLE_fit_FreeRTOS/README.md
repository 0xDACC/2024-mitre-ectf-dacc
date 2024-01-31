# Description

Bluetooth fitness device. Showcases heart rate, battery level, running speed and cadence.

Please refer to the [Examples/MAX32655/BLE_fit/README.md](../BLE_fit/README.md) for details.

This demo project modifies the [Examples/MAX32655/BLE_fit/](../BLE_fit/) project and implements the application in FreeRTOS.

In the serial console, two new commands "cmd ps s" and "cmd ps l" are added to display the FreeRTOS task related information.
```
cmd ps s  
Task            Run time cnt    Run time percentage  
***************************************************  
CordioH        	73		<1  
IDLE           	13641		99  
Tmr Svc        	0		<1  
CordioM        	0		<1  
```

```
cmd ps l  
Task          State  Priority  Stack    #  
**************************************  
CordioH        	X	2	3654	2  
IDLE           	R	0	117	3  
Tmr Svc        	B	2	90	4  
CordioM        	S	3	3982	1  
```

# Use ARM core and RISC-V core for split HCI
In the project.mk, changing USE_DUAL_CORE to 1 will enable using both ARM core and RISC-V core for the split HCI.


## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

* This project comes pre-configured for the MAX32655EVKIT.  See [Board Support Packages](https://analog-devices-msdk.github.io/msdk/USERGUIDE/#board-support-packages) in the MSDK User Guide for instructions on changing the target board.

