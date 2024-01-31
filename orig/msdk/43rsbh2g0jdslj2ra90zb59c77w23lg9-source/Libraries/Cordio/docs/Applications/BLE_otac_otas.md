# BLE_otac
## Description

Bluetooth data client that scans for and connects to advertisers with the name of "OTAS".

The Wireless Data Exchange profile is used to transfer files from the client to the server. 
A CRC32 value is used to check the integrity of the transferred file. 

## Usage

### LEDs

The red LED will indicate that an error assertion has occurred.  

The green LED indicates CPU activity. When the LED is on, the CPU is active, when the LED
is off, the CPU is in sleep mode.

### Setup
The `project.mk` can be edited to select the appropriate application directory for the update
image. Change FW_UPDATE_DIR to modify which application is used for the update. Whichever
application is selected must be setup to run from the appropriate memory section, as defined
by the Bootloader.


### Expected Output

On startup:
```
terminal: init
32kHz trimmed to 0x16
DatcHandlerInit
File addr: 10025950 file size: 00033368
Update File CRC: 0x8871C78B
WDXC: WdxcHandlerInit
>>> Reset complete <<<
Database hash updated
dmDevPassEvtToDevPriv: event: 12, param: 36, advHandle: 0
>>> Scanning started <<<
                                                     
```

When a connection has been made.
```
dmDevPassEvtToDevPriv: event: 13, param: 37, advHandle: 0
Scan results: 10
dmConnIdByBdAddr not found
dmConnCcbAlloc 1
>>> Scanning stopped <<<
dmConnSmExecute event=24 state=0
dmDevPassEvtToDevPriv: event: 14, param: 0, advHandle: 0
dmConnSmExecute event=28 state=1
dmDevPassEvtToDevPriv: event: 14, param: 1, advHandle: 0
dmDevPassEvtToDevPriv: event: 12, param: 39, advHandle: 0
smpDbGetRecord: connId: 1 type: 0
smpDbAddDevice
SmpDbGetFailureCount: connId: 1 count: 0
smpDbGetRecord: connId: 1 type: 0
smpDbAddDevice
SmpDbGetPairingDisabledTime: connId: 1 period: 0 attemptMult: 0
>>> Connection opened <<<
connId=1 idleMask=0x0008
AttcDiscServiceCmpl status 0x00
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x00
connId=1 idleMask=0x0008
AttcDiscServiceCmpl status 0x00
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x00
connId=1 idleMask=0x0008
AttcDiscServiceCmpl status 0x00
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x00
connId=1 idleMask=0x0008
AttcDiscServiceCmpl status 0x00
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x79
AttcDiscCharCmpl status 0x00
connId=1 idleMask=0x0000
AppDiscComplete connId:1 status:0x04
connId=1 idleMask=0x0008
AttcDiscConfigCmpl status 0x79
AttcDiscConfigCmpl status 0x79
AttcDiscConfigCmpl status 0x79
AttcDiscConfigCmpl status 0x79
AttcDiscConfigCmpl status 0x79
AttcDiscConfigCmpl status 0x79
AttcDiscConfigCmpl status 0x00
connId=1 idleMask=0x0000
AppDiscComplete connId:1 status:0x08
                                                                    
```

OTA procedure
```
btn 2 s
Short Button 2 Press
> 
WDXC file transfer control.
FTC op: 2 status: 0

WDXC file transfer control.
FTC op: 10 status: 0
>>> File discovery complete <<<

>>> Current fw version: 1.0 <<<                                              
                                                                              
btn 2 m                                                                       
Medium Button 2 Press                                                         
> WDXC file transfer control.                                                 
FTC op: 4 status: 0                                                           
>>> Starting file transfer <<<
... 
WDXC file transfer control.
FTC op: 10 status: 0
>>> File transfer complete 3547207 us <<<
file_size = 209768 usec = 3547207 bps = 473112
flowDisabled=0 handle=0


btn 2 l                                                                       
Long Button 2 Press                                                           
> WDXC file transfer control.                                                 
FTC op: 8 status: 0                                                           
>>> Verify complete status: 0 <<< 


btn 2 x                                                                       
XL Button 2 Press                                                             
> dmConnSmExecute event=29 state=3                                            
dmConnCcbDealloc 1                                                            
dmDevPassEvtToDevPriv: event: 13, param: 40, advHandle: 0                     
smpDbGetRecord: connId: 1 type: 0                                             
smpDbAddDevice                                                                
SmpDbSetFailureCount: connId: 1 count: 0                                      
smpSmExecute event=10 state=0                                                 
Connection closed status 0x0, reason 0x13                                     
 REMOTE TERM                                                                  
>>> Connection closed <<<
```

### Commands 
Type the desired command and parameter (if applicable) and press enter to execute the command.  

__help__  Displays the available commands.  
__echo__ (on|off) Enables or disables the input echo. On by default.  
__btn__ (ID) (s|m|l|x) Simulates button presses. Example: "btn 1 s" for a short button press on button 1.  
__pin__ (ConnID) (Pin Code) Used to input the pairing pin code.  

## Push buttons
Push buttons can be used to interact with the application.

__short__ press is less than 200 ms  
__medium__ press is between 200 and 500 ms  
__long__ press is between 500 and 1000 ms  
__extra long__ press is greater than 1000 ms  

### When connected
1. Button 1 short: On/Off scanning  
2. Button 1 medium: Cycle through the connection index  
3. Button 1 long: Drop selected connection  
4. Button 1 extra long: Toggle PHY 
5. Button 2 short: Discover file space on the peer device.
6. Button 2 medium: Start the update transfer.
7. Button 2 long: Verify the transfer.
8. Button 2 extra long: Command the peer to disconnect and reset.

### When disconnected
1. Button 1 short press: On/Off scanning
2. Button 1 medium press: Cycle through the connection index
3. Button 1 long press: Clear all bonding info
4. Button 1 extra long press: Add RPAO characteristic to GAP service -- needed only when DM Privacy enabled
5. Button 2 extra long press: Enable device privacy -- start generating local RPAs every 15 minutes

# BLE_otas
## Description

Bluetooth data server that advertises as "OTAS" and accepts connection requests.

The Wireless Data Exchange profile is used to transfer files from the client to the server's internal/external flash. 
A CRC32 value is used to check the integrity of the transferred file.
## Usage

### LEDs

The red LED will indicate that an error assertion has occurred.  

The green LED indicates CPU activity. When the LED is on, the CPU is active, when the LED
is off, the CPU is in sleep mode.

### Setup
The `Bootloader` application needs to be loaded prior to loading `BLE_otas` application. `BLE_otas` will run on top of the `Bootloader`. 
The linker file included with `BLE_otas` application must be used to properly setup the memory sections to coincide with the `Bootloader`.
The `project.mk` in this `BLE_otas` application in conjunction with `project.mk` in `Bootloader` determine
where the expected file is stored and read from.
Default configuration is to use external flash to store the transferd file before
writing it to internal flash space during the update.
Alternatively by changing `USE_INTERNAL_FLASH ?=0` to `USE_INTERNAL_FLASH ?=1` the transfered file
is stored in the update space. 

### Expected Output

On startup:
```
terminal: init
32kHz trimmed to 0x18
DatsHandlerInit
WDXS: WdxsHandlerInit
FW_VERSION: 1.0
File Hdl: 1
Dats got evt 32
>>> Reset complete <<<
dmAdvActConfig: state: 0
dmAdvActSetData: state: 0
dmAdvActSetData: state: 0
dmAdvActStart: state: 0
HCI_LE_ADV_ENABLE_CMD_CMPL_CBACK_EVT: state: 3
dmDevPassEvtToDevPriv: event: 12, param: 33, advHandle: 0
Dats got evt 33
>>> Advertising started <<<

```

When a connection has been made.
```
dmConnIdByBdAddr not found
dmConnCcbAlloc 1
dmConnSmExecute event=28 state=0
dmAdvConnected: state: 1
dmDevPassEvtToDevPriv: event: 13, param: 34, advHandle: 0
smpDbGetRecord: connId: 1 type: 0
smpDbAddDevice
SmpDbGetFailureCount: connId: 1 count: 0
smpDbGetRecord: connId: 1 type: 0
smpDbAddDevice
SmpDbGetPairingDisabledTime: connId: 1 period: 0 attemptMult: 0
Dats got evt 39
>>> Connection opened <<<
Dats got evt 65
Dats got evt 87
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004
connId=1 idleMask=0x0004

```

Upon reception of `btn 2 s` command
```
WDXS: FTC Write: len=12
WDXS: FTC Write: op=1 handle=0
WDXS: FTC GetReq handle=0 len=9
WDXS: FTC SendRsp op=2 handle=0 status=0
WDXS: Task Handler Evt=1
WDXS: FTC Send
WDXS: AttHook handle=581 event=18
WDXS: Task Handler Evt=1
WDXS: FTC SendRsp op=10 handle=0 status=0
WDXS: AttHook handle=584 event=18
WDXS: Task Handler Evt=1
WDXS: FTC Send
WDXS: AttHook handle=581 event=18
WDXS: Task Handler Evt=1

```

Upon reception of `btn 2 m` command
```
WDXS: FTC Write: len=16
WDXS: FTC Write: op=3 handle=1
WDXS: FTC PutReq handle=1 offset=0, len=209768
>>> Initiating erase of 52 4K sectors in external flash <<<
WDXS: FTC PutReq handle=1 status=0
>>> Erasing address 0x1000 in external flash <<<
>>> Erasing address 0x2000 in external flash <<<
>>> Erasing address 0x3000 in external flash <<<
>>> Erasing address 0x4000 in external flash <<<
>>> Erasing address 0x5000 in external flash <<<
>>> Erasing address 0x6000 in external flash <<<
>>> Erasing address 0x7000 in external flash <<<
>>> Erasing address 0x8000 in external flash <<<
...
...
>>> External flash erase complete <<<
WDXS: FTC SendRsp op=4 handle=1 status=0
WDXS: Task Handler Evt=1
WDXS: FTC Send
WDXS: AttHook handle=581 event=18
WDXS: Task Handler Evt=1
Ext Flash: Wrote 224 bytes @ 0x00000008
Ext Flash: Wrote 224 bytes @ 0x000000E8
Ext Flash: Wrote 224 bytes @ 0x000001C8
Ext Flash: Wrote 224 bytes @ 0x000002A8
Ext Flash: Wrote 224 bytes @ 0x00000388
Ext Flash: Wrote 224 bytes @ 0x00000468
Ext Flash: Wrote 224 bytes @ 0x00000548
Ext Flash: Wrote 224 bytes @ 0x00000628
...
...
WDXS: FTC SendRsp op=10 handle=1 status=0
WDXS: Task Handler Evt=1
WDXS: FTC Send
WDXS: AttHook handle=581 event=18
WDXS: Task Handler Evt=1


```

Upon reception of `btn 2 l` command 
```
WDXS: FTC Write: len=3
WDXS: FTC Write: op=7 handle=1
WDXS: FTC VerifyReq: handle=1
CRC start addr: 0x00000000 Len: 0x00033368
CRC From File : 0x8871C78B
CRC Calculated: 0x8871C78B
WDXS: FTC SendRsp op=8 handle=1 status=0
WDXS: Task Handler Evt=1
WDXS: FTC Send
WDXS: AttHook handle=581 event=18
WDXS: Task Handler Evt=1

```

Upon reception of `btn 2 x` command 
```
connId=1 idleMask=0x0000
dmConnSmExecute event=25 state=3
dmConnSmExecute event=29 state=4
dmConnCcbDealloc 1
smpDbGetRecord: connId: 1 type: 0
smpDbAddDevice
SmpDbSetFailureCount: connId: 1 count: 0
smpSmExecute event=10 state=0
Dats got evt 40
Reseting!

```

On successful update the device resets and connects once again.


### Commands
Type the desired command and parameter (if applicable) and press enter to execute the command.  

__help__  Displays the available commands.  
__echo__ (on|off) Enables or disables the input echo. On by default.  
__btn__ (ID) (s|m|l|x) Simulates button presses. Example: "btn 1 s" for a short button press on button 1.  
__pin__ (ConnID) (Pin Code) Used to input the pairing pin code.  

## Push buttons
Push buttons can be used to interact with the application.

__short__ press is less than 200 ms  
__medium__ press is between 200 and 500 ms  
__long__ press is between 500 and 1000 ms  
__extra long__ press is greater than 1000 ms  

### When connected
1. Button 2 short press: Toggle PHY 
2. Button 2 medium press : Display firmware version
### When disconnected
1. Button 1 short press: On/Off advertising
2. Button 1 medium press: Cycle through the connection index
3. Button 1 long press: Clear all bonding info
4. Button 1 extra long press: Add RPAO characteristic to GAP service -- needed only when DM Privacy enabled
5. Button 2 medium press : Display firmware version
6. Button 2 extra long press: Enable device privacy -- start generating local RPAs every 15 minutes
