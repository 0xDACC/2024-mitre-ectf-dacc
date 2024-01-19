## Description

A basic getting started application for BLE and FreeRTOS.


# Usage

## LEDs

The red LED will indicate that an error assertion has occurred.  

The green LED indicates CPU activity. When the LED is on, the CPU is active, when the LED
is off, the CPU is in sleep mode.

## Expected Output

On startup:
```

-=- MAX32655 BLE FreeRTOS (V10.2.0) Demo -=-
SystemCoreClock = 100000000
terminal: init
32kHz trimed to 0x16
DatsHandlerInit
Calculating database hash
Dats got evt 119
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
Database hash calculation complete
Dats got evt 21
Database hash updated
```

When a connection (to evkit running DATC example) has been made.
```
dmConnIdByBdAddr not found
dmConnCcbAlloc 1
dmConnSmExecute event=28 state=0
dmAdvConnected: state: 1
dmDevPassEvtToDevPriv: event: 13, param: 34, advHandle: 0
AttsCccInitTable connId=1
smpDbGetRecord: connId: 1 type: 0
smpDbAddDevice
SmpDbGetFailureCount: connId: 1 count: 0
smpDbGetRecord: connId: 1 type: 0
smpDbAddDevice
SmpDbGetPairingDisabledTime: connId: 1 period: 0 attemptMult: 0
Dats got evt 39
>>> Connection opened <<<
Dats got evt 65
attsProcMtuReq features 0x00
hciCoreTxAclStart len=7
Dats got evt 22
hciCoreTxAclStart len=24
Dats got evt 87
connId=1 idleMask=0x0004
hciCoreTxAclStart len=9
hciCoreTxAclStart len=34
hciCoreTxAclStart len=9
connId=1 idleMask=0x0004
hciCoreTxAclStart len=10
connId=1 idleMask=0x0004
hciCoreTxAclStart len=9
hciCoreTxAclStart len=27
hciCoreTxAclStart len=9
connId=1 idleMask=0x0004
hciCoreTxAclStart len=9
hciCoreTxAclStart len=27
hciCoreTxAclStart len=9
connId=1 idleMask=0x0004
hciCoreTxAclStart len=10
connId=1 idleMask=0x0004
hciCoreTxAclStart len=9
attsCccMainCback connId=1 handle=19
hciCoreTxAclStart len=5
connId 1 updated csf to 0x01
hciCoreTxAclStart len=5
attsCccMainCback connId=1 handle=515
hciCoreTxAclStart len=5
App got evt 16
```

When message received from peer
```
hello world
hciCoreTxAclStart len=18
Dats got evt 18
```

## Commands
Type the desired command and parameter (if applicable) and press enter to execute the command.  

__help__  Displays the available commands.  
__echo (on|off)__  Enables or disables the input echo. On by default.  
__btn (ID) (s|m|l|x)__  Simulates button presses. Example: "btn 1 s" for a short button press on button 1.  
__pin (ConnID) (Pin Code)__  Used to input the pairing pin code.  

## Push buttons
Push buttons can be used to interact with the application.

__short__ press is less than 200 ms  
__medium__ press is between 200 and 500 ms  
__long__ press is between 500 and 1000 ms  
__extra long__ press is greater than 1000 ms  

### When disconnected
1. Button 1 short press: Start advertising
2. Button 1 medium press: Enter bondable mode
3. Button 1 long press: Clear all bonding info
4. Button 1 extra long press: Show version info
5. Button 2 short press: Stop advertising

### When connected
1. Button 2 short press: Change PHY (1M-2M-Coded_S2-Coded_S8)
