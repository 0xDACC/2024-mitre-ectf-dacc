## Description

This example demonstrates the use of the Analog Comparator to wake up the device from sleep mode. 

The example is configured to use analog channels 0 and 1 as the negative and positive comparator inputs respectively. A wakeup event is triggered when the comparator output transitions from low to high (analog 1 needs to transition from a voltage lower than analog 0 to voltage higher than analog 0).


## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

* This project comes pre-configured for the MAX32655EVKIT.  See [Board Support Packages](https://analog-devices-msdk.github.io/msdk/USERGUIDE/#board-support-packages) in the MSDK User Guide for instructions on changing the target board.


##### Required Connections
If using the Standard EV Kit (EvKit_V1):
-   Connect a USB cable between the PC and the CN1 (USB/PWR) connector.
-   Connect pins JP4(RX_SEL) and JP5(TX_SEL) to RX0 and TX0  header.
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.
-   Apply the negative comparator input to AIN0/AIN0N (JH11).
-	Apply the positive comparator input to AIN1/AIN0P (JH11).

If using the Featherboard (FTHR\_Apps\_P1):
-   Connect a USB cable between the PC and the J4 (USB/PWR) connector.
-   Open an terminal application on the PC and connect to the board's console UART at 115200, 8-N-1.

## Expected Output

The Console UART of the device will output these messages:

```
********** Comparator Example **********

Connect the analog signal used as the positive comparator input 1 (AIN1/AIN0P).
Connect the analog signal used as the negative comparator input 0 (AIN0/AIN0N).

The device will be placed in sleep mode and requires a rising edge of the
comparator output to wakeup.

Press SW3 to begin.

Entering sleep mode.
Waking up.

Entering sleep mode.
Waking up.

Entering sleep mode.
...
```
