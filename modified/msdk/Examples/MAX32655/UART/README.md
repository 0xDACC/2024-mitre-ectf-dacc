## Description

This application uses two serial ports to send and receive data.  One serial port transmits data while the other receives it.


## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

* This project comes pre-configured for the MAX32655EVKIT.  See [Board Support Packages](https://analog-devices-msdk.github.io/msdk/USERGUIDE/#board-support-packages) in the MSDK User Guide for instructions on changing the target board.

## Setup

### Required Connections
If using the Standard EV Kit (EvKit_V1):
-   Connect a USB cable between the PC and the CN1 (USB/PWR) connector.
-   Connect pins JP4(RX_SEL) and JP5(TX_SEL) to RX0 and TX0  header.
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.
-   Connect JH13 (P2.6) to JH8 (P1.1).
-   Connect JH13 (P2.7) to JH8 (P1.0).

If using the Featherboard (FTHR\_Apps\_P1):
-   Only one UART instance available. Example not supported.

## Expected Output

The Console UART of the device will output these messages:

```
**************** UART Example ******************
This example sends data from one UART to another

The green LED (P0_25) will illuminate for successful transaction.
The red LED (P0_24) will illuminate if transaction failed.


Connect UART3 to UART2 for this example.
P2.6 -> P1.1 and P2.7 -> P1.0


-->UART Baud    : 115200 Hz

-->Test Length  : 1024 bytes
-->UART Initialized

-->Data verified

-->Example Succeeded
```

The green LED (P0_25) will illuminate for successful transaction.
The red LED (P0_24) will illuminate if transaction failed.
