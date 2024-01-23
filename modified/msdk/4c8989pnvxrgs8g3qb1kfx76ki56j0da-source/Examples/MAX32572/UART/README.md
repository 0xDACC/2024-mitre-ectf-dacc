## Description

This application uses two serial ports to send and receive data.  One serial port transmits data while the other receives it.


## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

(None - this project builds as a standard example)

## Required Connections

-   Connect a USB cable between the PC and the CN1 (USB/PWR) connector.
-   Connect a USB cable between the PC and the CN1 (USB/UART0) connector.
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.
-   Connect P1.12 to P1.21.
-   Connect P1.13 to P1.20.

## Expected Output

The Console UART of the device will output these messages:

```
**************** UART Example ******************
This example sends data from one UART to another

The LED (P2.17) is used to indicate the success of the test.
LED ON -> Success


Connect UART1 to UART3 for this example.
P1.12 -> P1.21 and P1.13 -> P1.20


-->UART Baud    : 115200 Hz

-->Test Length  : 1024 bytes

-->UART Initialized

-->Data verified

-->Example Succeeded
```

The LED (P2.17) will illuminate to indicate the success of the test.
