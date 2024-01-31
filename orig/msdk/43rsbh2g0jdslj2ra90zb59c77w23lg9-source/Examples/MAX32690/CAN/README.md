## Description

This example demonstrates how to perform various CAN transactions, specifically, sending a CAN 2.0 message and/or an RTR message, as well as receiving a CAN message (any type except CAN FD). These operations can be enbled and disabled with the macros at the top of main.c. And they can be performed using either blocking, non-blocking or DMA methods (also selectable with the macros defined at top of main.c.)

Connect CAN signals on header JH8 to CAN bus.

## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

(None - this project builds as a standard example)

## Required Connections

-   Connect a USB cable between the PC and the CN2 (USB/PWR) connector.
-   Install JP7(RX_EN) and JP8(TX_EN) headers.
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.
-   Close jumper JP5 (LED1 EN).
-   Close jumper JP6 (LED2 EN).
- 	Connect CAN signals on header JH8 to CAN bus.

## Expected Output

The Console UART of the device will output these messages:

```
*********************** CAN Example ******************************
This example demonstrates how to perform various CAN transactions,
specifically, sending a CAN 2.0 message and/or an RTR message, as
well as receiving a CAN message (any type except CAN FD). These
operations can be performed with either blocking, non-blocking or
DMA methods (selectable with the macros defined above.)

Connect CAN signals on header JH8 to CAN bus.

Press button SW2 to begin example.

Sending standard CAN message...
Message sent!
Sending RTR message...
Message sent!

Ready to receive message.
Message received!
MSG ID: 29-bit ID - 0x1aa
RTR: 0
FDF: 0
BRS: 0
ESI: 0
DLC: 8
Data Received:
1 3 5 7 9 2 4 6

Example complete.
```
