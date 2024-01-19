## Description

A basic getting started program.

This version of Hello_World prints an incrementing count to the console UART and toggles an LED once every 500 ms.

## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

(None - this project builds as a standard example)

## Required Connections

-   Connect a USB cable between the PC and the CN1 (USB/PWR) connector.
-   Select RX0 and TX0 on Headers JP10 and JP11 (UART 0).
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.

## Expected Output

The Console UART of the device will output these messages:

```
C++ Hello World Example
Number of blinks: 0
Number of blinks: 1
Number of blinks: 2
Number of blinks: 3
```

You will also observe LED1 blinking at a rate of 1Hz.
