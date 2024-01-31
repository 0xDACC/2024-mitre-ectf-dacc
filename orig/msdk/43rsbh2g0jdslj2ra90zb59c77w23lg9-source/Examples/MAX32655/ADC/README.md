## Description

Demonstrates the use of the ADC by continuously monitoring ADC input channel 0.  Vary the voltage on the AIN0 input (0 to 1.8V) to observe different readings from the ADC.

The example can be configured to either use a polling or interrupt driven ADC Conversion by commenting or uncommenting the "USE_INTERRUPTS" define respectively. 

Any reading that exceeds the full-scale value of the ADC will have an '*' appended to the value.


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
-   Apply an input voltage between 0 and 0.9V to pin labeled 0 of the JH11 (Analog) header.

If using the Featherboard (FTHR\_Apps\_P1):
-   Connect a USB cable between the PC and the J4 (USB/PWR) connector.
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.
-   Apply an input voltage between 0 and 0.9V to pin labeled 0 of the JH11 (Analog) header.

## Expected Output

The Console UART of the device will output these messages:

```
ADC Example
0: 0x0001


0: 0x003f


0: 0x01ad


0: 0x028d


0: 0x0289


0: 0x006a
```
