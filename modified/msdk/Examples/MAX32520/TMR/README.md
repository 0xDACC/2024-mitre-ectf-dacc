## Description

Two timers are used to demonstrate two different modes of the general purpose timers.

1. A continuous mode timer is used to create an interrupt at freq of 1 Hz. LED0 (Port 1.06) will toggle each time the interrupt occurs.

2. Timer 0 is used to output a PWM signal on Port 1.0. The PWM frequency is 200 Hz and the duty cycle is 75%.


## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

(None - this project builds as a standard example)

## Required Connections

-   Connect a USB cable between the PC and the CN1 (USB/PWR) connector.
-   Select RX SEL and TX SEL on headers JP7 and JP8.
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.

## Expected Output

The Console UART of the device will output these messages:

```
************************** Timer Example **************************

1. A continuous mode timer is used to create an interrupt every 1 sec.
   LED0 (Port 1.06) will toggle each time the interrupt occurs.

2. Timer 0 is used to output a PWM signal on Port 1.0.
   The PWM frequency is 200 Hz and the duty cycle is 75%.

PWM started.

Continuous timer started.
```
