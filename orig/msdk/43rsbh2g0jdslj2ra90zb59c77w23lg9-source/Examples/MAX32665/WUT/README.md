## Description
This Example shows how to wake up a device after it is asleep with a wake up timer.  After a defined number of seconds it will wake up after going to sleep.


## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

(None - this project builds as a standard example)

## Required Connections

-   Connect a USB cable between the PC and the CN2 (USB/PWR) connector.
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.

## Expected Output

```
/************** Wakeup timer example ********************/
This example is to show how the Wakeup timer is used and configured
Press push button 0 to put the chip into sleep and then the wakeup timer will wake up in 5000 Miliseconds
Entering SLEEP mode.
Waking up from SLEEP mode.
```
