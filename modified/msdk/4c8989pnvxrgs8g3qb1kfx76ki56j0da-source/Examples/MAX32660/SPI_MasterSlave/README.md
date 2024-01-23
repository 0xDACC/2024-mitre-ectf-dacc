## Description

This example demonstrates a SPI transaction between two distinct SPI peripherals on the MAX32660. 

SPIMSS (SPI1) is setup as the master in this example and is configured by default to send/receive 1024 8-bit words to and from the slave. Likewise, SPI0 is setup as the slave and is also expecting to both send and receive 1024 8-bit words to and from the master.

Once the master ends the transaction, the data received by the master and the slave is compared to the data sent by their counterpart to ensure all bytes were received properly.


## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

(None - this project builds as a standard example)

## Required Connections

-   Connect a USB cable between the PC and the CN2 (USB/PWR) connector.
-   Open an terminal application on the PC and connect to the EV kit's console UART at 115200, 8-N-1.
-   Connect the SPI pins on headers JH3 and JH4. (P0.11-->P0.5 (MOSI), P0.10-->P0.4 (MISO), P0.12-->P0.6 (SCK), and P0.13-->P0.7 (CS))

## Expected Output
NOTE: The SPIMSS pins are shared with the Console UART so you may see some garbage characters in the terminal.

The Console UART of the device will output these messages:

```

************************ SPI Master-Slave Example ************************
This example sends data between two SPI peripherals in the MAX32660.
SPI0 is configured as the slave and SPIMSS (SPI1) is configured as the master.
Each SPI peripheral sends 1024 bytes on the SPI bus. If the data received
by each SPI instance matches the data sent by the other instance, the
LED will illuminate.

Press SW2 to begin transaction.

EXAMPLE SUCCEEDED!
```