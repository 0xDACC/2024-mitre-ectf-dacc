# CameraIF_Debayer

This example demonstrates the HM0360 camera drivers for the [HM0360-AWA](https://www.digikey.com/en/products/detail/himax/HM0360-AWA/14109822) color sensor, which is a Bayer-patterned sensor.

It requires debayering/demosaicing and color correction post-processing algorithms to reconstruct a color image.  This example demonstrates how to configure the camera drivers, apply the post-processing functions, and display the image to the TFT display or send it over UART.

## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

* This project only supports the MAX78000EVKIT or MAX78000CAM01 board.
* This project supports displaying the captured image on the TFT display.  To enable this functionality, define `ENABLE_TFT` in [main.c](main.c)

## Required Connections

For instructions on setting up the MAX78000EVKIT see the [MAX78000EVKIT Quick-Start Guide](https://github.com/MaximIntegratedAI/MaximAI_Documentation/tree/master/MAX78000_Evaluation_Kit)

