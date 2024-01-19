# bmp2c
This utility converts a 24 bit color bitmap, or a jpeg image to a 565 RGB format byte array that can be used for the ILI9341 240x320 TFT LCD controller.


	$ python bmp2c.py infile.bmp [-r]
	-r: rotate 90 degree


## Software

### Project Usage

Universal instructions on building, flashing, and debugging this project can be found in the **[MSDK User Guide](https://analog-devices-msdk.github.io/msdk/USERGUIDE/)**.

### Project-Specific Build Notes

* This project comes pre-configured for the MAX32655EVKIT.  See [Board Support Packages](https://analog-devices-msdk.github.io/msdk/USERGUIDE/#board-support-packages) in the MSDK User Guide for instructions on changing the target board.

