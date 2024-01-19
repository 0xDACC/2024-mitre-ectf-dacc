#! /usr/bin/env python3

################################################################################
 # Copyright (C) 2020 Maxim Integrated Products, Inc., All Rights Reserved.
 #
 # Permission is hereby granted, free of charge, to any person obtaining a
 # copy of this software and associated documentation files (the "Software"),
 # to deal in the Software without restriction, including without limitation
 # the rights to use, copy, modify, merge, publish, distribute, sublicense,
 # and/or sell copies of the Software, and to permit persons to whom the
 # Software is furnished to do so, subject to the following conditions:
 #
 # The above copyright notice and this permission notice shall be included
 # in all copies or substantial portions of the Software.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 # IN NO EVENT SHALL MAXIM INTEGRATED BE LIABLE FOR ANY CLAIM, DAMAGES
 # OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 # ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 # OTHER DEALINGS IN THE SOFTWARE.
 #
 # Except as contained in this notice, the name of Maxim Integrated
 # Products, Inc. shall not be used except as stated in the Maxim Integrated
 # Products, Inc. Branding Policy.
 #
 # The mere transfer of this software does not imply any licenses
 # of trade secrets, proprietary technology, copyrights, patents,
 # trademarks, maskwork rights, or any other form of intellectual
 # property whatsoever. Maxim Integrated Products, Inc. retains all
 # ownership rights.
 #
 ###############################################################################

## dtm_sweep.py
 #
 # Sweep connection parameters.
 #
 # Ensure that both targets are built with BT_VER := 9
 #

import sys
import argparse
from argparse import RawTextHelpFormatter
from time import sleep
import itertools


## mc_rcdat_6000 can be found in msdk-test-and measurenent
## mini_rcdat_usb.py can be used to sub this
from mc_rcdat_6000 import McRcdat9000



from BLE_hci import BLE_hci
from BLE_hci import Namespace
from termcolor import colored
import math
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.ticker as ticker
from matplotlib.colors import LogNorm, Normalize
from matplotlib.ticker import MaxNLocator
import matplotlib.pyplot as plt
from matplotlib import colors,cm
from matplotlib.colors import ListedColormap

verbose=True

TRACE_INFO = 2
TRACE_WARNING =  1
TRACE_ERROR = 0

traceLevel = TRACE_INFO

def printTrace(label, msg,callerLevel, color='white'):
    if  callerLevel <= traceLevel:
        print(colored(label + ": ", color), colored(msg, color))

def printWarning(msg):
    printTrace('Warning', msg, TRACE_WARNING, 'yellow')

def printInfo(msg):
    printTrace('Info', msg, TRACE_INFO, 'green')

def printError(msg):
    printTrace('Error', msg, TRACE_ERROR, 'red')


LL_CRC_LEN =                  3   # CRC length.
LL_AA_LEN =                   4   # Access address length.
LL_PREAMBLE_LEN_1M =          1   # Preamble length (LE 1M PHY)
LL_PREAMBLE_LEN_2M =          2   # Preamble length (LE 2M PHY)
LL_PREAMBLE_LEN_CODED_BITS =  10  # Preamble length (LE Coded PHY)
LL_CI_LEN_BITS =              2   # Coding indicator length (LE Coded PHY)
LL_TERM1_LEN_BITS =           3   # TERM1 length (LE Coded PHY)
LL_TERM2_LEN_BITS =           3   # TERM2 length (LE Coded PHY)
LL_BLE_BIT_PER_US =           1   # BLE PHY rate
LL_BLE_US_PER_BYTE_1M =       8   # BLE PHY speed (LE 1M PHY)
LL_BLE_US_PER_BYTE_2M =       4   # BLE PHY speed (LE 2M PHY)
LL_BLE_US_PER_BYTE_CODED_S8 = 64  # BLE PHY speed (LE Coded PHY, S=8)
LL_BLE_US_PER_BIT_CODED_S8 =  8   # BLE PHY speed (LE Coded PHY, S=8)
LL_BLE_US_PER_BYTE_CODED_S2 = 16  # BLE PHY speed (LE Coded PHY, S=2)
LL_BLE_US_PER_BIT_CODED_S2 =  2   # BLE PHY speed (LE Coded PHY, S=2)
LL_DTM_HDR_LEN =              2   # Direct Test Mode PDU header length
NUM_CHANNELS =                40   # Number of testing channels

# Calculate the duration of the test
def calcTestTime(packetLen, phy, numPackets):

    packetLen=int(packetLen)
    phy=int(phy)
    numPackets=int(numPackets)
    totalTime = 0

    # 1: 1M
    # 2: 2M
    # 3: S8
    # 4: S2

    # Calculate the length of each packet
    if (phy == 3 or phy == 4):
        totalTime = (LL_PREAMBLE_LEN_CODED_BITS + (LL_AA_LEN * 8) + LL_CI_LEN_BITS + LL_TERM1_LEN_BITS) * LL_BLE_US_PER_BIT_CODED_S8
        if (phy == 4):
            totalTime = totalTime + ((LL_DTM_HDR_LEN + packetLen + LL_CRC_LEN) * LL_BLE_US_PER_BYTE_CODED_S2) + (LL_TERM2_LEN_BITS * LL_BLE_US_PER_BIT_CODED_S2)
        else:
            totalTime = totalTime + ((LL_DTM_HDR_LEN + packetLen + LL_CRC_LEN) * LL_BLE_US_PER_BYTE_CODED_S8) + (LL_TERM2_LEN_BITS * LL_BLE_US_PER_BIT_CODED_S8)

    elif (phy == 2):
        totalTime = (LL_PREAMBLE_LEN_2M + LL_AA_LEN + LL_DTM_HDR_LEN + packetLen + LL_CRC_LEN) * LL_BLE_US_PER_BYTE_2M
    else:
        totalTime = (LL_PREAMBLE_LEN_1M + LL_AA_LEN + LL_DTM_HDR_LEN + packetLen + LL_CRC_LEN) * LL_BLE_US_PER_BYTE_1M

    # Add the inter frame spacing
    totalTime = math.ceil((totalTime + 249) / 625) * 625

    # Multiply by the number of packets we're sending
    totalTime = totalTime * numPackets

    # Add a constant 10 ms
    totalTime = totalTime + 10000

    return totalTime

def plottable_3d_info(df: pd.DataFrame):
    """
    Transform Pandas data into a format that's compatible with
    Matplotlib's surface and wireframe plotting.
    """
    index = df.index
    columns = df.columns

    x, y = np.meshgrid(np.arange(len(columns)), np.arange(len(index)))
    z = np.array([[df[c][i] for c in columns] for i in index])
    
    xticks = dict(ticks=np.arange(len(columns)), labels=columns)
    yticks = dict(ticks=np.arange(len(index)), labels=index)
    
    return x, y, z, xticks, yticks

MAP_COLORS = [[181/255.0, 213/255.0, 227/255.0],
              [66/255.0,  131/255.0, 231/255.0],
              [128/255.0, 251/255.0, 96/255.0],
              [58/255.0,  125/255.0, 39/255.0],
              [254/255.0, 255/255.0, 84/255.0],
              [241/255.0, 167/255.0, 61/255.0],
              [233/255.0, 53/255.0,  40/255.0],
              [126/255.0, 30/255.0,  22/255.0],
              [0/255.0,   0/255.0,  0/0255.0]]

def create_heatmap(df, annot=False):
	cmap = ListedColormap(MAP_COLORS, name='adi-heatmap')

	bounds = [0.0, 0.0001, 0.1, 0.3, 1, 3, 10, 30, 99.9999, 105]
	norm = colors.BoundaryNorm(bounds, cmap.N)
	hm = sns.heatmap(df, cmap=cmap, norm=norm, annot=annot, xticklabels=True, linecolor=[237/255.0, 237/255.0, 237/255.0, 0.2], linewidth=0.35)
	
	old_ticks = hm.collections[0].colorbar.get_ticks()
	new_ticks = []

	for i in range(len(old_ticks) - 1):
		new_ticks.append(old_ticks[i] + (old_ticks[i+1] - old_ticks[i])/2)

	labels = ['0%', '0%-0.1%', '0.1%-0.3%', '0.3%-1%', '1%-3%', '3%-10%', '10%-30%', '30%-100%', '100%']
	hm.collections[0].colorbar.set_ticks(new_ticks, labels=labels)
	hm.collections[0].colorbar.ax.set_ylabel('Packet Error Rate')
	hm.set(xlabel="Channels", ylabel="Rx Power [dBm]", title="Rx Sensitivity -- No interference")

	return hm


# Setup the command line description text
descText = """
Direct Test Mode Sweep

This tool uses a Mini Circuits RCDAT to control attenuation between two devices
running DTM software. The Packet error rate (PER) of the slave will be collected by setting the master device in tx test mode and the slave in rx test mode.
A vendor specific command will be sent to end the test. 
The total number of packets transmitted will be compared to the number of packtes received and the PER will be  
calculated as numPacketsReceived/numPacketsTransmitted * 100

IMPORTANT: The end test command is vendor specific,
meaning it will only work with MAX32 BLE devices using the latest stack.

"""

# Parse the command line arguments
parser = argparse.ArgumentParser(description=descText, formatter_class=RawTextHelpFormatter)
parser.add_argument('slaveSerial',help='Serial port for slave device')
parser.add_argument('masterSerial',help='Serial port for master device')
parser.add_argument('results',help='CSV files to store the results')
parser.add_argument('-d', '--delay', default=0.5,help='Number of seconds to wait before ending the test')
parser.add_argument('-n', '--numPackets', default=0,help='Number of packets to send per test')
parser.add_argument('-l', '--limit', default=0,help='PER limit for return value')
parser.add_argument('-p', '--phys', default="1",help='PHYs to test with, comma separated list with 1-4.')
parser.add_argument('-t', '--txpows', default="0",help='TX powers to test with, comma separated list.')
parser.add_argument('-a', '--attens', help='Attenuation settings to use, comma separated list.')
parser.add_argument('-da', '--disable-atten', action='store_true',help='Disbale Attenuator For Testing Purposes')
parser.add_argument('-cl', '--channel-loss', default="0",help='TX powers to test with, comma separated list.')
parser.add_argument('-as', '--atten-step', default="20",help='Attenuation Step Size.')


args = parser.parse_args()
print(args)

packetLengths    = [250]
phys             = args.phys.strip().split(",")
txPowers         = args.txpows.strip().split(",")
numPackets       = args.numPackets





if(args.attens == None):
    attens = list(range(20,90,int(args.atten_step)))

    # Add the max attenuation 
    attens.append(90)
else:
    attens = args.attens.strip().split(",")


if args.disable_atten:
    attens=[0]
    printInfo('Disabling Attenuator')
    disableAttenuator = True
else:
    printInfo('Attenuator active')
    disableAttenuator = False

print("slaveSerial   :",args.slaveSerial)
print("masterSerial  :",args.masterSerial)
print("results       :",args.results)
print("delay         :",args.delay)
print("numPackets    :",numPackets)
print("packetLengths :",packetLengths)
print("phys          :",phys)
print("attens        :",attens)
print("txPowers      :",txPowers)
print("PER limit     :",args.limit)


# Open the results file, write the parameters
results = args.results
results = open(args.results, "w")
results.write("# slaveSerial   : "+str(args.slaveSerial)+"\n")
results.write("# masterSerial  : "+str(args.masterSerial)+"\n")
results.write("# results       : "+str(args.results)+"\n")
results.write("# delay         : "+str(args.delay)+"\n")
results.write("# numPackets    : "+str(numPackets)+"\n")
results.write("# packetLengths : "+str(packetLengths)+"\n")
results.write("# phys          : "+str(phys)+"\n")
results.write("# attens        : "+str(attens)+"\n")
results.write("# PER limit     : "+str(args.limit)+"\n")
# Write the header line

results.close()

mini_RCDAT = McRcdat9000()


results_df = pd.DataFrame()

assert(args.slaveSerial != args.masterSerial)

# Create the BLE_hci objects
hciSlave = BLE_hci(Namespace(serialPort=args.slaveSerial, monPort="", baud=115200))
hciMaster = BLE_hci(Namespace(serialPort=args.masterSerial, monPort="", baud=115200))

perMax = 0

# Reset the devices
hciSlave.resetFunc(None)
hciMaster.resetFunc(None)
sleep(0.1)
for ch in range(NUM_CHANNELS):
    temp_results = []
    print('Channel Num', ch)
    print(f'{ch / NUM_CHANNELS *100}% complete')
    printInfo('Setting TX Power')
    hciSlave.txPowerFunc(Namespace(power=0, handle="0"))
    hciMaster.txPowerFunc(Namespace(power=0, handle="0"))

    for packetLen,phy,txPower in itertools.product(packetLengths,phys,txPowers):


        
        # Set the TX Power
        

        for atten in attens:
            print(packetLen," ",phy," ",atten," ",txPower)

            # Set the attenuation
            if not disableAttenuator:
                mini_RCDAT.setAttenuation(atten)
            
            
            # sleep(0.1)
            
            #start the test
            printInfo("RX Starting")
            hciSlave.rxTestFunc(Namespace(channel=ch, phy=phy))
            printInfo('TX Starting')
            hciMaster.txTestVSFunc(Namespace(channel=ch, phy=phy,payload=0,packetLength=packetLen,numPackets=numPackets))


            
            if(numPackets == 0):
                sleep(int(args.delay))
            else:
                # Sleep based on the amount of time it takes to complete the test
                # Convert us to seconds
                sleep(calcTestTime(packetLen, phy, numPackets) / 1000000)
            
            printInfo('Endding master')
            stats = hciMaster.endTestVSFunc(Namespace(noPrint=True))
            printInfo('Edning slave')
            packetsReceived = hciSlave.endTestFunc(Namespace(noPrint=True))


            packetsTransmitted = 0
            perMaster = 0

            if(numPackets == 0):
                if stats is not None:
                    packetsTransmitted = stats['txData']

                if packetsTransmitted != 0:
                    perSlave = round(100 * (1 - packetsReceived / packetsTransmitted), 2)
                
                else:
                    printWarning('End Test stats returned invalid data. (Packets Transmitted = 0) PER rate being set to 100')
                    perSlave = 100
            else:
                perSlave = round(100 * (1 - packetsReceived / int(numPackets)), 2)

            if(packetsReceived == 0):
                printWarning('Did not receive any packets')

            if perSlave >= 50.0:
                printWarning(f'Unusually high PER {perSlave}')

        
            if(perSlave > perMax):
                perMax = perSlave
            elif(perSlave < 0):
                perSlave = 0
                
            # Gather the results
            temp_results.append(perSlave)
            

    # Save the results to dataframe


    col_name = f'ch{ch}'
    results_df[col_name] = temp_results


    
    print("perMax: ",perMax)

    if(float(args.limit) != 0.0):
        if(perMax > float(args.limit)):
            print("PER too high!")
            sys.exit(1)

    
# Create the master dataframe
results_df.index = [str(-(x+int(args.channel_loss))) for x in attens]

print(results_df)
results_df.to_csv(args.results,mode='a')

hm = create_heatmap(results_df)
plt.savefig('heatmap.png')



x,y,z,xticks,yticks = plottable_3d_info(results_df)


for i,row in enumerate(y):
    y[i] = [i * int(args.atten_step) + attens[0]] * len(row)

# print(y)
cmap = ListedColormap(MAP_COLORS, name='adi-heatmap')
bounds = [0.0, 0.0001, 0.1, 0.3, 1, 3, 10, 30, 99.9999, 105]
norm = colors.BoundaryNorm(bounds, cmap.N)
mappable = cm.ScalarMappable(norm=norm, cmap=cmap)

fig = plt.figure(figsize=(10,5))
cb = fig.colorbar(mappable)


old_ticks = cb.get_ticks()
new_ticks = []

for i in range(len(old_ticks) - 1):
    new_ticks.append(old_ticks[i] + (old_ticks[i+1] - old_ticks[i])/2)

labels = ['0%', '0%-0.1%', '0.1%-0.3%', '0.3%-1%', '1%-3%', '3%-10%', '10%-30%', '30%-100%', '100%']
cb.set_ticks(new_ticks, labels=labels)
cb.ax.set_ylabel("Packet Error Rate")

axes = fig.add_subplot(projection='3d')
axes.plot_surface(x, y, z,cmap='gnuplot')
axes.set(title='PER Across Channels', xlabel='Channel', ylabel='RX Power',zlabel='PER %')

plt.savefig('surfaceplt.png')




sys.exit(0)
