﻿using SharpPcap.LibPcap;
using SharpPcap;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.Network.FPC
{
    internal class LivePacketCapture : BasePacketCapture
    {
        public void StartCaptureToFile(string pcapFile)
        {
            // Register our handler function to the 'packet arrival' event
            _captureDevice.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            ConsoleOutput.Print($"Opening {_captureDevice.Name} for reading packets with read timeout of {readTimeoutMilliseconds}", PrintType.Debug);
            _captureDevice.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            // open the output file
            ConsoleOutput.Print($"Opening {pcapFile} to write packets to", PrintType.Debug);
            _captureFileWriterDevice = new CaptureFileWriterDevice(pcapFile);
            _captureFileWriterDevice.Open(_captureDevice);

            ConsoleOutput.Print($"Starting capture process", PrintType.Debug);
            _captureDevice.StartCapture();
        }
    }
}
