using SharpPcap.LibPcap;
using SharpPcap;
using WhoYouCalling.Utilities;


namespace WhoYouCalling.FPC
{
    public class LivePacketCapture : BasePacketCapture
    {
        public void StartCaptureToFile(string pcapFile)
        {
            // Register our handler function to the 'packet arrival' event
            _captureDevice.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            ConsoleOutput.Print($"Opening {_captureDevice.Name} for reading packets with read timeout of {readTimeoutMilliseconds}", "debug");
            _captureDevice.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            // open the output file
            ConsoleOutput.Print($"Opening {pcapFile} to write packets to", "debug");
            _captureFileWriterDevice = new CaptureFileWriterDevice(pcapFile);
            _captureFileWriterDevice.Open(_captureDevice);

            ConsoleOutput.Print($"Starting capture process", "debug");
            _captureDevice.StartCapture();
        }
    }
}
