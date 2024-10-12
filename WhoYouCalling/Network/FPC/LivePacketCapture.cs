using SharpPcap.LibPcap;
using SharpPcap;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.Network.FPC
{
    internal class LivePacketCapture : BasePacketCapture
    {
        public void StartCaptureToFile(string pcapFile)
        {
            s_packetCounter = 0;

            // Register our handler function to the 'packet arrival' event
            _captureDevice.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            ConsoleOutput.Print($"Opening {_captureDevice.Name} for reading packets with read timeout of {Constants.Timeouts.PacketCaptureTimeoutMilliseconds}", PrintType.Debug);
            _captureDevice.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: Constants.Timeouts.PacketCaptureTimeoutMilliseconds);

            // open the output file
            ConsoleOutput.Print($"Opening {pcapFile} to write packets to", PrintType.Debug);
            _captureFileWriterDevice = new CaptureFileWriterDevice(pcapFile);
            _captureFileWriterDevice.Open(_captureDevice);

            ConsoleOutput.Print($"Starting capture process", PrintType.Debug);
            _captureDevice.StartCapture();
        }
    }
}
