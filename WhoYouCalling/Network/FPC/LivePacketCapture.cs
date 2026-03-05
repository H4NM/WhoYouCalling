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
            if (_captureDevice == null)
            {
                return;
            }
            // Register our handler function to the 'packet arrival' event
            _captureDevice.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            _captureDevice.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: Constants.Timeouts.PacketCaptureTimeoutMilliseconds);

            // open the output file
            _captureFileWriterDevice = new CaptureFileWriterDevice(pcapFile);
            _captureFileWriterDevice.Open(_captureDevice);

            _captureDevice.StartCapture();
        }
    }
}
