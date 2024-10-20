using SharpPcap.LibPcap;
using SharpPcap;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.Network.FPC
{
    internal class FilePacketCapture : BasePacketCapture
    {
        public void FilterCaptureFile(string BPFFilter, string fullPcapFile, string filteredPcapFile)
        {
            ICaptureDevice capturedDevice;
            s_packetCounter = 0;
            try
            {
                ConsoleOutput.Print($"Opening saved packet capture file {fullPcapFile}", PrintType.Debug);
                capturedDevice = new CaptureFileReaderDevice(fullPcapFile);
                capturedDevice.Open();
            }
            catch (Exception e)
            {
                ConsoleOutput.Print("Caught exception when opening file" + e.ToString(), PrintType.Debug);
                return;
            }

            try
            {
                ConsoleOutput.Print($"Opening new packet capture file {filteredPcapFile} to save filtered packets", PrintType.Debug);
                _captureFileWriterDevice = new CaptureFileWriterDevice(filteredPcapFile);
                _captureFileWriterDevice.Open();
            }
            catch (Exception e)
            {
                ConsoleOutput.Print("Caught exception when writing to file" + e.ToString(), PrintType.Error);
                return;
            }
            ConsoleOutput.Print($"Setting BPF filter for reading the saved", PrintType.Debug);
            capturedDevice.Filter = BPFFilter;
            capturedDevice.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            var startTime = DateTime.Now;

            ConsoleOutput.Print($"Starting reading packets from {fullPcapFile}", PrintType.Debug);
            capturedDevice.Capture();

            ConsoleOutput.Print($"Finished reading packets from {fullPcapFile}. Closing read", PrintType.Debug);
            capturedDevice.Close();
            ConsoleOutput.Print($"Finished writing packets to {filteredPcapFile}", PrintType.Debug);
            _captureFileWriterDevice.Close();

        }
    }
}
