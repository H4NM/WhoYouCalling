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

            try
            {
                ConsoleOutput.Print($"Opening saved packet capture file {fullPcapFile}", "debug");
                capturedDevice = new CaptureFileReaderDevice(fullPcapFile);
                capturedDevice.Open();
            }
            catch (Exception e)
            {
                ConsoleOutput.Print("Caught exception when opening file" + e.ToString(), "error");
                return;
            }

            try
            {
                ConsoleOutput.Print($"Opening new packet capture file {filteredPcapFile} to save filtered packets", "debug");
                _captureFileWriterDevice = new CaptureFileWriterDevice(filteredPcapFile);
                _captureFileWriterDevice.Open();
            }
            catch (Exception e)
            {
                ConsoleOutput.Print("Caught exception when writing to file" + e.ToString(), "error");
                return;
            }
            ConsoleOutput.Print($"Setting BPF filter for reading the saved", "debug");
            capturedDevice.Filter = BPFFilter;
            capturedDevice.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            var startTime = DateTime.Now;

            ConsoleOutput.Print($"Starting reading packets from {fullPcapFile}", "debug");
            capturedDevice.Capture();

            ConsoleOutput.Print($"Finished reading packets from {fullPcapFile}. Closing read", "debug");
            capturedDevice.Close();
            ConsoleOutput.Print($"Finished writing packets to {filteredPcapFile}", "debug");
            _captureFileWriterDevice.Close();

            string filterDuration = Generic.GetPresentableDuration(startTime, DateTime.Now);
            string performanceMsg = $"Filtered {s_packetCounter} packets in {filterDuration}";
            ConsoleOutput.Print(performanceMsg, "info");
        }
    }
}
