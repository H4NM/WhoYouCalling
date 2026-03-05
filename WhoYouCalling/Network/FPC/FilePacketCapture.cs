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
                capturedDevice = new CaptureFileReaderDevice(fullPcapFile);
                capturedDevice.Open();
            }
            catch (Exception e)
            {
                ConsoleOutput.Print($"Caught exception trying to read {fullPcapFile}. Error: {e}", PrintType.Error);
                return;
            }

            try
            {
                _captureFileWriterDevice = new CaptureFileWriterDevice(filteredPcapFile);
                _captureFileWriterDevice.Open();
            }
            catch (Exception e)
            {
                ConsoleOutput.Print($"Caught exception when writing to file. Error: {e}", PrintType.Error);
                return;
            }
            capturedDevice.Filter = BPFFilter;
            capturedDevice.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            var startTime = DateTime.Now;

            capturedDevice.Capture();

            capturedDevice.Close();
            _captureFileWriterDevice.Close();

        }
    }
}
