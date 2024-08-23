using SharpPcap;
using SharpPcap.LibPcap;

namespace WhoYouCalling.Utilities
{
    public class NetworkPackets
    {

        private static int packetIndex = 0;
        private static int filterPacketIndex = 0;
        private  CaptureFileWriterDevice captureFileWriter;
        private  CaptureFileWriterDevice filteredFileWriter;
        private LibPcapLiveDevice? captureDevice;

        public LibPcapLiveDeviceList GetNetworkInterfaces()
        {
            return LibPcapLiveDeviceList.Instance; // Retrieve the device list
        }

        public static void PrintNetworkInterfaces()
        {
            var devices = LibPcapLiveDeviceList.Instance;
            if (devices.Count < 1)
            {
                ConsoleOutput.Print("No network interfaces were found on this machine.", "error");
                System.Environment.Exit(1);
            }

            int i = 0;
            string deviceMsg;
            foreach (var dev in devices)
            {
                deviceMsg = $"{i}) {dev.Name} {dev.Description}";
                ConsoleOutput.Print(deviceMsg);
                i++;
            }
        }

        public void SetCaptureDevice(LibPcapLiveDevice device)
        {
            captureDevice = device;
        }

        public void StopCapturingNetworkPackets()
        {
            captureDevice.StopCapture();
            captureFileWriter.Close();
        }

        public void CaptureNetworkPacketsToPcap(string pcapFile)
        {
            // Register our handler function to the 'packet arrival' event
            captureDevice.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            ConsoleOutput.Print($"Opening {captureDevice.Name} for reading packets with read timeout of {readTimeoutMilliseconds}", "debug");
            captureDevice.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            // open the output file
            ConsoleOutput.Print($"Opening {pcapFile} to write packets to", "debug");
            captureFileWriter = new CaptureFileWriterDevice(pcapFile);
            captureFileWriter.Open(captureDevice);

            ConsoleOutput.Print($"Starting capture process", "debug");
            captureDevice.StartCapture();
        }

        public void FilterNetworkCaptureFile(string BPFFilter, string fullPcapFile, string filteredPcapFile)
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
                filteredFileWriter = new CaptureFileWriterDevice(filteredPcapFile);
                filteredFileWriter.Open();
            }
            catch (Exception e)
            {
                ConsoleOutput.Print("Caught exception when writing to file" + e.ToString(), "error");
                return;
            }
            ConsoleOutput.Print($"Setting BPF filter for reading the saved", "debug");
            capturedDevice.Filter = BPFFilter;
            capturedDevice.OnPacketArrival +=
                 new PacketArrivalEventHandler(filter_device_OnPacketArrival);

            var startTime = DateTime.Now;

            ConsoleOutput.Print($"Starting reading packets from {fullPcapFile}", "debug");
            capturedDevice.Capture();

            ConsoleOutput.Print($"Finished reading packets from {fullPcapFile}. Closing read", "debug");
            capturedDevice.Close();
            ConsoleOutput.Print($"Finished writing packets to {filteredPcapFile}", "debug");
            filteredFileWriter.Close();
            var endTime = DateTime.Now;

            var duration = endTime - startTime;
            string performanceMsg = $"Read {filterPacketIndex} packets in {duration.TotalSeconds}s";
            ConsoleOutput.Print(performanceMsg, "info");
        }
        private void filter_device_OnPacketArrival(object sender, PacketCapture e)
        {
            filterPacketIndex++;
            var rawPacket = e.GetPacket();
            filteredFileWriter.Write(rawPacket);
            //ConsoleOutput.Print($"Captured packets: {filterPacketIndex}", "debug");

        }

        private void device_OnPacketArrival(object sender, PacketCapture e)
        {
            packetIndex++;
            var rawPacket = e.GetPacket();
            captureFileWriter.Write(rawPacket);
            //ConsoleOutput.Print($"Captured packets: {packetIndex}", "debug");
        }
    }

}