using SharpPcap;
using SharpPcap.LibPcap;


namespace WhoYouCalling.Network.FPC
{
    internal class BasePacketCapture
    {
        protected static int s_packetCounter;
        protected CaptureFileWriterDevice _captureFileWriterDevice;
        protected LibPcapLiveDevice _captureDevice;

        public int GetPacketCount()
        {
            return s_packetCounter;
        }

        public void SetCaptureDevice(LibPcapLiveDevice device)
        {
            _captureDevice = device;
        }

        public void StopCapture()
        {
            _captureDevice.StopCapture();
            _captureFileWriterDevice.Close();
        }

        protected void device_OnPacketArrival(object sender, PacketCapture e)
        {
            s_packetCounter++;
            var rawPacket = e.GetPacket();
            _captureFileWriterDevice.Write(rawPacket);
            //ConsoleOutput.Print($"Captured packets: {packetIndex}", "debug");
        }
    }
}