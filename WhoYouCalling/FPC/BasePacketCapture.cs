using SharpPcap;
using SharpPcap.LibPcap;


namespace WhoYouCalling.FPC
{
    public class BasePacketCapture
    {
        protected static int s_packetCounter = 0;
        protected CaptureFileWriterDevice _captureFileWriterDevice;
        protected LibPcapLiveDevice _captureDevice;

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