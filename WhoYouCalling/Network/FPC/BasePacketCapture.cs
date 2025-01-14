using SharpPcap;
using SharpPcap.LibPcap;

namespace WhoYouCalling.Network.FPC
{
    internal class BasePacketCapture
    {
        protected static int s_packetCounter;
        protected CaptureFileWriterDevice? _captureFileWriterDevice;
        protected LibPcapLiveDevice? _captureDevice;

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
            if (_captureDevice != null) { 
                _captureDevice.StopCapture();
            }
            if (_captureFileWriterDevice != null)
            {
                _captureFileWriterDevice.Close();
            }
        }

        protected void device_OnPacketArrival(object sender, PacketCapture e)
        {
            s_packetCounter++;
            var rawPacket = e.GetPacket();
            if (_captureFileWriterDevice != null)
            { 
                _captureFileWriterDevice.Write(rawPacket);
            }
        }
    }
}