using SharpPcap.LibPcap;
using WhoYouCalling.Network;

namespace WhoYouCalling.Utilities
{
    internal static class BPFFilter
    {
        public static Dictionary<int, string> GetBPFFilter(Dictionary<int, HashSet<NetworkPacket>> bpfFilterBasedDict, bool strictBPFEnabled)
        {
            Dictionary<int, string> bpfFilterPerExecutable = new Dictionary<int, string>();

            foreach (KeyValuePair<int, HashSet<NetworkPacket>> entry in bpfFilterBasedDict) //For each Process 
            {
                if (entry.Value.Count == 0) // Check if the executable has any recorded network activity
                {
                    ConsoleOutput.Print($"Not calculating BPFFilter for PID {entry.Key}. No recored network activity", "debug");
                    continue;
                }
                List<string> FullBPFlistForProcess = new List<string>();
                foreach (NetworkPacket packet in entry.Value) //For each recorded unique network activity
                {
        
                    string partialBPFstring;
                    if (strictBPFEnabled)
                    {
                        partialBPFstring = $"({packet.IPversion} and {packet.TransportProtocol} and src host {packet.SourceIP} and src port {packet.SourcePort} and dst host {packet.DestinationIP} and dst port {packet.DestinationPort})";
                    }
                    else
                    {
                        partialBPFstring = $"({packet.IPversion} and {packet.TransportProtocol} and ((host {packet.SourceIP} and host {packet.DestinationIP}) and ((dst port {packet.DestinationPort} and src port {packet.SourcePort}) or (dst port {packet.SourcePort} and src port {packet.DestinationPort}))))";
                    }
                    FullBPFlistForProcess.Add(partialBPFstring);
                }
                string BPFFilter = string.Join(" or ", FullBPFlistForProcess);
                bpfFilterPerExecutable[entry.Key] = BPFFilter; // Add BPF filter for executable
            }

            if (bpfFilterPerExecutable.Count > 1)
            {
                List<string> tempBPFList = new List<string>();
                foreach (KeyValuePair<int, string> processBPFFilter in bpfFilterPerExecutable)
                {
                    tempBPFList.Add($"({processBPFFilter.Value})");
                }
                bpfFilterPerExecutable[0] = string.Join(" or ", tempBPFList); //0 is the combined PID number for all
            }
            return bpfFilterPerExecutable;
        }
    }
}