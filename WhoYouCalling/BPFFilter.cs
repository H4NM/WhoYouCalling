namespace WhoYouCalling.Utilities
{
    public static class BPFFilter
    {
        public static Dictionary<int, string> GetBPFFilter(Dictionary<int, HashSet<string>> bpfFilterBasedDict, bool strictBPFEnabled)
        {

            Dictionary<int, string> bpfFilterPerExecutable = new Dictionary<int, string>();

            foreach (KeyValuePair<int, HashSet<string>> entry in bpfFilterBasedDict) //For each Process 
            {
                if (entry.Value.Count == 0) // Check if the executable has any recorded network activity
                {
                    ConsoleOutput.Print($"Not calculating BPFFilter for PID {entry.Key}. No recored network activity", "debug");
                    continue;
                }
                List<string> FullBPFlistForProcess = new List<string>();
                foreach (string entryCSV in entry.Value) //For each recorded unique network activity
                {
                    string[] parts = entryCSV.Split(',');

                    string ipVersion = parts[0];
                    string transportProto = parts[1];
                    string srcAddr = parts[2];
                    string srcPort = parts[3];
                    string dstAddr = parts[4];
                    string dstPort = parts[5];
                    string partialBPFstring = "";
                    if (strictBPFEnabled)
                    {
                        partialBPFstring = $"({ipVersion} and {transportProto} and src host {srcAddr} and src port {srcPort} and dst host {dstAddr} and dst port {dstPort})";
                    }
                    else
                    {
                        partialBPFstring = $"({ipVersion} and {transportProto} and ((host {srcAddr} and host {dstAddr}) and ((dst port {dstPort} and src port {srcPort}) or (dst port {srcPort} and src port {dstPort}))))";
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