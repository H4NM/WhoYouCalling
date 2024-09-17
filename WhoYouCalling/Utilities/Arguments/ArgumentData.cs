using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WhoYouCalling.Utilities.Arguments
{
    public struct ArgumentData
    {
        public string Var1 { get; set; }
        public int Var2 { get; set; }
        public bool Var3 { get; set; }

        // You can include a constructor for convenience
        public ArgumentData(string var1, int var2, bool var3)
        {
            Var1 = var1;
            Var2 = var2;
            Var3 = var3;
        }
    }
}
