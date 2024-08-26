using System;
using Microsoft.Msagl.Drawing;

namespace WhoYouCalling.Visualization
{
    public class NetworkGraph
    {
        public void CreateNetworkGraph()
        {

        // Create a graph
        var graph = new Graph("graph");

        // Add nodes and edges
        graph.AddEdge("A", "B");
        graph.AddEdge("B", "C");
        graph.AddEdge("B", "D");

        // Create a viewer for the graph

        }
    }
}
