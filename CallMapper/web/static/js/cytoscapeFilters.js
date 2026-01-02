import { getCy } from './initCytoscape.js';

/*
=============================== FILTERS TO DO ===============================

TCPIP
- Hard - Filter processes that's only communicating with loopback IPs
- Easy - External or local IPs 
- Easy - IPversion
- Easy - Transport protocol
- Easy - Destination port
- Easy - Source port

DNS
- Easy - Has DNS activity (By process)


DONE
- [DONE] Medium - IP query - Check code for help



Kanske lägga till en global lista med DICT type för att visa vilka filter som är aktiva
Ta bort auto filtering kapabiltiies

i ui.js  -> waitForCyAndInitUI
  Lägg till så hostar m.m. populeras kanske

*/

/*
=============================== GENERIC FUNCTIONALITY ===============================
*/

export function hideNodeAndCascade(nodeToHide) {
  const cy = getCy();
  const stack = [nodeToHide];

  while (stack.length > 0) {
    const node = stack.pop();

    if (!node || node.empty() || node.style('display') === 'none') continue;

    // Hide the node itself
    node.style('display', 'none');

    // Hide all visible connected edges
    const edges = node.connectedEdges(':visible');
    edges.style('display', 'none');

    // Check all neighbor nodes of these edges
    edges.connectedNodes().forEach(neighbor => {
      if (neighbor.id() === node.id()) return;

      // Count only edges connecting to visible nodes
      const visibleEdges = neighbor.connectedEdges(':visible');

      if (visibleEdges.length === 0 && neighbor.style('display') !== 'none') {
        // Add to stack to hide it next
        stack.push(neighbor);
      }
    });
  }
}



/*
=============================== TCPIP - Filter by IP ===============================
*/

export function filterIP(ipPrefix) {
  const cy = getCy();
  const normalized = ipPrefix.trim();

  if (normalized === '') {
    return;
  }

  // Step 1: Find matching IP nodes
  const matchingIPs = cy.nodes('node[type = "ip"]').filter(node => {
    const nodeIP = node.data('IP');
    return typeof nodeIP === 'string' && nodeIP.startsWith(normalized);
  });

  if (matchingIPs.empty()) {
    // No matching IPs — hide everything
    cy.nodes().style('display', 'none');
    cy.edges().style('display', 'none');
    return;
  }

  // Step 2: Get all edges directly connected to matching IPs
  const connectedEdges = matchingIPs.connectedEdges();

  // Step 3: Get all nodes connected via those edges
  const connectedNodes = connectedEdges.connectedNodes();

  // Combine IPs + connected nodes
  const nodesToShow = matchingIPs.union(connectedNodes);
  const edgesToShow = connectedEdges;

  // Step 4: Hide everything first
  cy.nodes().style('display', 'none');
  cy.edges().style('display', 'none');

  // Step 5: Show relevant nodes and edges
  nodesToShow.style('display', 'element');
  edgesToShow.style('display', 'element');
}





/*
=============================== CLICKABLE PROCESS/IP/DOMAIN COUNT FUNCTIONALITY ===============================
*/

const focusIndex = {
  process: 0,
  ip: 0,
  domain: 0
};

function resetFocusIndexes() {
  focusIndex.process = 0;
  focusIndex.ip = 0;
  focusIndex.domain = 0;
}

export function focusNextNodeOfType(type) {
  const cy = getCy();

  const nodes = cy.nodes(`node[type = "${type}"]:visible`);
  if (nodes.length === 0) return;

  const index = focusIndex[type] % nodes.length;
  const node = nodes[index];

  focusIndex[type]++;

  cy.nodes().removeClass('highlighted');
  node.addClass('highlighted');

  cy.animate(
    {
      center: { eles: node },
      zoom: Math.max(cy.zoom(), 1.2)
    },
    {
      duration: 400,
      easing: 'ease-in-out'
    }
  );
}

/*
=============================== HIDE ISOLATED NODES ===============================
*/
export function hideIsolatedNodes() {
  const cy = getCy();

  cy.nodes(':isolated').style('display', 'none');
  cy.edges().style('display', 'element');
}


/*
=============================== SHOW ALL NODES ===============================
*/
export function showAllNodes() {
  const cy = getCy();

  cy.nodes().style('display', 'element');
  cy.edges().style('display', 'element');
}


/*
=============================== RESET FILTERS ===============================
*/

export function resetFilters() {
  showAllNodes()
  resetFocusIndexes()
}

export function applyFilters() {
  
  // IP Filtering
  const ipInput = document.getElementById('filter-ip');

  filterIP(ipInput.value)
  resetFocusIndexes()
}
