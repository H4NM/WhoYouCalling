

import { applyFilters, resetFilters, focusNextNodeOfType } from './cytoscapeFilters.js';
import { getCy } from './initCytoscape.js';



/*
=============================== CYTOSCAPE, FILTERING - RESET BUTTON ===============================
*/

document
  .getElementById('btn-reset-filters')
  .addEventListener('click', () => {
    resetFilters();
  });

/*
=============================== CYTOSCAPE, FILTERING - FILTER BUTTON ===============================
*/

document
  .getElementById('btn-apply-filters')
  .addEventListener('click', () => {
    applyFilters();
  });



/*
=============================== CYTOSCAPE - POPULATE NUMBER OF NODES ===============================
*/

document
  .getElementById('count-processes')
  .addEventListener('click', () => {
    focusNextNodeOfType('process');
  });

document
  .getElementById('count-ips')
  .addEventListener('click', () => {
    focusNextNodeOfType('ip');
  });

document
  .getElementById('count-domains')
  .addEventListener('click', () => {
    focusNextNodeOfType('domain');
  });

function updateNodeCounts() {
  const cy = getCy();

  const nodes = cy.nodes(':visible');

  const counts = {
    process: 0,
    ip: 0,
    domain: 0
  };

  nodes.forEach(node => {
    const type = node.data('type');
    if (counts[type] !== undefined) {
      counts[type]++;
    }
  });

  document.getElementById('count-processes').textContent =
    `Processes: ${counts.process}`;

  document.getElementById('count-ips').textContent =
    `IPs: ${counts.ip}`;

  document.getElementById('count-domains').textContent =
    `Domains: ${counts.domain}`;
}

function waitForCyAndInitUI() {
  try {
    const cy = getCy();
    updateNodeCounts();

    cy.on('add remove data style', updateNodeCounts);
  } catch {
    setTimeout(waitForCyAndInitUI, 50);
  }
}

waitForCyAndInitUI();

/*
=============================== PROGRAM - TAB MANAGEMENT ===============================
*/

const tabs = document.querySelectorAll('.tab');
const views = document.querySelectorAll('.view');

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        // Remove active states
        tabs.forEach(t => t.classList.remove('active'));
        views.forEach(v => v.classList.remove('active'));

        // Activate selected
        tab.classList.add('active');
        document.getElementById(tab.dataset.view).classList.add('active');
    });
});