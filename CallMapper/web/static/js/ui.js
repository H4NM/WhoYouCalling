
/*
=============================== GENERIC FUNCTIONALITY ===============================
*/
let areApisAvailable = null;
let cachedApiLookups = null;

const wrapperFilterSpinner = document.querySelector('.node-count-wrapper');
const overlayFilterSpinner = document.getElementById('cy-loading-overlay');

const NODE_FIELD_CONFIG = {
  process: [
    ['Name', 'Process name'],
    ['PID', 'PID'],
    ['SessionID', 'Session ID'],
    ['Running as user', 'Running as user'],
    ['Protected process', 'Protected process'],
    ['Commandline', 'Command line'],
    ['Started', 'Process Started'],
    ['Stopped', 'Process Stopped'],
    ['File path', 'File path'],
    ['Is signed', 'Is Signed'],
    ['FileCompany', 'Company'],
    ['FileProductName', 'Product'],
    ['FileProductVersion', 'Version'],
    ['FileSize', 'File size'],
    ['FileEntropy', 'Entropy'],
    ['Created', 'Executable Created'],
    ['MD5', 'MD5'],
    ['SHA1', 'SHA1'],
    ['SHA256', 'SHA256']
  ],

  ip: [
    ['Private', 'LOCAL'],
    ['Multicast', 'Multicast'],
    ['Local', 'Localhost or linklocal'],
    ['IPv4', 'IPv4']
  ],

  domain: [
  ],

  capture: [
    ['Hostname', 'Hostname'],
    ['HostOS', 'OS'],
    ['HostTimeZone', 'Time zone'],
    ['WYCMode', 'WYC Mode'],
    ['WYCVersion', 'Version'],
    ['FPC', 'FPC'],
    ['WYCResultsOutputPath', 'Output path'],
    ['WYCCommandline', 'Commandline'],
    ['StartTime', 'Start time'],
    ['StopTime', 'Stop time'],
    ['PresentableDuration', 'Duration']
  ]
};


const CYTOSCAPE_OBJECT_DESIGN_CHARACTERISTICS = {
  node: {
    process:{
      color: "#e200e2"
    },
    ip: {
      color: "#2ffcf3",

    },
    domain:{
      color: "#fcf62f"
    },
    default:{
      shape: 'ellipse',
      borderWidth: 2,
      borderColor: '#000',
      borderStyle: 'solid',
      textVAlign: 'center',
      textMarginX: 0,
      textMarginY: 25,
      width: 30,
      height: 30
    }
  },
  edge: {
    default:{
      curveStyle: 'bezier',
      targetArrowShape: 'triangle',
      width: 1,
      lineColor: '#9e9e9e',
      lineStyle: 'dotted',
      targetArrowColor: '#9e9e9e'
    },
    dnsQuery:{
    },
    dnsResolution:{
    },
    tcpipConnection:{
      width: 1,
      lineColor: '#303030',
      targetArrowColor: '#303030',
      lineStyle: 'dotted'
    },
    processStart:{
      width: 2,
      lineColor: '#000',
      targetArrowColor: '#000',
      lineStyle: 'solid'
    }
  },
  highlighted:{
    borderWidth: 4,
    width: 65,
    height: 65,
    transitionProperty: 'width height font-size font-weight',
    transitionDuration: '0.3s',
    transitionTimingFunction: 'ease',
    fontWeight: 'bold',
    fontSize: '22px',
    textOpacity: 1,
    zIndex: 9999
  }
}


function highlightCard(card, highlight) {
  if (highlight) {
    card.classList.add('glow');
  } else {
    card.classList.remove('glow');
  }
}

function removeHighlightCard(card) {
  card.classList.remove('glow');
}

function getNodeColor(nodeType){
  return CYTOSCAPE_OBJECT_DESIGN_CHARACTERISTICS.node[nodeType].color;
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

function focusNextNodeOfType(type) {
  const cy = getCy();

  const nodes = cy.nodes(`node[type = "${type}"]:visible`);
  if (nodes.length === 0) return;

  const index = focusIndex[type] % nodes.length;
  const node = nodes[index];

  focusIndex[type] = index + 1;

  cy.nodes().removeClass('highlighted');
  node.addClass('highlighted');

  cy.animate(
    {
      center: { eles: node },
      zoom: Math.max(cy.zoom(), 1.2)
    },
    {
      duration: 300,
      easing: 'ease-in-out',
      complete: () => {
        showNodeTooltip(node, areApisAvailable, availableAPIs);
      }
    }
  );
}



function initCallMapperMetadata(metadata) {
  const section = document.querySelector(".filter-section");

  for (const key in metadata) {
    const value = metadata[key];
    const wrapper = document.createElement("div");
    wrapper.className = "wyc-checkbox-item wyc-tooltip-container";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = `wyc-${key}`;
    checkbox.value = key;
    checkbox.defaultChecked = true;

    const label = document.createElement("label");
    label.htmlFor = checkbox.id;
    label.className = "wyc-hostname-label";

    const labelText = document.createElement("span");
    labelText.className = "wyc-hostname-text";
    labelText.textContent = key;
    labelText.style.backgroundColor = value.callmapper_color;

    label.appendChild(labelText);


    wrapper.appendChild(checkbox);
    wrapper.appendChild(label);

    section.appendChild(wrapper);
  };
}

/*
=============================== FILTERING - SPINNER ===============================
*/

function showFilterSpinner() {
  overlayFilterSpinner.classList.remove('hidden');
  wrapperFilterSpinner.classList.add('loading');
}

function hideFilterSpinner() {
  overlayFilterSpinner.classList.add('hidden'); 
  wrapperFilterSpinner.classList.remove('loading');
}

/*
=============================== CYTOSCAPE - POPULATE NUMBER OF NODES ===============================
*/

function setupClickableCounters(){

  document.getElementById('count-processes').addEventListener('click', () => {
    focusNextNodeOfType('process');
  });

  document.getElementById('count-ips').addEventListener('click', () => {
    focusNextNodeOfType('ip');
  });

  document.getElementById('count-domains').addEventListener('click', () => {
    focusNextNodeOfType('domain');
  });
}

function updateNodeCounts() {
  const cy = getCy();
  const nodes = cy.nodes(':visible');

  const counts = { process: 0, ip: 0, domain: 0 };
  nodes.forEach(node => {
    const type = node.data('type');
    if (counts[type] !== undefined) counts[type]++;
  });

  document.querySelector('#count-processes .node-count-value').textContent = counts.process;
  document.querySelector('#count-ips .node-count-value').textContent = counts.ip;
  document.querySelector('#count-domains .node-count-value').textContent = counts.domain;
}

/*
=============================== PROGRAM - BUILD SUMMARY META PANE ===============================
*/
function buildSummaryMetaWYCFilesTable(metadata) {
  const table = document.querySelector("#metadata-info-table");
  const thead = table.querySelector("thead");
  const tbody = table.querySelector("tbody");

  thead.innerHTML = "";
  tbody.innerHTML = "";

  const headerRow = document.createElement("tr");

  const firstTh = document.createElement("th");
  firstTh.textContent = "ID";
  headerRow.appendChild(firstTh);

  for (const field of NODE_FIELD_CONFIG.capture) {
    const th = document.createElement("th");
    th.textContent = field[1]; 
    headerRow.appendChild(th);    
  }

  thead.appendChild(headerRow);

  for (const captureID in metadata) {
    const metadataForCapture = metadata[captureID];
    const row = document.createElement("tr");

    const td = document.createElement("td");
    td.textContent = captureID;
    td.className = 'wyc-hostname-text';
    td.id = "wyc-summary-capture-cell-id"
    td.style.backgroundColor = metadataForCapture.callmapper_color;
    
    row.appendChild(td);

    for (const field of NODE_FIELD_CONFIG.capture) {
      const td = document.createElement("td");
      td.textContent = metadataForCapture[field[0]];
      row.appendChild(td);
    }

    tbody.appendChild(row);
  }
}

/*
=============================== PROGRAM - BUILD SUMMARY TABLES ===============================
*/
function buildSummaryTables(unique) {
  const processBody = document.querySelector('#summary-table-processes tbody');
  if (unique.process_names) {
    unique.process_names.forEach(name => {
      const row = processBody.insertRow();
      const cell = row.insertCell();
      cell.textContent = name;
    });
  }

  const ipBody = document.querySelector('#summary-table-ips tbody');
  ipBody.innerHTML = '';
  if (unique.ips) {
    unique.ips.forEach(ip => {
      const row = ipBody.insertRow();
      const cell = row.insertCell();
      cell.textContent = ip;
    });
  }

  const domainBody = document.querySelector('#summary-table-domains tbody');
  domainBody.innerHTML = '';
  if (unique.domains) {
    unique.domains.forEach(domain => {
      const row = domainBody.insertRow();
      const cell = row.insertCell();
      cell.textContent = domain;
    });
  }
}

/*
=============================== PROGRAM - BUILD SUMMARY PORTS TABLES ===============================
*/
function buildSummaryTCPPortsTables(tcpPorts) {
  const tcpTableBody = document.querySelector('#summary-table-tcp-ports tbody');

  tcpPorts.forEach(([port, count]) => {
    const row = tcpTableBody.insertRow();
    const cellPort = row.insertCell();
    const cellCount = row.insertCell();
    cellPort.textContent = port;
    cellCount.textContent = count;
  });
}

function buildSummaryUDPPortsTables(udpPorts) {
  const udpTableBody = document.querySelector('#summary-table-udp-ports tbody');

  udpPorts.forEach(([port, count]) => {
    const row = udpTableBody.insertRow();
    const cellPort = row.insertCell();
    const cellCount = row.insertCell();
    cellPort.textContent = port;
    cellCount.textContent = count;
  });
}


/*
=============================== PROGRAM - TAB MANAGEMENT ===============================
*/

async function enableTabSwitching() {
  const tabs = document.querySelectorAll('.tab');
  const views = document.querySelectorAll('.view');

  tabs.forEach(tab => {
      tab.addEventListener('click', () => {
          tabs.forEach(t => t.classList.remove('active'));
          views.forEach(v => v.classList.remove('active'));

          tab.classList.add('active');
          document.getElementById(tab.dataset.view).classList.add('active');
          if (tab.dataset.view === 'view2') {
            const cy = getCy();
            cy.fit();     
          }
      });
  });
}

function activateView(viewId) {
  const tabs = document.querySelectorAll('.tab');
  const views = document.querySelectorAll('.view');

  tabs.forEach(t => t.classList.remove('active'));
  views.forEach(v => v.classList.remove('active'));

  const tab = document.querySelector(`.tab[data-view="${viewId}"]`);
  const view = document.getElementById(viewId);
  if (tab && view) {
    tab.classList.add('active');
    view.classList.add('active');
  }
}

/*
=============================== PROGRAM - AUTO FILTERING ===============================
*/


function setupAutoFiltering() {
  const autoFilterCheckbox = document.getElementById('auto-filter-checkbox');

  const filterInputs = document.querySelectorAll(
    '#cytoscape-left-pane input, #cytoscape-left-pane select'
  );

  filterInputs.forEach(input => {
    const eventType = input.tagName === 'INPUT' && input.type === 'text' ? 'input' : 'change';
    
    input.addEventListener(eventType, () => {
      if (autoFilterCheckbox.checked) {
        applyFilters();
      }
    });
  });
}

/*
=============================== PROGRAM - GENERIC ===============================
*/

function waitForCyAndInitUI() {
  try {
    const cy = getCy();
    updateNodeCounts();

    cy.on('add remove data style', updateNodeCounts);
  } catch {
    setTimeout(waitForCyAndInitUI, 50);
  }
}


function nextFrame() {
  return new Promise(resolve => setTimeout(resolve, 0));
}

/*
=============================== PROGRAM - MAIN BUTTONS ===============================
*/

function setupMainButtonFunctionality(){
    document
      .getElementById('btn-reset-filters')
      .addEventListener('click', () => {
        resetFilters();
      });

    document
      .getElementById('btn-apply-filters')
      .addEventListener('click', () => {
        applyFilters();
      });
}

