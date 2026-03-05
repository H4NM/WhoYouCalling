
let DEFAULT_VALUE_SELECTION = 'ANYTHING';
let MANUALLY_FILTERED_NODES = []

/*
=============================== GENERIC ===============================
*/

function hideNode(node) {
  node.style('display', 'none');

  const id = node.id();
  if (!MANUALLY_FILTERED_NODES.includes(id)) {
    MANUALLY_FILTERED_NODES.push(id);
  }
  applyFilters();
}

/*
=============================== WYC - Filter by capture file ===============================
*/

function getSelectedCaptureFileIDs() {
    return Array.from(
      document.querySelectorAll(
        '.filter-section input[type="checkbox"]:checked'
      )
    ).map(cb => Number(cb.value));
}

function getBaseNodesByCaptureFile(cy, captureFileIDs) {
  if (!Array.isArray(captureFileIDs) || captureFileIDs.length === 0) {
    return cy.collection(); 
  }

  return cy.nodes().filter(node => {
    const resultIds = node.data('result_file_id');
    if (!Array.isArray(resultIds)) return false;

    return resultIds.some(id => captureFileIDs.includes(id));
  });
}

/*
=============================== GENERAL - Manually filtered nodes ===============================
*/

function filterManuallyFilteredNodes(nodes) {
  if (!MANUALLY_FILTERED_NODES.length) {
    return {
      nodes,
      matched: nodes.collection()
    };
  }

  const manuallyFiltered = nodes.filter(node =>
    MANUALLY_FILTERED_NODES.includes(node.id())
  );

  return {
    nodes: nodes.difference(manuallyFiltered),
    matched: manuallyFiltered
  };
}

function filterOutIPLoopbackOrLinklocal(nodes){

  const matchingIPs = nodes.filter(node => {
    if (node.data('type') !== 'ip') return false;

    const isLocalHostOrLinkLocal = node.data('Local');
    if (isLocalHostOrLinkLocal == null) return false;

    return !isLocalHostOrLinkLocal;
  });

  const nonIPNodes = nodes.filter(node => node.data('type') !== 'ip');

  return {
    nodes: matchingIPs.union(nonIPNodes),
    matched: matchingIPs
  };
}


/*
=============================== GENERAL - Filter nodes that are not connected ===============================
*/
function filterProcessesWithoutTCPIPActivity(nodes, edges) {

  const processNodes = nodes.filter('[type = "process"]');

  const tcpipEdges = edges.filter(edge => {
    const s = edge.source().data('type');
    const t = edge.target().data('type');
    return (
      (s === 'process' && t === 'ip') ||
      (s === 'ip' && t === 'process')
    );
  });

  const processesWithTCPIP = tcpipEdges.connectedNodes('[type = "process"]');
  const processesWithoutTCPIP = processNodes.difference(processesWithTCPIP);
  const remainingNodes = nodes.difference(processesWithoutTCPIP);

  return {
    nodes: remainingNodes,
    matched: processesWithoutTCPIP
  };
}


/*
=============================== GENERAL - Filter ip and domain nodes that are not connected to a process ===============================
*/
function filterOrphanNonProcessNodes(nodes, edges) {

  const processEdges = edges.filter(edge => {
    const s = edge.source().data('type');
    const t = edge.target().data('type');
    return s === 'process' || t === 'process';
  });

  const nonProcessTypes = nodes.filter('[type = "ip"], [type = "domain"]');

  const connectedToProcess = processEdges
    .connectedNodes()
    .intersection(nonProcessTypes);

  const orphanNodes = nonProcessTypes.difference(connectedToProcess);

  const remainingNodes = nodes.difference(orphanNodes);

  return {
    nodes: remainingNodes,
    matched: orphanNodes
  };
}



/*
=============================== TCPIP - Filter by IP ===============================
*/

function filterIPsByPrefix(nodes, input) {

  const isNegated = input.startsWith('!');
  const prefix = isNegated ? input.slice(1) : input;
  if (!prefix) {
    return { nodes, matched: nodes.collection() };
  }

  const matchingIPs = nodes.filter(node => {
    if (node.data('type') !== 'ip') return false;

    const ip = node.data('IP');
    return typeof ip === 'string' && ip.startsWith(prefix);
  });

  if (isNegated) {
    return {
      nodes: nodes.difference(matchingIPs),
      matched: matchingIPs
    };
  }

  const nonIPNodes = nodes.filter(node => node.data('type') !== 'ip');

  return {
    nodes: matchingIPs.union(nonIPNodes),
    matched: matchingIPs
  };
}

/*
=============================== DNS - Filter by domain ===============================
*/

function filterDomainsBySubstring(nodes, input) {

  const isNegated = input.startsWith('!');
  const searchTerm = isNegated ? input.slice(1) : input;
  if (!searchTerm) {
    return { nodes, matched: nodes.collection() };
  }

  const matchingDomains = nodes.filter(node => {
    if (node.data('type') !== 'domain') return false;

    const nodeDomain = node.data('Domain');
    return typeof nodeDomain === 'string' && nodeDomain.toLowerCase().includes(searchTerm);
  });

  if (isNegated) {
    return {
      nodes: nodes.difference(matchingDomains),
      matched: matchingDomains
    };
  }

  const nonDomainNodes = nodes.filter(node => node.data('type') !== 'domain');

  return {
    nodes: matchingDomains.union(nonDomainNodes),
    matched: matchingDomains
  };
}

/*
=============================== PROCESS - Filter by Name ===============================
*/

function filterProcessesByName(nodes, input) {

  const isNegated = input.startsWith('!');
  const searchTerm = isNegated ? input.slice(1) : input;
  if (!searchTerm) return { nodes, matched: nodes.collection() };

  const matchingProcesses = nodes.filter(node => {
    if (node.data('type') !== 'process') return false;

    const nodeProcessName = node.data('Name');
    return typeof nodeProcessName === 'string' && nodeProcessName.toLowerCase().includes(searchTerm);
  });

  if (isNegated) {
    return {
      nodes: nodes.difference(matchingProcesses),
      matched: matchingProcesses
    };
  }

  const nonProcessNodes = nodes.filter(node => node.data('type') !== 'process');

  return {
    nodes: matchingProcesses.union(nonProcessNodes),
    matched: matchingProcesses
  };
}


/*
=============================== EXECUTABLE - Filter by CREATION DATE ===============================
*/

function parseDateTime(dateStr) {
  if (!dateStr) return null;

  let value = dateStr.trim();

  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    value += ' 00:00:00'; 
  }

  const [d, t] = value.split(' ');
  if (!d || !t) return null;

  const date = new Date(value);
  return isNaN(date) ? null : date;
}

function filterExecutablesByCreationDate(nodes, input, afterDate) {

  const inputDate = parseDateTime(input);
  if (!inputDate) {
    return { nodes, matched: nodes.collection() };
  }

  const matchingProcesses = nodes.filter(node => {
    if (node.data('type') !== 'process') return false;

    const nodeCreationDateStr = node.data('Created');
    const nodeDate = parseDateTime(nodeCreationDateStr);
    if (!nodeDate) return false;
    if (afterDate){
      return nodeDate >= inputDate;
    }else{
      return nodeDate <= inputDate;
    }
  });

  const nonProcessNodes = nodes.filter(node => node.data('type') !== 'process');

  return {
    nodes: matchingProcesses.union(nonProcessNodes),
    matched: matchingProcesses
  };
}


/*
=============================== TCPIP - Filter by destination port ===============================
*/


function filterEdgesByDestinationPort(edges, input) {
  const raw = input.trim();
  if (!raw) {
    return { edges, matched: edges.collection() };
  }

  const isNegated = raw.startsWith('!');
  const portValue = isNegated ? raw.slice(1) : raw;
  if (!portValue) {
    return { edges, matched: edges.collection() };
  }

  const relevantEdges = edges.filter(edge => {
    const sourceType = edge.source().data('type');
    const targetType = edge.target().data('type');
    return (
      (sourceType === 'process' && targetType === 'ip') ||
      (sourceType === 'ip' && targetType === 'process')
    );
  });

  const matchingEdges = relevantEdges.filter(edge => {
    const port = edge.data('dest_port');
    if (port == null) return false;
    return String(port) === portValue;
  });

  const resultEdges = isNegated
    ? edges.difference(matchingEdges)
    : matchingEdges.union(edges.difference(relevantEdges));

  return {
    edges: resultEdges,
    matched: matchingEdges
  };
}



/*
=============================== TCPIP - Filter by IP Version (v4 / v6) ===============================
*/

function filterIPVersion(nodes, input) {
  const version = input.toUpperCase();

  const matchingIPs = nodes.filter(node => {
    if (node.data('type') !== 'ip') return false;

    const isIPv4 = node.data('IPv4');
    if (isIPv4 == null) return false;

    if (version === 'V4') return isIPv4 === true;
    if (version === 'V6') return isIPv4 === false;

    return false;
  });


  const nonIPNodes = nodes.filter(node => node.data('type') !== 'ip');

  return {
    nodes: matchingIPs.union(nonIPNodes),
    matched: matchingIPs
  };
}


/*
=============================== TCPIP - Filter by IP zone (External / Local) ===============================
*/

function filterIPZone(nodes, input) {

  const matchingIPs = nodes.filter(node => {
    if (node.data('type') !== 'ip') return false;

    const isPrivate = node.data('Private');
    if (isPrivate == null) return false;

    if (input === 'External') return isPrivate === false;
    if (input === 'Local') return isPrivate === true;

    return false;
  });

  const nonIPNodes = nodes.filter(node => node.data('type') !== 'ip');

  return {
    nodes: matchingIPs.union(nonIPNodes),
    matched: matchingIPs
  };
}


/*
=============================== TCPIP - Filter by transport protocol ===============================
*/

function filterEdgesByTransportProtocol(edges, input) {
  const raw = input.trim();
  if (!raw || raw === DEFAULT_VALUE_SELECTION) {
    return { edges, matched: edges.collection() };
  }

  const relevantEdges = edges.filter(edge => {
    const sourceType = edge.source().data('type');
    const targetType = edge.target().data('type');
    return (
      (sourceType === 'process' && targetType === 'ip') ||
      (sourceType === 'ip' && targetType === 'process')
    );
  });

  const matchingEdges = relevantEdges.filter(edge => {
    const protocol = edge.data('protocol');
    if (!protocol) return false;
    return protocol === raw;
  });

  const nonRelevantEdges = edges.difference(relevantEdges);

  return {
    edges: matchingEdges.union(nonRelevantEdges),
    matched: matchingEdges
  };
}





/*
=============================== EXECUTABLE - Filter by Path ===============================
*/

function normalizeWinPathForCompare(path) {
  if (typeof path !== 'string') return '';
  return path.replace(/\\/g, '/').replace(/\/+/g, '/').toLowerCase();
}


function filterExecutablesByPath(nodes, input) {
  const isNegated = input.startsWith('!');
  const searchTerm = isNegated ? input.slice(1) : input;
  if (!searchTerm) {
    return { nodes, matched: nodes.collection() };
  }

  const matchingExecutables = nodes.filter(node => {
    if (node.data('type') !== 'process') return false;

    const nodeExecutablePath = node.data('File path');
    if (typeof nodeExecutablePath !== 'string') return false;

    const normalizedNodePath = normalizeWinPathForCompare(nodeExecutablePath);
    return normalizedNodePath.includes(normalizeWinPathForCompare(searchTerm));
  });

  if (isNegated) {
    return {
      nodes: nodes.difference(matchingExecutables),
      matched: matchingExecutables
    };
  }

  const nonProcessNodes = nodes.filter(node => node.data('type') !== 'process');

  return {
    nodes: matchingExecutables.union(nonProcessNodes),
    matched: matchingExecutables
  };
}


/*
=============================== EXECUTABLE - Filter by digital signature ===============================
*/

function filterExecutableSignature(nodes, input) {
  
  const matchingProcesses = nodes.filter(node => {
    if (node.data('type') !== 'process') return false;

    const isSigned = node.data('Is signed');
    if (isSigned == null) return false;

    if (input === 'YES') return isSigned === true;
    if (input === 'NO') return isSigned === false;

    return false;
  });

  const nonProcessNodes = nodes.filter(node => node.data('type') !== 'process');

  return {
    nodes: matchingProcesses.union(nonProcessNodes),
    matched: matchingProcesses
  };
}




/*
=============================== SHOW ALL NODES ===============================
*/
function showAllNodes(cy) {
  cy.nodes().style('display', 'element');
  cy.edges().style('display', 'element');
}


/*
=============================== RESET FILTERS ===============================
*/

function resetFilters() {
  const textInputs = document.querySelectorAll('input[type="text"]');
  textInputs.forEach(input => {
    input.value = '';
  });
  MANUALLY_FILTERED_NODES = []

  document.getElementById('filter-process-has-tcpip-activity').checked = false;
  document.getElementById('filter-ip-and-domain-without-process').checked = false;
  document.getElementById('filter-hide-isolated-nodes').checked = false;
  document.getElementById('filter-hide-loopback-or-linklocal').checked = false;

  const selects = document.querySelectorAll('select');
  selects.forEach(select => {
    select.selectedIndex = 0; 
  });

  const autoFilterCheckbox = document.getElementById('auto-filter-checkbox');
  if (autoFilterCheckbox.checked) {
    applyFilters();
  }
}


function applyFilters() {
  showFilterSpinner();

  const cy = getCy();
  const wycResultFileIds = getSelectedCaptureFileIDs();

  let activeNodes = getBaseNodesByCaptureFile(cy, wycResultFileIds);
  const totalNodeCount = activeNodes.length;

  if (activeNodes.empty()) {
    cy.nodes().style('display', 'none');
    cy.edges().style('display', 'none');
    return;
  }


  // GET CARD WITH COUNTERS
  const processCard = document.getElementById('count-processes');
  const ipCard = document.getElementById('count-ips');
  const domainCard = document.getElementById('count-domains');

  removeHighlightCard(processCard);
  removeHighlightCard(ipCard);
  removeHighlightCard(domainCard);

  // GET INPUT VALUES
  const filterIPInput = document.getElementById('filter-ip').value.trim();
  const filterIPZoneInput = document.getElementById('filter-ip-zone').value;
  const filterIPVersionInput = document.getElementById('filter-ip-version').value;

  const filterIPLoopbackOrLinklocal = document.getElementById('filter-hide-loopback-or-linklocal').checked;
  const filterProcessWithoutTCPIPActivity = document.getElementById('filter-process-has-tcpip-activity').checked;
  const filterIPAndDomainWithoutProcess = document.getElementById('filter-ip-and-domain-without-process').checked;
  const filterIsolatedNodes = document.getElementById('filter-hide-isolated-nodes').checked;

  const filterDomainNameInput = document.getElementById('filter-domain').value.trim();
  const filterProcessNameInput = document.getElementById('filter-process-name').value.trim();
  const filterProcessExecutablePathInput = document.getElementById('filter-executable-path').value.trim();
  const filterProcessExecutableIsSignedInput = document.getElementById('filter-executable-is-signed').value;
  const filterProcessExecutableCreatedAfter = document.getElementById('filter-executable-created-after').value.trim();
  const filterProcessExecutableCreatedBefore = document.getElementById('filter-executable-created-before').value.trim();

  // FILTER MANUALLY HIDDEN NODES
  activeNodes = filterManuallyFilteredNodes(activeNodes).nodes;


  // TCPIP NODE FILTERING
  if (filterIPInput) {
    const { nodes, matched } = filterIPsByPrefix(activeNodes, filterIPInput);
    activeNodes = nodes;
    highlightCard(ipCard, matched.length > 0);
  }

  if (filterIPZoneInput !== DEFAULT_VALUE_SELECTION) {
    const { nodes, matched } = filterIPZone(activeNodes, filterIPZoneInput);
    activeNodes = nodes;
    highlightCard(ipCard, matched.length > 0);
  }

  if (filterIPVersionInput !== DEFAULT_VALUE_SELECTION) {
    const { nodes, matched } = filterIPVersion(activeNodes, filterIPVersionInput);
    activeNodes = nodes;
    highlightCard(ipCard, matched.length > 0);
  }

  // DOMAIN NODE FILTERING
  if (filterDomainNameInput) {
    const { nodes, matched } = filterDomainsBySubstring(activeNodes, filterDomainNameInput.toLowerCase());
    activeNodes = nodes;
    highlightCard(domainCard, matched.length > 0);
  }

  // PROCESS NODE FILTERING
  if (filterProcessNameInput) {
    const { nodes, matched } = filterProcessesByName(activeNodes, filterProcessNameInput.toLowerCase());
    activeNodes = nodes;
    highlightCard(processCard, matched.length > 0);
  }
  if (filterProcessExecutablePathInput) {
    const { nodes, matched } = filterExecutablesByPath(activeNodes, filterProcessExecutablePathInput.toLowerCase());
    activeNodes = nodes;
    highlightCard(processCard, matched.length > 0);
  }
  if (filterProcessExecutableIsSignedInput !== DEFAULT_VALUE_SELECTION) {
    const { nodes, matched } = filterExecutableSignature(activeNodes, filterProcessExecutableIsSignedInput);
    activeNodes = nodes;
    highlightCard(processCard, matched.length > 0);
  }

  if (filterProcessExecutableCreatedAfter) {
    const { nodes, matched } = filterExecutablesByCreationDate(activeNodes, filterProcessExecutableCreatedAfter, true);
    activeNodes = nodes;
    highlightCard(processCard, matched.length > 0);
  }
  
  if (filterProcessExecutableCreatedBefore) {
    const { nodes, matched } = filterExecutablesByCreationDate(activeNodes, filterProcessExecutableCreatedBefore, false);
    activeNodes = nodes;
    highlightCard(processCard, matched.length > 0);
  }

  let activeEdges = cy.edges().filter(edge =>
    activeNodes.contains(edge.source()) &&
    activeNodes.contains(edge.target())
  );

  activeEdges = filterEdgesByDestinationPort(activeEdges, document.getElementById('filter-dest-port').value).edges;
  activeEdges = filterEdgesByTransportProtocol(activeEdges, document.getElementById('filter-transport-protocol').value).edges;


  // FILTER OUT PROCESSES WITHOUT TCPIP
  if (filterProcessWithoutTCPIPActivity) {
    activeNodes = filterProcessesWithoutTCPIPActivity(activeNodes, activeEdges).nodes;
    activeEdges = activeEdges.filter(edge =>
      activeNodes.contains(edge.source()) && activeNodes.contains(edge.target())
    );
  }

  // FILTER OUT IPS AND DOMAINS WITHOUT CONNECTED PROCESSES
  if (filterIPAndDomainWithoutProcess) {
    activeNodes = filterOrphanNonProcessNodes(activeNodes, activeEdges).nodes;
    activeEdges = activeEdges.filter(edge =>
      activeNodes.contains(edge.source()) && activeNodes.contains(edge.target())
    );
  }

  if (filterIPLoopbackOrLinklocal){
    activeNodes = filterOutIPLoopbackOrLinklocal(activeNodes).nodes;
  }

  // FILTER OUT ISOLATED NODES
  if (filterIsolatedNodes) {

    const connected = activeEdges.connectedNodes();

    const nonCaptureNodes = activeNodes.filter('[type != "capture"]');
    const captureNodes = activeNodes.filter('[type = "capture"]');

    const filteredNonCapture = nonCaptureNodes.intersection(connected);

    activeNodes = filteredNonCapture.union(captureNodes);
  }


  cy.batch(() => {
    cy.nodes().style('display', 'none');
    cy.edges().style('display', 'none');

    activeNodes.style('display', 'element');
    activeEdges.style('display', 'element');
  });


  const includedNodeCount = activeNodes.length;
  const filteredNodecount = totalNodeCount - includedNodeCount;

  const filteredCountEl = document.getElementById('filtered-node-count');
  if (filteredCountEl) {
    filteredCountEl.textContent = filteredNodecount;
  }

  resetFocusIndexes();
  hideFilterSpinner();
}

