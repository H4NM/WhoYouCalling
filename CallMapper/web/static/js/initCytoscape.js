
const MAX_NODES_FOR_OPTIMIZATION = 500;
let cy = null;

const NODE_LINK_CONFIG = {
  process: [
    {
      label: 'https://virustotal.com (SHA256)',
      buildUrl: (data) =>
        data.SHA256 ? `https://www.virustotal.com/gui/file/${data.SHA256}` : null
    }
  ],

  ip: [
    {
      label: 'https://virustotal.com',
      buildUrl: (data) =>
        `https://www.virustotal.com/gui/ip-address/${data.label}`
    },
    {
      label: 'https://abuseipdb.com',
      buildUrl: (data) =>
        `https://www.abuseipdb.com/check/${data.label}`
    },
    {
      label: 'https://ipinfo.io',
      buildUrl: (data) =>
        `https://ipinfo.io/${data.label}`
    }
  ],

  domain: [
    {
      label: 'https://virustotal.com',
      buildUrl: (data) =>
        `https://www.virustotal.com/gui/domain/${data.label}`
    },
    {
      label: 'https://whois.com',
      buildUrl: (data) =>
        `https://www.whois.com/whois/${data.label}`
    }
  ]
};

const tooltip = document.getElementById('tooltip');
let isPanning = false;
let isTooltipVisible = false;


function hideTooltip() {
    tooltip.style.display = 'none';
    isTooltipVisible = false;
}

function buildSectionHeader(text) {
  const header = document.createElement('h4');
  header.className = 'tooltip-section-header';
  header.textContent = text;
  return header;
}

function getNodeLinks(nodeData) {
  const type = nodeData.type;
  const config = NODE_LINK_CONFIG[type];

  const container = document.createElement('div');
  container.className = 'node-lookup-interactive-divs';

  for (const linkDef of config) {
    const url = linkDef.buildUrl(nodeData);
    if (!url) continue;

    const a = document.createElement('a');
    a.style.setProperty('--node-color', getNodeColor(nodeData.type));
    a.href = url;
    a.textContent = linkDef.label;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.className = 'node-lookup-interactive-div'
    a.style.borderColor = getNodeColor(nodeData.type);

    container.appendChild(a);
  }

  return container.children.length ? container : null;
}


function buildLookupsSection(node, nodeType, suitableAPI, availableAPIs) {
  const container = document.createElement('div');
  container.className = 'node-lookup-interactive-divs';

  const apiLookupButton = document.createElement('div');
  apiLookupButton.className = 'node-lookup-interactive-div';
  apiLookupButton.style.setProperty('--node-color', getNodeColor(nodeType));
  apiLookupButton.style.borderColor = getNodeColor(nodeType);


  apiLookupButton.textContent = suitableAPI.label;
  apiLookupButton.id = suitableAPI.api;
  apiLookupButton.addEventListener('click', async () => {
    try {
      const response = await fetch(suitableAPI.postEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
      }

      const result = await response.json();
      const apiResults = {
          ...node.data('APIResults'),
          [suitableAPI.api]: result
      };

      node.data('APIResults', apiResults);
      node.data('hasAPIResults', true);

      document.getElementById('tooltip').style.display = 'none';
      showNodeTooltip(node, true, availableAPIs);

    } catch (err) {
      console.error('Lookup failed:', err);
    }
  });

  container.appendChild(apiLookupButton);
  return container;
}

function buildAPIResultsSection(nodeData) {
  const container = document.createElement('div');
  container.className = 'node-api-results';

  const apiResults = nodeData.APIResults;

  for (const [apiName, apiResponse] of Object.entries(apiResults)) {
    container.appendChild(structureApiResult(apiName, apiResponse, nodeData.type));
  }

  return container;
}


function structureApiResult(apiName, apiResponse, nodeType) {
  const wrapper = document.createElement('div');
  wrapper.className = 'api-result-wrapper';

  const header = document.createElement('h4');
  header.className = 'tooltip-section-header';
  header.textContent = apiName;
  wrapper.appendChild(header);

  wrapper.appendChild(buildAPIResultOutput(apiResponse, nodeType));
  
  return wrapper;
}

function hideNodeAndTooltip(node){
  hideNode(node);
  hideTooltip();
  resetFocusIndexes();
}


function buildHideNodeButton(node, nodeType){
  const hideNodeButton = document.createElement('div');

  hideNodeButton.textContent = `Hide ${nodeType}`;
  hideNodeButton.className = 'node-lookup-interactive-div';
  hideNodeButton.style.setProperty('--node-color', getNodeColor(nodeType));
  hideNodeButton.style.borderColor = getNodeColor(nodeType);

  hideNodeButton.addEventListener('click', (event) => {
    hideNodeAndTooltip(node);
  });

  return hideNodeButton;
}


function buildAPIResultOutput(apiResponse, nodeType) {
  const container = document.createElement('div');
  container.className = 'node-details api-details';

  if (apiResponse.status === 'OK' || apiResponse.status === 'NO_RESULTS'){
    for (const [key, value] of Object.entries(apiResponse.results)) {
      if (value == null) continue;

      const row = document.createElement('div');
      row.className = 'node-row';
      row.style.borderColor = getNodeColor(nodeType);

      const k = document.createElement('div');
      k.className = 'node-key';
      k.textContent = key;

      const v = document.createElement('div');
      v.className = 'node-value';
      v.textContent = String(value);

      row.appendChild(k);
      row.appendChild(v);
      container.appendChild(row);
    }
  }else{

      const row = document.createElement('div');
      row.className = 'node-row-api-error';

      const k = document.createElement('div');
      k.className = 'node-key';
      k.textContent = apiResponse.status;

      const v = document.createElement('div');
      v.className = 'node-value';
      v.textContent = JSON.stringify(apiResponse.results, null, 2);

      row.appendChild(k);
      row.appendChild(v);
      container.appendChild(row);

  }


  return container;
}


function buildNodeDetailsTable(nodeData) {
  const container = document.createElement('div');
  container.className = 'node-details';
  const config = NODE_FIELD_CONFIG[nodeData.type];

  if (!config) return container;

  for (const [key, label] of config) {
    if (!(key in nodeData)) continue;
    if (nodeData[key] == null) continue;

    const row = document.createElement('div');
    row.className = 'node-row';
    if (nodeData.type != 'capture'){
      row.style.borderColor = getNodeColor(nodeData.type);
    }else{
      row.style.borderColor = nodeData.callmapper_color;
    }

    const k = document.createElement('div');
    k.className = 'node-key';
    k.textContent = label;

    const v = document.createElement('div');
    v.className = 'node-value';
    v.textContent = String(nodeData[key]);

    row.appendChild(k);
    row.appendChild(v);
    container.appendChild(row);
  }

  return container;
}

function thereIsAnAPIForNodeType(node, availableAPIs){
  let suitableAPIs = []

  for (const api of availableAPIs) {
    if (node.type === 'process') {

        if (api.lookup_types.includes('sha256') && node.SHA256){
          suitableAPIs.push({
            api: api.name,
            label: `${api.name} (SHA256)`,
            postEndpoint: `/api/${api.name}/sha256/${node.SHA256}/${node.id}`
          })
        }
        else if (api.lookup_types.includes('sha1') && node.SHA1){
          suitableAPIs.push({
            api: api.name,
            label: `${api.name} (SHA1)`,
            postEndpoint: `/api/${api.name}/sha1/${node.SHA1}/${node.id}`
          })
        }
        else if (api.lookup_types.includes('md5') && node.MD5){
          suitableAPIs.push({
            api: api.name,
            label: `${api.name} (MD5)`,
            postEndpoint: `/api/${api.name}/md5/${node.MD5}/${node.id}`
          })
        }
    }
    else if (node.type === 'ip' && api.lookup_types.includes(node.type)){
    suitableAPIs.push({
      api: api.name,
      label: `${api.name}`,
      postEndpoint: `/api/${api.name}/ip/${node.IP}/${node.id}`
    })
    }else if (node.type === 'domain' && api.lookup_types.includes(node.type)){ // Redundat but for my own sanity
      suitableAPIs.push({
        api: api.name,
        label: `${api.name}`,
        postEndpoint: `/api/${api.name}/domain/${node.Domain}/${node.id}`
      })
    }
}

  return suitableAPIs;
}

function showNodeTooltip(node, apisAreAvailable, availableAPIs) {
  const frag = document.createDocumentFragment();

  const tooltip = document.getElementById('tooltip');
  tooltip.innerHTML = '';

  const cy = getCy();
  const prev = cy.nodes('.highlighted');
  if (prev.length) prev.removeClass('highlighted');

  node.addClass('highlighted');

  const nodeData = node.data();

  // NODE HEADER - PROCESS/DOMAIN/IP
  const title = document.createElement('h3');
  title.textContent = nodeData.type;
  title.className = 'endpoint-type';

  // NODE VALUE - THE LABEL THATS VISIBLE
  const subtitle = document.createElement('p');
  subtitle.textContent = nodeData.label;
  subtitle.className = 'endpoint-value';

  frag.appendChild(title);
  frag.appendChild(subtitle);

  // NODE DETAILS - NAME, EXECUTABLE PATH, ETC.
  frag.appendChild(buildNodeDetailsTable(nodeData));

  // FILTER LOCAL IPs AND NON-EXTERNAL DOMAIN NAMES
  if (!(nodeData.type === 'ip' && nodeData.Private) && !(nodeData.type === 'domain' && !nodeData.ValidDomainName) && nodeData.type != 'capture'){

    if (nodeData.hasAPIResults) {
      const apiSection = buildAPIResultsSection(nodeData);
      if (apiSection) {
        frag.appendChild(apiSection);
      }
    }

    // NODE LOOKUPS - APIS ETC.
    if (apisAreAvailable && availableAPIs.length !== 0){
      const suitableAPIs = thereIsAnAPIForNodeType(nodeData, availableAPIs);

      if (suitableAPIs.length !== 0){
          const sectionContainer = document.createElement('div');
          sectionContainer.className = 'node-tooltip-section-container';
          sectionContainer.appendChild(buildSectionHeader('API Lookup'));

        for (const suitableAPI of suitableAPIs) {
          sectionContainer.appendChild(buildLookupsSection(node, nodeData.type, suitableAPI, availableAPIs));
        }
        frag.appendChild(sectionContainer);
      }
    }

    // NODE LINKS - CLICKABLE, IPINFO, VT ETC.
    const links = getNodeLinks(nodeData);
    if (links) {
        const sectionContainer = document.createElement('div');
        sectionContainer.className = 'node-tooltip-section-container';
        sectionContainer.appendChild(buildSectionHeader('Links'));
        sectionContainer.appendChild(links);
        frag.appendChild(sectionContainer);
    }
  }

  if (nodeData.type != 'capture'){
    frag.appendChild(buildHideNodeButton(node, nodeData.type))
  }


  // £ DEBUGGING
  //const jsonData = document.createElement('pre');
  //jsonData.textContent = JSON.stringify(nodeData, null, 2);
  //frag.appendChild(jsonData);

  tooltip.innerHTML = '';
  tooltip.appendChild(frag);

  tooltip.style.display = 'block';
}

/*
=============================== CYTOSCAPE - ADD CACHED DATA TO NODES ===============================
*/
function populateNodesWithCachedAPIData(cachedApiLookups){

  for (const nodeId in cachedApiLookups) {
    const node = cy.getElementById(nodeId);
    
    const apiResultsForNode = {}

    for (const cachedAPIResult of cachedApiLookups[nodeId]) {
        apiResultsForNode[cachedAPIResult.api_name] = cachedAPIResult.lookup_results;
    }

    node.data({
      hasAPIResults: true,
      APIResults: apiResultsForNode,
      apiStatus: 'cached'
    });
  }
}

function getCy() {
  if (!cy) {
    throw new Error('Cytoscape not initialized yet');
  }
  return cy;
}

async function initCytoscape(data, cyto_object_design, apisAreAvailable, availableAPIs) {

    cy = cytoscape({
    container: document.getElementById('cy'),
    elements: data.elements,
    pixelRatio: 1,
    layout:
    {
      name: 'fcose',
      quality: 'default',      
      randomize: true,
      animate: false,
      fit: true,
      numIter: data.elements.nodes.length >= MAX_NODES_FOR_OPTIMIZATION ? 500 : 300,
      nodeRepulsion: function( node ) {
        if (node.data('type') === 'process') {
          return 1000;  
        }
        return 4000;
      },     
      idealEdgeLength: 240,
      edgeElasticity: 0.1,     
      gravity: 0.2,
      gravityCompound: 1.0,
      gravityRange: 3.8,
      gravityRangeCompound: 1.5,
      nodeDimensionsIncludeLabels: false,
      tile: false,
      nestingFactor: 1.2,
      padding: 20
    },
    avoidOverlap: true,
    minZoom: 0.1,
    maxZoom: 5,
    hideEdgesOnViewport: true,
    textureOnViewport: false,
    motionBlur: true, 

    uniformNodeDimensions: true,
    packComponents: true,

    style: [
        {
          selector: 'node[type != "capture"]',
          style: {
            'label': 'data(label)',
            'shape': cyto_object_design.node.default.shape,         
            'border-width': cyto_object_design.node.default.borderWidth,     
            'border-color': cyto_object_design.node.default.borderColor,     
            'border-style': cyto_object_design.node.default.borderStyle,
            'text-valign': cyto_object_design.node.default.textVAlign,       
            'text-margin-x': cyto_object_design.node.default.textMarginX,            
            'text-margin-y': cyto_object_design.node.default.textMarginY, 
            'width': cyto_object_design.node.default.width,
            'height': cyto_object_design.node.default.height,
            'transition-property': 'none',
            'transition-duration': 0
          }
        },
        {
          selector: 'edge',
          style: {
            'curve-style': cyto_object_design.edge.default.curveStyle,
            'target-arrow-shape': cyto_object_design.edge.default.targetArrowShape,
            'width': cyto_object_design.edge.default.width, 
            'line-color': cyto_object_design.edge.default.lineColor, 
            'line-style': cyto_object_design.edge.default.lineStyle,
            'target-arrow-color': cyto_object_design.edge.default.targetArrowColor
          }
        },
        {
        selector: 'node[type = "capture"]',
        style: {
            'background-color': 'data(color)',
            'label': 'data(label)',
            'shape': 'round-rectangle',         
            'border-width': cyto_object_design.node.default.borderWidth,     
            'border-color': cyto_object_design.node.default.borderColor,     
            'border-style': cyto_object_design.node.default.borderStyle,
            'width': 300,
            'height': 200,
            'padding': 0
        },
        },
        {
        selector: 'node[type = "process"]',
        style: {
            'background-color': cyto_object_design.node.process.color
        },
        },
        {
        selector: 'node[type = "domain"]',
        style: {
            'background-color': cyto_object_design.node.domain.color
        },
        },
        {
        selector: 'node[type = "ip"]',
        style: {
            'background-color': cyto_object_design.node.ip.color
        },
        },
        {
        selector: 'edge[type = "tcpipPacketSent"]',
        style: {
            'width': cyto_object_design.edge.tcpipConnection.width, 
            'line-color': cyto_object_design.edge.tcpipConnection.lineColor, 
            'target-arrow-color': cyto_object_design.edge.tcpipConnection.targetArrowColor,
            'line-style': cyto_object_design.edge.tcpipConnection.lineStyle,
        }
        },
        {
        selector: 'edge[type = "processStart"]',
        style: {
            'width': cyto_object_design.edge.processStart.width, 
            'line-color': cyto_object_design.edge.processStart.lineColor, 
            'target-arrow-color': cyto_object_design.edge.processStart.targetArrowColor,
            'line-style': cyto_object_design.edge.processStart.lineStyle,
        }
        },
        {
          selector: 'edge.show-label',
          style: {
            'label': 'data(label)',
            'line-style': 'solid',
            'line-color': 'red',
            'target-arrow-color': 'red',
            'width': 2,
            'arrow-scale': 1.5,
            'text-opacity': 1,
            'font-size': 10,
            'text-valign': 'center',
            'color': '#000',
            'text-background-color': '#fff',
            'text-background-opacity': 1,
            'text-background-shape': 'round-rectangle',
            'text-background-padding': '4px',
            'font-weight': cyto_object_design.highlighted.fontWeight
          }
        },
        {
        selector: 'node.highlighted',
        style: {
            'border-width': cyto_object_design.highlighted.borderWidth, 
            'overlay-opacity': 0.15,
            'font-weight': cyto_object_design.highlighted.fontWeight,
            'z-index': cyto_object_design.highlighted.zIndex,
            'text-opacity': cyto_object_design.highlighted.textOpacity,
            'text-background-shape': 'round-rectangle',
            'text-background-opacity': 1,
            'text-background-color': '#fff',
            'text-background-padding': 4
           }
        }
    ],
    
    });

    /*
    ==================================
    |
    |   Promise of finished loading the nodes
    |
    ===================================
    */
    await new Promise(resolve => {
        cy.ready(resolve);
    });


    /*
    ==================================
    |
    |   Panning
    |
    ===================================
    */     

    cy.on('panstart', () => isPanning = true);
    cy.on('panend', () => isPanning = false);

    /*
    ==================================
    |
    |   Tooltip management
    |
    ===================================
    */        


    cy.on('click', 'node', function (event) {
    if (isPanning) return;

    const node = event.target;

    tooltip.style.display = 'block';
    tooltip.innerHTML = '<div class="tooltip-loading">Loading…</div>';

    requestAnimationFrame(() => {
      showNodeTooltip(node, apisAreAvailable, availableAPIs);
    });
  });


    cy.on('click', 'edge', function (event) {
      const edge = event.target;

      edge.data('label', edge.data('info'));
      edge.addClass('show-label');
    });

    cy.on('click', function (event) {
      if (event.target !== cy) return;

      hideTooltip();
      cy.elements('.highlighted').removeClass('highlighted');

      cy.edges('.show-label')
        .removeClass('show-label')
        .removeData('label');
    });
}

