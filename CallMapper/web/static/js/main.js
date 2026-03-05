
/*
=============================== MAIN PROGRAM THAT'S RUN ON LOAD ===============================
*/
window.addEventListener('load', () => {

  (async () => {
    const loader = document.getElementById('loading-overlay');
    const loadingText = document.querySelector('.loading-text');

    enableTabSwitching();
    loader.style.display = 'flex';

    loadingText.textContent = 'Loading data…';
    await nextFrame();
    const data = await loadCallMapperData();
  
    loadingText.textContent = 'Checking API status...';
    await nextFrame();
    areApisAvailable  = await apisAreAvailable();

    if (areApisAvailable){
      loadingText.textContent = 'Retrieving available APIs...';
      await nextFrame();
      availableAPIs = await loadAvailableAPIs();
    }
    
    loadingText.textContent = 'Rendering graph…';
    await nextFrame();
    await initCytoscape(data, CYTOSCAPE_OBJECT_DESIGN_CHARACTERISTICS, areApisAvailable , availableAPIs);

    if (areApisAvailable && availableAPIs){
        loadingText.textContent = 'Retrieving cached API lookups...';
        await nextFrame();
        cachedApiLookups = await loadCachedAPILookups();
        populateNodesWithCachedAPIData(cachedApiLookups); 
    }

    loadingText.textContent = 'Building UI…';
    await nextFrame();
    waitForCyAndInitUI();
    updateNodeCounts();
    initCallMapperMetadata(data.wyc_results_metadata);
    buildSummaryMetaWYCFilesTable(data.wyc_results_metadata);
    buildSummaryTables(data.summary.unique);
    buildSummaryTCPPortsTables(data.summary.destination_ports.TCP);
    buildSummaryUDPPortsTables(data.summary.destination_ports.UDP);

    setupClickableCounters();
    setupAutoFiltering();
    setupMainButtonFunctionality();
    if (data.elements.nodes.length >= MAX_NODES_FOR_OPTIMIZATION){
        document.getElementById('auto-filter-checkbox').checked = false;
    }
    
    activateView('view1');
    
    loader.style.display = 'none';

  })();
});
