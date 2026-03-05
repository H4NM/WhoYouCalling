let callmapperData = null;
let availableAPIs = null;
let cachedAPIlookups = null;

async function loadCallMapperData() {
  if (callmapperData) {
    return callmapperData; 
  }

  const response = await fetch('/data.json');
  if (!response.ok) {
    throw new Error('Failed to load data.json');
  }

  callmapperData = await response.json();
  return callmapperData;
}

async function apisAreAvailable() {
  const response = await fetch('/status', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  });

  if (response.ok) {
    return true;
  }else{
    return false;
  }
}

async function loadAvailableAPIs() {
  if (availableAPIs) {
    return availableAPIs;
  }

  const response = await fetch('/apis', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to load APIs (${response.status})`);
  }

  availableAPIs = await response.json();
  return availableAPIs;
}

async function loadCachedAPILookups() {
  if (cachedAPIlookups) {
    return cachedAPIlookups;
  }

  const response = await fetch('/api/cached', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to load cached API lookups (${response.status})`);
  }

  cachedAPIlookups = await response.json();
  return cachedAPIlookups;
}

