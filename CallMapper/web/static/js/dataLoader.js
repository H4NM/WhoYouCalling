let cachedData = null;

export async function loadCallMapperData() {
  if (cachedData) {
    return cachedData; 
  }

  const response = await fetch('/data.json');
  if (!response.ok) {
    throw new Error('Failed to load data.json');
  }

  cachedData = await response.json();
  return cachedData;
}

export function getCallMapperData() {
  if (!cachedData) {
    throw new Error('Data not loaded yet');
  }
  return cachedData;
}
