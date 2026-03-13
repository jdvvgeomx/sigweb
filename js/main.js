window.onload = function () {
    // Intentar "despertar" al servidor de inmediato (Render free tier)
    fetch(API_BASE_URL + '/api/v1/points').catch(() => { });

    const authForm = document.getElementById('auth-form');
    if (authForm) authForm.onsubmit = handleAuth;

    updateAuthUI();
    setupCategoryFilters();
    loadCustomPointsFromServer();
    initGoogleAuth();
    spawnParticles();
    setupSearchListeners();

    // Precarga de GeoJSON (opcional, pero útil para búsqueda rápida)
    fetch('Municipal_opt.geojson')
        .then(r => r.json())
        .then(data => {
            municipalGeoJSON = data;
            // No creamos la capa aquí, solo el índice para búsqueda
            municipiosIndex = data.features.map(f => ({
                cve: f.properties.CVEGEO,
                nombre: f.properties.NOMGEO
            }));
            mergePopulationData();
        })
        .catch(e => console.warn("Error precarga municipios", e));

    fetch("poblacion_veracruz.json")
        .then(r => r.json())
        .then(data => {
            poblacion = data;
            mergePopulationData();
        });

    setTimeout(() => {
        const selector = document.getElementById('base-layer-selector');
        if (selector) {
            selector.addEventListener('change', (e) => {
                changeBaseLayer(e.target.value);
            });
        }
        map.invalidateSize();
    }, 800);

    // Ajuste inicial de límites
    fetch('Nacional_opt.geojson').then(r => r.json()).then(data => {
        const l = L.geoJSON(data);
        map.fitBounds(l.getBounds(), { padding: [30, 30] });
    }).catch(e => { });
};

