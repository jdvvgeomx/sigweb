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

    // Precarga de GeoJSON para mejorar velocidad
    fetch('Nacional_opt.geojson')
        .then(r => r.json())
        .then(data => {
            nacionalGeoJSON = data;
        })
        .catch(e => console.warn("Error precarga nacional", e));

    fetch('Veracruz.geojson')
        .then(r => r.json())
        .then(data => { estatalGeoJSON = data; })
        .catch(e => console.warn("Error precarga estatal", e));

    fetch('Municipal_opt.geojson')
        .then(r => r.json())
        .then(data => {
            municipalGeoJSON = data;
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
};

