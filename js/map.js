var map = L.map('map', { zoomControl: false }).setView([19.17, -96.13], 7);

const baseLayers = {
    'Mapa Claro': L.tileLayer('https://cartodb-basemaps-a.global.ssl.fastly.net/light_all/{z}/{x}/{y}.png', {
        attribution: '&copy; OpenStreetMap · CartoDB',
        maxZoom: 19
    }),
    'Satélite Híbrido': L.layerGroup([
        L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
            attribution: '&copy; Esri',
            maxZoom: 19
        }),
        L.tileLayer('https://cartodb-basemaps-a.global.ssl.fastly.net/dark_only_labels/{z}/{x}/{y}.png', {
            attribution: '&copy; CartoDB',
            maxZoom: 19,
            pane: 'markerPane'
        })
    ])
};

let currentBaseLayer = baseLayers['Mapa Claro'];
currentBaseLayer.addTo(map);

const BaseLayerControl = L.Control.extend({
    options: { position: 'topright' },
    onAdd: function (map) {
        const container = L.DomUtil.create('div', 'leaflet-bar leaflet-control');
        container.style.cssText = `
  background: rgba(255, 255, 255, 0.15);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 12px;
  padding: 8px;
  margin-top: 60px;
`;

        container.innerHTML = `
  <div style="color: white; font-size: 11px; font-weight: bold; margin-bottom: 6px; text-align: center;">
    CAPAS BASE
  </div>
  <select id="base-layer-selector" style="
    width: 100%;
    padding: 6px;
    border-radius: 6px;
    border: 1px solid rgba(255,255,255,0.3);
    background: rgba(0,0,0,0.3);
    color: white;
    font-size: 11px;
    cursor: pointer;
    outline: none;
  ">
    <option value="Mapa Claro">🗺️ Mapa Claro</option>
    <option value="Satélite Híbrido">🛰️ Satélite Híbrido</option>
  </select>
`;

        L.DomEvent.disableClickPropagation(container);
        return container;
    }
});

map.addControl(new BaseLayerControl());

function changeBaseLayer(layerName) {
    if (currentBaseLayer) {
        map.removeLayer(currentBaseLayer);
    }
    currentBaseLayer = baseLayers[layerName];
    currentBaseLayer.addTo(map);

    if (currentBaseLayer.bringToBack) {
        currentBaseLayer.bringToBack();
    } else if (currentBaseLayer.eachLayer) {
        currentBaseLayer.eachLayer(layer => {
            if (layer.bringToBack) layer.bringToBack();
        });
    }

    if (currentScale === 'nacional' && map.hasLayer(layers.nacional)) {
        layers.nacional.clearLayers();
        const render = (data) => {
            const isDarkLayer = (layerName === 'Satélite Híbrido');
            const nationalStyle = isDarkLayer ?
                { color: '#F6C453', weight: 2, fillOpacity: 0.25, fillColor: '#F6C453' } :
                { color: '#000', weight: 2, fillOpacity: 0.35, fillColor: '#555' };
            L.geoJSON(data, { style: nationalStyle }).addTo(layers.nacional);
        };

        if (nacionalGeoJSON) {
            render(nacionalGeoJSON);
        } else {
            fetch('Nacional_opt.geojson').then(r => r.json()).then(data => {
                nacionalGeoJSON = data;
                render(data);
            }).catch(e => console.warn("Error actualizando polígono nacional", e));
        }
    }
}

L.control.zoom({ position: 'bottomright' }).addTo(map);
L.control.scale({ position: 'bottomleft', imperial: false }).addTo(map);

L.easyButton('<span title="Centro">⤒</span>', function (btn, m) {
    map.setView([19.17, -96.13], 7);
}).addTo(map);

var compassControl = L.Control.extend({
    options: { position: 'topright' },
    onAdd: function (map) {
        var div = L.DomUtil.create('div', 'compass-control');
        div.innerHTML = `
  <svg width="50" height="50" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" style="filter: drop-shadow(0 2px 4px rgba(0,0,0,0.5));">
    <path d="M50 0 L65 40 L100 50 L65 60 L50 100 L35 60 L0 50 L35 40 Z" fill="rgba(30, 60, 114, 0.8)" stroke="#F6C453" stroke-width="2"/>
    <path d="M50 0 L50 100 M0 50 L100 50" stroke="rgba(255,255,255,0.3)" stroke-width="1"/>
    <text x="50" y="24" font-family="Inter, sans-serif" font-size="16" font-weight="900" fill="#F6C453" text-anchor="middle">N</text>
  </svg>
`;
        div.style.marginTop = '10px';
        div.style.marginRight = '10px';
        return div;
    }
});
map.addControl(new compassControl());

var layers = {
    nacional: L.featureGroup(),
    estatal: L.featureGroup(),
    municipios: L.featureGroup(),
    regionesUV: L.featureGroup(),
    regionesVer: L.featureGroup(),
    chiapasEstado: L.featureGroup(),
    chiapasMunicipios: L.featureGroup(),
    chiapasRegiones: L.featureGroup(),
    chiapasOlvidados: L.featureGroup(),
    marginacion: L.featureGroup(),
    crecimiento: L.featureGroup(),
    servicios: { 1: L.layerGroup(), 2: L.layerGroup(), 3: L.layerGroup(), 4: L.layerGroup(), 5: L.layerGroup() }
};

customPointsLayer = L.layerGroup().addTo(map);

var highlightLayer = L.geoJSON(null, {
    style: {
        color: "#1affff",
        weight: 4, // Un poco más presente pero elegante
        fillOpacity: 0, 
        opacity: 1,
        dashArray: null 
    }
}).addTo(map);

var highlightLabel = null;

function applyGlowToLayer(geoLayer) {
    try {
        geoLayer.eachLayer(l => {
            const el = l.getElement ? l.getElement() : null;
            if (el) {
                el.classList.add('glow', 'pulse'); // Mantenemos la clase pero la animación está desactivada en CSS
            } else {
                setTimeout(() => { try { l.getElement().classList.add('glow', 'pulse'); } catch (e) { } }, 50);
            }
        });
    } catch (e) {
        console.warn("applyGlowToLayer error", e);
    }
}

function updateLabelPosition() {
    if (highlightLabel && highlightLayer && highlightLayer.getLayers().length > 0) {
        try {
            const bounds = highlightLayer.getBounds();
            if (bounds.isValid()) {
                const c = bounds.getCenter();
                highlightLabel.setLatLng(c);
            }
        } catch (e) { }
    }
}
map.on('zoomend', updateLabelPosition);
map.on('moveend', updateLabelPosition);

function getColor(d) {
    return d > 500000 ? '#bd0026' :
        d > 250000 ? '#f03b20' :
            d > 100000 ? '#fd8d3c' :
                d > 50000 ? '#feb24c' :
                    d > 25000 ? '#fed976' :
                        d > 10000 ? '#ffeda0' :
                            '#ffffcc';
}

function mergePopulationData() {
    if (!municipalGeoJSON || !poblacion || !poblacion.municipios) return;
    municipalGeoJSON.features.forEach(f => {
        const match = poblacion.municipios.find(m => m.NOMGEO === f.properties.NOMGEO);
        if (match) {
            f.properties.POB1 = match.POB1;
            f.properties.POB84 = match.POB84;
            f.properties.POB42 = match.POB42;
        }
    });

    if (layers.municipios && layers.municipios.getLayers().length > 0) {
        layers.municipios.eachLayer(layer => {
            if (layer.setStyle) {
                layer.setStyle({
                    fillColor: getColor(layer.feature.properties.POB1 || 0)
                });
            }
        });
    }
}

function clearAll() {
    try { highlightLayer.clearLayers(); } catch (e) { }
    if (highlightLabel) {
        try { map.removeLayer(highlightLabel); } catch (e) { }
        highlightLabel = null;
    }
    try { map.removeLayer(layers.nacional); } catch (e) { }
    try { map.removeLayer(layers.estatal); } catch (e) { }
    try { map.removeLayer(layers.municipios); } catch (e) { }
    try { map.removeLayer(layers.regionesUV); } catch (e) { }
    try { map.removeLayer(layers.regionesVer); } catch (e) { }
    try { map.removeLayer(layers.chiapasEstado); } catch (e) { }
    try { map.removeLayer(layers.chiapasMunicipios); } catch (e) { }
    try { map.removeLayer(layers.chiapasRegiones); } catch (e) { }
    try { map.removeLayer(layers.chiapasOlvidados); } catch (e) { }
    try { map.removeLayer(layers.marginacion); } catch (e) { }
    try { map.removeLayer(layers.crecimiento); } catch (e) { }
}

function showNational() {
    if (currentScale === 'nacional') {
        currentScale = null;
        setActiveBtn(null);
        clearAll();
        document.getElementById('map-legend').innerHTML = '';
        return;
    }

    currentScale = 'nacional';
    setActiveBtn('btn-nacional');
    clearAll();
    actualizarLeyenda('nacional');
    checkMarginacionOverlay();
    checkCrecimientoOverlay();

    const renderNational = (data) => {
        const isDarkLayer = (currentBaseLayer === baseLayers['Satélite Híbrido']);
        const nationalStyle = isDarkLayer ?
            { color: '#F6C453', weight: 2, fillOpacity: 0.25, fillColor: '#F6C453' } :
            { color: '#000', weight: 2, fillOpacity: 0.35, fillColor: '#555' };

        const layer = L.geoJSON(data, { style: nationalStyle }).addTo(layers.nacional);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    };

    if (nacionalGeoJSON) {
        renderNational(nacionalGeoJSON);
    } else {
        fetch('Nacional_opt.geojson').then(r => r.json()).then(data => {
            nacionalGeoJSON = data;
            renderNational(data);
        }).catch(e => console.warn("Nacional_opt.geojson error", e));
    }

    layers.nacional.addTo(map);

    if (poblacion.nacional && poblacion.nacional.POB1) {
        const pn = poblacion.nacional;
        abrirPanel("Información Nacional", `
            <div class="mb-4">
                <p class="text-xs uppercase tracking-widest text-[#F6C453] mb-1 font-bold">Nacional</p>
                <h3 class="text-lg font-bold mb-3">Nivel Nacional</h3>
                <div class="bg-white/10 rounded-xl p-3 mb-4 border border-white/5">
                    <p class="text-[10px] uppercase opacity-60 mb-0.5">Población Total</p>
                    <p class="text-2xl font-black text-[#F6C453]">${(pn.POB1 || 0).toLocaleString()}</p>
                </div>
                </ul>
                <div class="relative h-44 w-full">
                    <canvas id="poblacionChartNacional"></canvas>
                </div>
            </div>
        `);

        if (currentChart) currentChart.destroy();
        setTimeout(() => {
            const ctx = document.getElementById('poblacionChartNacional').getContext('2d');
            currentChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Hombres', 'Mujeres'],
                    datasets: [{
                        data: [pn.POB84, pn.POB42],
                        backgroundColor: ['#3B82F6', '#F472B6'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#fff', font: { size: 10 } }
                        }
                    }
                }
            });
        }, 100);
    }
}

function showState() {
    if (currentScale === 'estatal') {
        currentScale = null;
        setActiveBtn(null);
        clearAll();
        document.getElementById('map-legend').innerHTML = '';
        return;
    }

    currentScale = 'estatal';
    setActiveBtn('btn-estatal');
    clearAll();
    actualizarLeyenda('estatal');
    checkMarginacionOverlay();
    checkCrecimientoOverlay();

    const renderState = (data) => {
        const layer = L.geoJSON(data, { style: { color: '#006847', weight: 2, fillOpacity: 0.2 } }).addTo(layers.estatal);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    };

    if (estatalGeoJSON) {
        renderState(estatalGeoJSON);
    } else {
        fetch('Veracruz.geojson').then(r => r.json()).then(data => {
            estatalGeoJSON = data;
            renderState(data);
        }).catch(e => console.warn("Veracruz.geojson error", e));
    }

    layers.estatal.addTo(map);

    if (poblacion.veracruz && poblacion.veracruz.POB1) {
        const pv = poblacion.veracruz;
        abrirPanel("Información Estatal (Veracruz)", `
            <div class="mb-4">
                <p class="text-xs uppercase tracking-widest text-[#F6C453] mb-1 font-bold">Estatal</p>
                <h3 class="text-lg font-bold mb-3">Estado de Veracruz</h3>
                <div class="bg-white/10 rounded-xl p-3 mb-4 border border-white/5">
                    <p class="text-[10px] uppercase opacity-60 mb-0.5">Población Total</p>
                    <p class="text-2xl font-black text-[#F6C453]">${(pv.POB1 || 0).toLocaleString()}</p>
                </div>
                <ul class="text-[12px] space-y-2 mb-4">
                    <li class="flex justify-between items-center text-blue-300">
                        <span class="flex items-center gap-2"><div class="w-3 h-3 rounded-full bg-[#3B82F6]"></div> Hombres</span> 
                        <b class="text-white">${(pv.POB84 || 0).toLocaleString()}</b>
                    </li>
                    <li class="flex justify-between items-center text-pink-300">
                        <span class="flex items-center gap-2"><div class="w-3 h-3 rounded-full bg-[#F472B6]"></div> Mujeres</span> 
                        <b class="text-white">${(pv.POB42 || 0).toLocaleString()}</b>
                    </li>
                </ul>
                <div class="relative h-44 w-full">
                    <canvas id="poblacionChartEstatal"></canvas>
                </div>
            </div>
        `);

        if (currentChart) currentChart.destroy();
        setTimeout(() => {
            const ctx = document.getElementById('poblacionChartEstatal').getContext('2d');
            currentChart = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: ['Hombres', 'Mujeres'],
                    datasets: [{
                        data: [pv.POB84, pv.POB42],
                        backgroundColor: ['#3B82F6', '#F472B6'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#fff', font: { size: 10 } }
                        }
                    }
                }
            });
        }, 100);
    }
}

function showMunicipalities() {
    if (currentScale === 'municipios') {
        currentScale = null;
        setActiveBtn(null);
        clearAll();
        document.getElementById('map-legend').innerHTML = '';
        return;
    }

    currentScale = 'municipios';
    setActiveBtn('btn-municipios');
    clearAll();
    actualizarLeyenda('municipios');
    checkMarginacionOverlay();
    checkCrecimientoOverlay();

    if (layers.municipios && layers.municipios.getLayers && layers.municipios.getLayers().length > 0) {
        layers.municipios.addTo(map);
        try { map.fitBounds(layers.municipios.getBounds(), { padding: [30, 30] }); } catch (e) { }
        return;
    }

    const render = (data) => {
        municipalGeoJSON = data;
        const layer = L.geoJSON(data, {
            style: (feature) => {
                const pob = feature.properties.POB1 || 0;
                return { fillColor: getColor(pob), weight: 1, opacity: 1, color: 'white', fillOpacity: 0.7 };
            },
            onEachFeature: (f, l) => {
                l.on('click', (e) => {
                    if (window.pipMode) {
                        try {
                            const polygon = f.geometry;
                            let count = 0;
                            if (typeof customPoints !== 'undefined') {
                                customPoints.forEach(p => {
                                    const point = turf.point([p.lng, p.lat]);
                                    if (turf.booleanPointInPolygon(point, polygon)) count++;
                                });
                            }
                            const msg = `<div style="text-align:center">
                                <b style="color:#F6C453">ANÁLISIS ESPACIAL</b><br>
                                Municipio: <b>${f.properties.NOMGEO}</b><br>
                                <hr style="margin:5px 0; border:0; border-top:1px solid rgba(255,255,255,0.2)">
                                Se encontraron <b style="font-size:14px">${count}</b> puntos personalizados dentro.
                            </div>`;
                            L.popup().setLatLng(e.latlng).setContent(msg).openOn(map);
                        } catch (err) { console.error('Error PiP:', err); }
                        return;
                    }
                    if (window.analysisMode) return;

                    try { highlightLayer.clearLayers(); } catch (e) { }
                    if (highlightLabel) { try { map.removeLayer(highlightLabel); } catch (e) { }; highlightLabel = null; }

                    highlightLayer.addData(f);
                    highlightLayer.eachLayer(layer => {
                        layer.bindTooltip(f.properties.NOMGEO, {
                            permanent: false,
                            direction: 'center',
                            className: 'custom-municipio-tooltip',
                            sticky: true
                        });
                    });
                    applyGlowToLayer(highlightLayer);

                    const normalizeStr = str => str ? str.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toUpperCase().trim() : "";
                    const searchName = normalizeStr(f.properties.NOMGEO);
                    if (!poblacion || !poblacion.municipios || poblacion.municipios.length === 0) {
                        l.bindPopup(`<div style="padding:12px; text-align:center">
                            <b style="color:#F6C453">${f.properties.NOMGEO}</b><br>
                            <i style="opacity:0.6; font-size:11px">⏳ Cargando datos demográficos...</i>
                        </div>`).openPopup();
                        return;
                    }
                    const pData = poblacion.municipios.find(x => normalizeStr(x.NOMGEO) === searchName);
                    if (!pData) {
                        l.bindPopup(`<div style="padding:10px"><b>${f.properties.NOMGEO}</b><br>Datos no disponibles.</div>`).openPopup();
                    }
                    if (window.ui && window.ui.mostrarInfoMunicipio) {
                        window.ui.mostrarInfoMunicipio(f.properties.CVEGEO, f.properties.NOMGEO);
                    }
                });
            }
        }).addTo(layers.municipios);
        layers.municipios.addTo(map);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    };

    if (municipalGeoJSON) {
        render(municipalGeoJSON);
    } else {
        fetch('Municipal_opt.geojson')
            .then(r => r.json())
            .then(data => render(data))
            .catch(e => console.warn("Error cargando municipios", e));
    }
}

function showUVRegions() {
    if (currentScale === 'regiones_uv') {
        currentScale = null;
        setActiveBtn(null);
        clearAll();
        document.getElementById('map-legend').innerHTML = '';
        const menu = document.getElementById('uv-menu-container');
        if (menu) menu.classList.add('hidden');
        return;
    }

    currentScale = 'regiones_uv';
    setActiveBtn('btn-regiones-uv');
    clearAll();
    actualizarLeyenda('regiones_uv');
    checkMarginacionOverlay();
    checkCrecimientoOverlay();

    // Generar Menú si no existe
    let container = document.getElementById('uv-menu-container');
    if (container) {
        container.innerHTML = '';
        container.classList.remove('hidden');
        Object.keys(uvRegionsData).forEach(region => {
            const data = uvRegionsData[region];
            const safeId = region.replace(/\s+/g, '-');
            container.innerHTML += `
                <div class="mb-1">
                    <button id="btn-region-${safeId}" class="uv-region-btn" onclick="toggleFacultades('${region}')" style="border-left-color: ${data.color}">
                        ${region} <span class="uv-arrow">▼</span>
                    </button>
                    <div id="list-${safeId}" class="uv-facultades-list">
                        ${data.facultades.map(f => `<div class="facultad-item" onclick="mostrarDetalleFacultad('${f}')">• ${f}</div>`).join('')}
                    </div>
                </div>
            `;
        });
    }

    let uvRegionesGeoJSON = null;
    
    const renderUV = (data) => {
        const layer = L.geoJSON(data, {
            style: (feature) => {
                const regionName = feature.properties.REGION_UV;
                let regionColor = '#cccccc';
                if (uvRegionsData && uvRegionsData[regionName]) {
                    regionColor = uvRegionsData[regionName].color;
                }
                return { color: 'white', weight: 2, fillColor: regionColor, fillOpacity: 0.5 };
            },
            onEachFeature: (f, l) => {
                const regionName = f.properties.REGION_UV;
                if (regionName) {
                    l.on('click', () => {
                        toggleFacultades(regionName);
                        mostrarInfoRegionUV(regionName);
                        l.setStyle({ fillOpacity: 0.8 });
                        setTimeout(() => l.setStyle({ fillOpacity: 0.5 }), 500);
                    });
                    const total = f.properties.TOTAL_INSTALACIONES || 0;
                    l.bindTooltip(<b></b><br>Instalaciones: , { direction: 'center', className: 'text-xs' });
                }
            }
        }).addTo(layers.regionesUV);
        layers.regionesUV.addTo(map);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    };

    fetch('regiones_uv.geojson').then(r => r.json()).then(data => {
        renderUV(data);
    }).catch(e => console.warn("Error UV regiones", e));
}

let regionesVerGeoJSONs = {};

function showVeracruzRegions() {
    if (currentScale === 'regiones_ver') {
        currentScale = null;
        setActiveBtn(null);
        clearAll();
        document.getElementById('map-legend').innerHTML = '';
        return;
    }

    currentScale = 'regiones_ver';
    setActiveBtn('btn-regiones-ver');
    clearAll();
    actualizarLeyenda('regiones_veracruz');
    checkMarginacionOverlay();
    checkCrecimientoOverlay();

    if (layers.regionesVer && layers.regionesVer.getLayers && layers.regionesVer.getLayers().length > 0) {
        layers.regionesVer.addTo(map);
        try { map.fitBounds(layers.regionesVer.getBounds(), { padding: [30, 30] }); } catch (e) { }
        return;
    }

    const regionFiles = {
        'Huasteca Alta': { file: 'HuastecaAlta.geojson', color: '#3B82F6' },
        'Huasteca Baja': { file: 'HuastecaBaja.geojson', color: '#60A5FA' },
        'Totonaca': { file: 'Totonaca.geojson', color: '#F97316' },
        'Nautla': { file: 'Nautla1.geojson', color: '#FB923C' },
        'Capital': { file: 'Capital.geojson', color: '#10B981' },
        'Grandes Montañas': { file: 'AltasMontanas.geojson', color: '#84CC16' },
        'Sotavento': { file: 'Sotavento.geojson', color: '#EF4444' },
        'Papaloapan': { file: 'Papaloapan.geojson', color: '#F43F5E' },
        'Los Tuxtlas': { file: 'LosTuxtlas.geojson', color: '#8B5CF6' },
        'Olmeca': { file: 'Olmeca.geojson', color: '#EC4899' }
    };

    if (typeof showNotification === 'function') {
        showNotification('Cargando las 10 regiones de Veracruz...', 'info');
    }

    const promises = Object.entries(regionFiles).map(([regionName, info]) => {
        if (regionesVerGeoJSONs[regionName]) {
            return Promise.resolve({ name: regionName, data: regionesVerGeoJSONs[regionName], color: info.color });
        }
        return fetch(info.file)
            .then(r => r.json())
            .then(data => {
                regionesVerGeoJSONs[regionName] = data;
                return { name: regionName, data: data, color: info.color };
            })
            .catch(e => {
                console.error(`Error cargando la región ${regionName}:`, e);
                return null;
            });
    });

    Promise.all(promises).then(results => {
        const activeResults = results.filter(r => r !== null);
        
        activeResults.forEach(res => {
            const geoJsonLayer = L.geoJSON(res.data, {
                style: () => ({
                    color: 'white',
                    weight: 1.5,
                    fillColor: res.color,
                    fillOpacity: 0.65,
                    opacity: 1
                }),
                onEachFeature: (f, l) => {
                    l.on('click', (e) => {
                        if (window.pipMode) {
                            try {
                                const polygon = f.geometry;
                                let count = 0;
                                if (typeof customPoints !== 'undefined') {
                                    customPoints.forEach(p => {
                                        const point = turf.point([p.lng, p.lat]);
                                        if (turf.booleanPointInPolygon(point, polygon)) count++;
                                    });
                                }
                                const msg = `<div style="text-align:center">
                                    <b style="color:#F6C453">ANÁLISIS ESPACIAL</b><br>
                                    Municipio: <b>${f.properties.NOMGEO}</b><br>
                                    Región: <b>${res.name}</b><br>
                                    <hr style="margin:5px 0; border:0; border-top:1px solid rgba(255,255,255,0.2)">
                                    Se encontraron <b style="font-size:14px">${count}</b> puntos personalizados dentro.
                                </div>`;
                                L.popup().setLatLng(e.latlng).setContent(msg).openOn(map);
                            } catch (err) { console.error('Error PiP:', err); }
                            return;
                        }
                        if (window.analysisMode) return;

                        try { highlightLayer.clearLayers(); } catch (e) { }
                        if (highlightLabel) { try { map.removeLayer(highlightLabel); } catch (e) { }; highlightLabel = null; }

                        highlightLayer.addData(f);
                        highlightLayer.eachLayer(layer => {
                            layer.bindTooltip(`${f.properties.NOMGEO}<br><small style="opacity:0.8">Región: ${res.name}</small>`, {
                                permanent: false,
                                direction: 'center',
                                className: 'custom-municipio-tooltip',
                                sticky: true
                            });
                        });
                        applyGlowToLayer(highlightLayer);

                        const normalizeStr = str => str ? str.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toUpperCase().trim() : "";
                        const searchName = normalizeStr(f.properties.NOMGEO);
                        
                        if (poblacion && poblacion.municipios) {
                            const pData = poblacion.municipios.find(x => normalizeStr(x.NOMGEO) === searchName);
                            if (pData) {
                                pData.NOMGEO = `${f.properties.NOMGEO} (${res.name})`;
                                actualizarLeyenda('regiones_veracruz', pData);
                                pData.NOMGEO = f.properties.NOMGEO;
                            }
                        }

                        if (window.ui && window.ui.mostrarInfoMunicipio) {
                            window.ui.mostrarInfoMunicipio(f.properties.CVEGEO, f.properties.NOMGEO);
                        }
                    });

                    l.bindTooltip(`${f.properties.NOMGEO} (${res.name})`, {
                        direction: 'center',
                        className: 'text-xs'
                    });
                }
            });
            layers.regionesVer.addLayer(geoJsonLayer);
        });

        layers.regionesVer.addTo(map);
        try { map.fitBounds(layers.regionesVer.getBounds(), { padding: [30, 30] }); } catch (e) { }

        if (typeof showNotification === 'function') {
            showNotification('¡Regiones de Veracruz cargadas con éxito!', 'success');
        }
    }).catch(err => {
        console.error("Error cargando regiones de Veracruz:", err);
        if (typeof showNotification === 'function') {
            showNotification('Error al cargar las regiones.', 'error');
        }
    });
}

function normalizar(txt) {
    if (!txt) return '';
    return txt.normalize('NFD').replace(/[\u0300-\u036f]/g, "").toLowerCase();
}

function onMapClickForMarker(e) {
    const { lat, lng } = e.latlng;
    if (tempMarker) map.removeLayer(tempMarker);
    tempMarker = L.marker([lat, lng], {
        icon: L.divIcon({
            className: 'temp-marker-container',
            html: `<div class="temp-marker" style="background: #F6C453; width: 30px; height: 30px; border-radius: 50% 50% 50% 0; transform: rotate(-45deg); border: 3px solid white; box-shadow: 0 4px 10px rgba(0,0,0,0.3);"></div>`,
            iconSize: [30, 30],
            iconAnchor: [15, 42]
        })
    }).addTo(map);
    openMarkerPanel(lat, lng);
}

function renderCustomPoints(pointsToRender = customPoints) {
    customPointsLayer.clearLayers();
    pointsToRender.forEach(point => {
        const color = categoryColors[point.category] || '#64748b';
        const iconClass = categoryIcons[point.category] || 'fa-map-pin';
        const marker = L.marker([point.lat, point.lng], {
            icon: L.divIcon({
                className: 'custom-point-marker',
                html: `<div style="background: ${color}; width: 24px; height: 24px; border-radius: 50% 50% 50% 0; transform: rotate(-45deg); border: 2px solid white; box-shadow: 0 3px 8px rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center;"><i class="fas ${iconClass}" style="color: white; font-size: 10px; transform: rotate(45deg);"></i></div>`,
                iconSize: [24, 24],
                iconAnchor: [14, 30]
            })
        });

        const container = document.createElement('div');
        container.style.minWidth = "250px";
        container.innerHTML = `
            <h3 style="color: ${color}; font-weight: bold; margin-bottom: 8px; font-size: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom:4px;">${point.name}</h3>
            <div style="font-size: 12px; color: rgba(255,255,255,0.9);">
                ${point.image_url ? `<img src="${getFullUrl(point.image_url)}" class="w-full h-32 object-cover rounded-lg mb-3 border border-white/20 shadow-lg cursor-pointer" onclick="window.open('${getFullUrl(point.image_url)}', '_blank')">` : ''}
                <p><strong>Categoría:</strong> ${getCategoryLabel(point.category)}</p>
                <p><strong>Dirección:</strong> ${point.address || ''}</p>
                <p style="font-size: 10px; opacity: 0.7; margin-top: 5px;"><i class="fas fa-location-crosshairs"></i> <b>Lat:</b> ${point.lat.toFixed(6)}, <b>Lng:</b> ${point.lng.toFixed(6)}</p>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 12px; padding: 8px 0; border-top: 1px solid rgba(255,255,255,0.1);">
                    <button onclick="likePoint(${point.id}, this)" class="social-btn ${localStorage.getItem('liked_' + point.id) ? 'liked' : ''}">
                        <i class="fas fa-heart"></i> <span class="like-count">${point.likes || 0}</span>
                    </button>
                    <button onclick="toggleComments(${point.id})" class="social-btn">
                        <i class="fas fa-comment"></i> Comentarios
                    </button>
                </div>
                <div id="comments-section-${point.id}" class="hidden" style="margin-top:10px;">
                    <div id="comments-list-${point.id}" style="max-height: 120px; overflow-y: auto; font-size: 10px; background: rgba(0,0,0,0.2); border-radius: 8px; padding: 6px;"></div>
                    <div style="display: flex; gap: 4px; margin-top: 6px;">
                        <input type="text" id="comment-input-${point.id}" placeholder="Escribe..." style="flex:1; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); border-radius: 4px; padding: 4px; color: white;">
                        <button onclick="sendComment(${point.id})" style="background: #F6C453; color: #1e3c72; padding: 4px; border-radius: 4px;">➡️</button>
                    </div>
                </div>
                <div style="display: flex; gap: 8px; margin-top: 12px;">
                    ${(() => {
                const sUser = String(localStorage.getItem('sig_user') || '').toLowerCase();
                const sRole = String(localStorage.getItem('sig_role') || '').toLowerCase();
                const isAdm = sUser.includes('admin') || sRole.includes('admin');
                if (authToken && isAdm) {
                    return `<button onclick="editCustomPoint(${point.id})" class="flex-1 bg-[#F6C453] text-[#1e3c72] rounded p-1">Editar</button>
                                    <button onclick="window.deleteCustomPoint(${point.id})" class="flex-1 bg-red-500 text-white rounded p-1">Borrar</button>`;
                } else if (authToken) {
                    return '<p class="text-[10px] opacity-60 w-full text-center">Solo el administrador puede editar o borrar</p>';
                } else {
                    return '<p class="text-[10px] opacity-60 w-full text-center">Inicia sesión para interactuar</p>';
                }
            })()}
                </div>
            </div>
        `;
        marker.bindPopup(container);

        // --- MEJORA DE SELECCIÓN: Permitir capturar el punto para análisis ---
        marker.on('click', (e) => {
            if (window.analysisMode) {
                // Si estamos midiendo, enviamos el clic al mapa para que la herramienta lo capture
                L.DomEvent.stopPropagation(e);
                map.fire('click', { latlng: marker.getLatLng(), originalEvent: e.originalEvent });
                marker.closePopup(); // Asegurarnos de que no se abra la info si estamos midiendo
            }
        });

        customPointsLayer.addLayer(marker);
    });
}

// --- VISUALIZACIÓN DE CAPAS PERSONALIZADAS ---
window.mapLayers = {};

async function loadAndShowLayer(id, url, type) {
    try {
        let geojson = null;
        url = typeof getFullUrl === 'function' ? getFullUrl(url) : url;

        if (type === 'geojson') {
            const res = await fetch(url);
            geojson = await res.json();
        }
        else if (type === 'shp') {
            // shpjs lee el zip directamente desde el URL
            geojson = await shp(url);
        }
        else if (type === 'csv') {
            const res = await fetch(url);
            const csvText = await res.text();
            geojson = await processCSVToGeoJSON(csvText);
        }

        if (geojson) {
            const layer = L.geoJSON(geojson, {
                style: {
                    color: '#F6C453',
                    weight: 2,
                    fillOpacity: 0.4,
                    fillColor: '#F6C453'
                },
                onEachFeature: (f, l) => {
                    l.on('click', (e) => {
                        if (window.pipMode) {
                            // Modo Análisis: Conteo de Puntos en Polígono
                            try {
                                const polygon = f.geometry; // GeoJSON geometry del polígono
                                let count = 0;

                                if (typeof customPoints !== 'undefined') {
                                    customPoints.forEach(p => {
                                        const point = turf.point([p.lng, p.lat]);
                                        if (turf.booleanPointInPolygon(point, polygon)) {
                                            count++;
                                        }
                                    });
                                }

                                const msg = `<b>RESULTADO ANÁLISIS SIG</b><br>Se encontraron <b>${count}</b> puntos dentro de este polígono.<br><small>(Solo cuenta puntos guardados en la base de datos)</small>`;
                                L.popup().setLatLng(e.latlng).setContent(msg).openOn(map);
                                return false; // Detener propagación
                            } catch (err) { console.error('Error análisis PiP:', err); }
                        }
                    });

                    let popup = '<div style="max-height:200px; overflow-auto;"><b>Datos de Capa</b><hr>';
                    for (let key in f.properties) {
                        popup += `<br><b>${key}:</b> ${f.properties[key]}`;
                    }
                    popup += '</div>';
                    l.bindPopup(popup);
                }
            }).addTo(map);

            const bounds = layer.getBounds();
            if (bounds.isValid()) map.flyToBounds(bounds, { padding: [50, 50] });

            return layer;
        }
    } catch (error) {
        console.error('❌ Error procesando capa espacial:', {
            url: url,
            type: type,
            error: error
        });
        return null;
    }
}

async function processCSVToGeoJSON(csvText) {
    return new Promise((resolve) => {
        Papa.parse(csvText, {
            header: true,
            skipEmptyLines: true,
            complete: (results) => {
                const features = [];
                results.data.forEach(row => {
                    // Buscar columnas que parezcan latitud y longitud
                    const latKey = Object.keys(row).find(k => k.toLowerCase().includes('lat') || k.toLowerCase() === 'y');
                    const lngKey = Object.keys(row).find(k => k.toLowerCase().includes('lng') || k.toLowerCase().includes('lon') || k.toLowerCase() === 'x');

                    if (latKey && lngKey && row[latKey] && row[lngKey]) {
                        features.push({
                            type: 'Feature',
                            geometry: {
                                type: 'Point',
                                coordinates: [parseFloat(row[lngKey]), parseFloat(row[latKey])]
                            },
                            properties: row
                        });
                    }
                });
                resolve({ type: 'FeatureCollection', features });
            }
        });
    });
}

window.loadAndShowLayer = loadAndShowLayer;

// --- CHIAPAS ---
let chiapasEstadoGeoJSON = null;
let chiapasMunicipiosGeoJSON = null;
let chiapasRegionesGeoJSON = null;
let chiapasOlvidadosGeoJSON = null;

function showChiapasState() {
    if (currentScale === 'chiapas_estatal') {
        currentScale = null;
        setActiveBtn(null);
        clearAll();
        document.getElementById('map-legend').innerHTML = '';
        return;
    }
    currentScale = 'chiapas_estatal';
    setActiveBtn('btn-chiapas-estatal');
    clearAll();
    actualizarLeyenda('chiapas_estatal');

    const render = (data) => {
        const layer = L.geoJSON(data, { style: { color: '#f97316', weight: 2, fillOpacity: 0.2, fillColor: '#f97316' } }).addTo(layers.chiapasEstado);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    };

    if (chiapasEstadoGeoJSON) {
        render(chiapasEstadoGeoJSON);
    } else {
        fetch('chiapas_estado.geojson').then(r => r.json()).then(data => {
            chiapasEstadoGeoJSON = data;
            render(data);
        }).catch(e => console.warn("Error cargando chiapas estado", e));
    }
    checkMarginacionOverlay();
    checkCrecimientoOverlay();
}

function showChiapasMunicipalities() {
    if (currentScale === 'chiapas_municipios') {
        currentScale = null;
        setActiveBtn(null);
        clearAll();
        document.getElementById('map-legend').innerHTML = '';
        return;
    }
    currentScale = 'chiapas_municipios';
    setActiveBtn('btn-chiapas-municipios');
    clearAll();
    actualizarLeyenda('chiapas_municipios');

    const render = (data) => {
        const layer = L.geoJSON(data, {
            style: { color: '#ea580c', weight: 1, fillOpacity: 0.1, fillColor: '#fdba74' },
            onEachFeature: (feature, layer) => {
                const nom = feature.properties.NOMGEO || 'Desconocido';
                layer.bindTooltip(<b></b>, { sticky: true, className: 'custom-tooltip' });
            }
        }).addTo(layers.chiapasMunicipios);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    };

    if (chiapasMunicipiosGeoJSON) {
        render(chiapasMunicipiosGeoJSON);
    } else {
        fetch('chiapas_municipios.geojson').then(r => r.json()).then(data => {
            chiapasMunicipiosGeoJSON = data;
            render(data);
        }).catch(e => console.warn("Error", e));
    }
    checkMarginacionOverlay();
    checkCrecimientoOverlay();
}

function showChiapasRegions() {
    if (currentScale === 'chiapas_regiones') {
        currentScale = null;
        setActiveBtn(null);
        clearAll();
        document.getElementById('map-legend').innerHTML = '';
        return;
    }
    currentScale = 'chiapas_regiones';
    setActiveBtn('btn-regiones-chiapas');
    clearAll();
    actualizarLeyenda('chiapas_regiones');

    const render = (data) => {
        const layer = L.geoJSON(data, {
            style: (feature) => {
                return { color: '#c2410c', weight: 2, fillOpacity: 0.4, fillColor: getRandomColor(feature.properties.REGION || feature.properties.NOM_REGION) };
            },
            onEachFeature: (feature, layer) => {
                const nom = feature.properties.REGION || feature.properties.NOM_REGION || 'Región';
                layer.bindTooltip(<b></b>, { sticky: true, className: 'custom-tooltip' });
            }
        }).addTo(layers.chiapasRegiones);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    };

    if (chiapasRegionesGeoJSON) {
        render(chiapasRegionesGeoJSON);
    } else {
        fetch('chiapas_regiones.geojson').then(r => r.json()).then(data => {
            chiapasRegionesGeoJSON = data;
            render(data);
        }).catch(e => console.warn("Error", e));
    }
    checkMarginacionOverlay();
    checkCrecimientoOverlay();
}

function showChiapasForgotten() {
    if (currentScale === 'chiapas_olvidados') {
        currentScale = null;
        setActiveBtn(null);
        clearAll();
        document.getElementById('map-legend').innerHTML = '';
        return;
    }
    currentScale = 'chiapas_olvidados';
    setActiveBtn('btn-olvidados-chiapas');
    clearAll();
    actualizarLeyenda('chiapas_olvidados');

    const render = (data) => {
        const layer = L.geoJSON(data, {
            style: { color: '#b91c1c', weight: 2, fillOpacity: 0.5, fillColor: '#ef4444' },
            onEachFeature: (feature, layer) => {
                const nom = feature.properties.NOMGEO || 'Desconocido';
                layer.bindTooltip(<b></b><br><span style="color:#ef4444;font-size:10px;">Municipio Olvidado</span>, { sticky: true, className: 'custom-tooltip' });
            }
        }).addTo(layers.chiapasOlvidados);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    };

    if (chiapasOlvidadosGeoJSON) {
        render(chiapasOlvidadosGeoJSON);
    } else {
        fetch('chiapas_municipios_olvidados.geojson').then(r => r.json()).then(data => {
            chiapasOlvidadosGeoJSON = data;
            render(data);
        }).catch(e => console.warn("Error", e));
    }
    checkMarginacionOverlay();
    checkCrecimientoOverlay();
}

function getRandomColor(seed) {
    let hash = 0;
    if (seed) {
        const str = String(seed);
        for (let i = 0; i < str.length; i++) hash = str.charCodeAt(i) + ((hash << 5) - hash);
    } else {
        hash = Math.random() * 100000;
    }
    let c = (hash & 0x00FFFFFF).toString(16).toUpperCase();
    return '#' + '00000'.substring(0, 6 - c.length) + c;
}

// --- MARGINACION ---
let marginacionGeoJSONs = {};

function toggleMarginacion() {
    const chk = document.getElementById('chk-marginacion');
    if (chk && chk.checked) {
        applyMarginacionOverlay();
    } else {
        try { map.removeLayer(layers.marginacion); } catch (e) { }
    try { map.removeLayer(layers.crecimiento); } catch (e) { }
        layers.marginacion.clearLayers();
    }
}

function checkMarginacionOverlay() {
    const chk = document.getElementById('chk-marginacion');
    if (chk && chk.checked) {
        applyMarginacionOverlay();
    }
}

function applyMarginacionOverlay() {
    try { map.removeLayer(layers.marginacion); } catch (e) { }
    try { map.removeLayer(layers.crecimiento); } catch (e) { }
    layers.marginacion.clearLayers();

    let fileToLoad = null;
    if (currentScale === 'nacional') {
        fileToLoad = 'marginacion_estatal_nacional_2020.geojson';
    } else if (currentScale === 'estatal' || currentScale === 'municipios' || currentScale === 'regiones_ver' || currentScale === 'regiones_uv') {
        fileToLoad = 'marginacion_municipal_veracruz_2020.geojson';
    } else if (currentScale === 'chiapas_estatal' || currentScale === 'chiapas_municipios' || currentScale === 'chiapas_regiones' || currentScale === 'chiapas_olvidados') {
        fileToLoad = 'marginacion_municipal_chiapas_2020.geojson';
    } else {
        fileToLoad = 'marginacion_estatal_nacional_2020.geojson';
    }

    const render = (data) => {
        const layer = L.geoJSON(data, {
            style: (feature) => {
                const gm = feature.properties.GM_2020 || feature.properties.GM || feature.properties.Grado || 'Medio';
                let color = '#fcd34d'; 
                const gmLower = String(gm).toLowerCase();
                if (gmLower.includes('muy alto')) color = '#b91c1c';
                else if (gmLower.includes('alto')) color = '#ef4444';
                else if (gmLower.includes('medio')) color = '#f97316';
                else if (gmLower.includes('bajo') && !gmLower.includes('muy bajo')) color = '#eab308';
                else if (gmLower.includes('muy bajo')) color = '#22c55e';
                
                return { color: '#000', weight: 1, fillOpacity: 0.75, fillColor: color };
            },
            onEachFeature: (feature, layer) => {
                const nom = feature.properties.NOM_ENT || feature.properties.NOMGEO || feature.properties.NOM_MUN || 'Desconocido';
                const gm = feature.properties.GM_2020 || feature.properties.GM || feature.properties.Grado || 'N/D';
                const im = feature.properties.IM_2020 || feature.properties.IM || feature.properties.Indice || 'N/D';
                layer.bindTooltip(<b></b><br>Grado de Marginación: <b></b><br>Índice: , { sticky: true, className: 'custom-tooltip' });
            }
        }).addTo(layers.marginacion);
        layers.marginacion.addTo(map);
    };

    if (marginacionGeoJSONs[fileToLoad]) {
        render(marginacionGeoJSONs[fileToLoad]);
    } else {
        fetch(fileToLoad).then(r => r.json()).then(data => {
            marginacionGeoJSONs[fileToLoad] = data;
            render(data);
        }).catch(e => console.warn("Error marginacion", e));
    }
}

// --- CRECIMIENTO POBLACIONAL ---
let crecimientoGeoJSON = null;

function toggleCrecimiento() {
    const chk = document.getElementById('chk-crecimiento');
    if (chk && chk.checked) {
        applyCrecimientoOverlay();
    } else {
        try { map.removeLayer(layers.crecimiento); } catch (e) { }
        layers.crecimiento.clearLayers();
    }
}

function checkCrecimientoOverlay() {
    const chk = document.getElementById('chk-crecimiento');
    if (chk && chk.checked) {
        applyCrecimientoOverlay();
    }
}

function applyCrecimientoOverlay() {
    try { map.removeLayer(layers.crecimiento); } catch (e) { }
    layers.crecimiento.clearLayers();

    // The user's file is at national level (by state)
    // If the user zooms to state or municipality, it might look out of place if it's national,
    // but we only have 1 file. We will display it regardless.

    const render = (data) => {
        const layer = L.geoJSON(data, {
            style: (feature) => {
                const pct = feature.properties.Pct_Inc_00_20 || 0;
                let color = '#3b82f6'; // Azul base
                if (pct > 50) color = '#1e3a8a'; // Azul muy oscuro (+50%)
                else if (pct > 25) color = '#2563eb'; // Azul oscuro (+25%)
                else if (pct > 10) color = '#60a5fa'; // Azul claro (+10%)
                else if (pct > 0) color = '#93c5fd'; // Azul muy claro (+0%)
                else color = '#f87171'; // Rojo (Decrecimiento)
                
                return { color: '#000', weight: 1, fillOpacity: 0.7, fillColor: color };
            },
            onEachFeature: (feature, layer) => {
                const nom = feature.properties.Estado || feature.properties.NOMGEO || 'Desconocido';
                const p2000 = (feature.properties.Pob_2000 || 0).toLocaleString();
                const p2010 = (feature.properties.Pob_2010 || 0).toLocaleString();
                const p2020 = (feature.properties.Pob_2020 || 0).toLocaleString();
                const inc = (feature.properties.Inc_00_20 || 0).toLocaleString();
                const pct = feature.properties.Pct_Inc_00_20 || 0;
                layer.bindTooltip(`
                    <b>${nom}</b><br>
                    <hr style="margin:2px 0;border-color:rgba(255,255,255,0.2);">
                    Población 2000: ${p2000}<br>
                    Población 2010: ${p2010}<br>
                    Población 2020: ${p2020}<br>
                    Crecimiento (2000-2020): <b>${inc} habs.</b><br>
                    Aumento Porcentual: <b>${pct.toFixed ? pct.toFixed(2) : pct}%</b>
                `, { sticky: true, className: 'custom-tooltip' });
            }
        }).addTo(layers.crecimiento);
        layers.crecimiento.addTo(map);
    };

    if (crecimientoGeoJSON) {
        render(crecimientoGeoJSON);
    } else {
        fetch('Poblacion_comparativa.geojson').then(r => r.json()).then(data => {
            crecimientoGeoJSON = data;
            render(data);
        }).catch(e => console.warn("Error crecimiento", e));
    }
}
