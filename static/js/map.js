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
        fetch('Nacional_opt.geojson').then(r => r.json()).then(data => {
            const isDarkLayer = (layerName === 'Satélite Híbrido');
            const nationalStyle = isDarkLayer ?
                { color: '#F6C453', weight: 2, fillOpacity: 0.25, fillColor: '#F6C453' } :
                { color: '#000', weight: 2, fillOpacity: 0.35, fillColor: '#555' };
            L.geoJSON(data, { style: nationalStyle }).addTo(layers.nacional);
        }).catch(e => console.warn("Error actualizando polígono nacional", e));
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
    servicios: { 1: L.layerGroup(), 2: L.layerGroup(), 3: L.layerGroup(), 4: L.layerGroup(), 5: L.layerGroup() }
};

customPointsLayer = L.layerGroup().addTo(map);

var highlightLayer = L.geoJSON(null, {
    style: {
        color: "#1affff",
        weight: 6,
        fillOpacity: 0.3,
        opacity: 1,
        dashArray: '3'
    }
}).addTo(map);

var highlightLabel = null;

function applyGlowToLayer(geoLayer) {
    try {
        geoLayer.eachLayer(l => {
            const el = l.getElement ? l.getElement() : null;
            if (el) {
                el.classList.add('glow', 'pulse');
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

    fetch('Nacional_opt.geojson').then(r => r.json()).then(data => {
        const isDarkLayer = (currentBaseLayer === baseLayers['Satélite Híbrido']);
        const nationalStyle = isDarkLayer ?
            { color: '#F6C453', weight: 2, fillOpacity: 0.25, fillColor: '#F6C453' } :
            { color: '#000', weight: 2, fillOpacity: 0.35, fillColor: '#555' };

        const layer = L.geoJSON(data, { style: nationalStyle }).addTo(layers.nacional);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    }).catch(e => console.warn("Nacional_opt.geojson error", e));

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
                <ul class="text-[12px] space-y-2 mb-4">
                    <li class="flex justify-between items-center text-blue-300">
                        <span class="flex items-center gap-2"><div class="w-3 h-3 rounded-full bg-[#3B82F6]"></div> Hombres</span> 
                        <b class="text-white">${(pn.POB84 || 0).toLocaleString()}</b>
                    </li>
                    <li class="flex justify-between items-center text-pink-300">
                        <span class="flex items-center gap-2"><div class="w-3 h-3 rounded-full bg-[#F472B6]"></div> Mujeres</span> 
                        <b class="text-white">${(pn.POB42 || 0).toLocaleString()}</b>
                    </li>
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

    fetch('Veracruz.geojson').then(r => r.json()).then(data => {
        const layer = L.geoJSON(data, { style: { color: '#006847', weight: 2, fillOpacity: 0.2 } }).addTo(layers.estatal);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    }).catch(e => console.warn("Veracruz.geojson error", e));

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

    if (layers.municipios && layers.municipios.getLayers && layers.municipios.getLayers().length > 0) {
        layers.municipios.addTo(map);
        try { map.fitBounds(layers.municipios.getBounds(), { padding: [30, 30] }); } catch (e) { }
        return;
    }

    fetch('Municipal_opt.geojson').then(r => r.json()).then(data => {
        municipalGeoJSON = data;
        const layer = L.geoJSON(data, {
            style: (feature) => {
                const pob = feature.properties.POB1 || 0;
                return { fillColor: getColor(pob), weight: 1, opacity: 1, color: 'white', fillOpacity: 0.7 };
            },
            onEachFeature: (f, l) => {
                l.on('click', (e) => {
                    // --- NUEVA LÓGICA DE PRIORIDAD DE ANÁLISIS ---

                    // 1. Si estamos en modo "Conteo de Puntos" (PiP), ejecutamos análisis
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
                        return; // Importante: Salir para no mostrar info demográfica
                    }

                    // 2. Si estamos en CUALQUIER OTRA herramienta de análisis (Medir, Buffer)
                    // NO hacemos nada aquí para dejar que el clic llegue al MAPA
                    if (window.analysisMode) {
                        return;
                    }

                    // 3. Comportamiento normal: Mostrar información del municipio y abrir POPUP con gráfica
                    try { highlightLayer.clearLayers(); } catch (e) { }
                    if (highlightLabel) { try { map.removeLayer(highlightLabel); } catch (e) { }; highlightLabel = null; }

                    highlightLayer.addData(f);
                    applyGlowToLayer(highlightLayer);
                    const center = l.getBounds().getCenter();

                    highlightLabel = L.marker(center, {
                        icon: L.divIcon({ className: 'etiquetaGlow', html: `<div class="labelBox pulseLabel">${f.properties.NOMGEO}</div>` }),
                        interactive: false
                    }).addTo(map);

                    // Normalización robusta para búsqueda de población (igual que en ui.js)
                    const normalizeStr = str => str ? str.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toUpperCase().trim() : "";
                    const searchName = normalizeStr(f.properties.NOMGEO);

                    // Bug fix #2: guard — si los datos de población aún no cargaron, no crashear
                    if (!poblacion || !poblacion.municipios || poblacion.municipios.length === 0) {
                        l.bindPopup(`<div style="padding:12px; text-align:center">
                            <b style="color:#F6C453">${f.properties.NOMGEO}</b><br>
                            <i style="opacity:0.6; font-size:11px">⏳ Cargando datos demográficos...</i>
                        </div>`).openPopup();
                        return;
                    }
                    const pData = poblacion.municipios.find(x => normalizeStr(x.NOMGEO) === searchName);

                    if (pData) {
                        const popupContent = `
                            <div class="municipio-popup-content" style="min-width: 260px; padding: 5px; color: white !important;">
                                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px; border-bottom: 2px solid #F6C453; padding-bottom: 8px;">
                                    <h3 style="margin: 0; font-size: 16px; font-weight: 900; text-transform: uppercase; color: #F6C453; letter-spacing: 0.5px;">${f.properties.NOMGEO}</h3>
                                    <i class="fas fa-chart-pie" style="margin-left:auto; opacity:0.6"></i>
                                </div>
                                
                                <div style="background: rgba(255,255,255,0.05); padding: 12px; border-radius: 16px; margin-bottom: 15px; text-align: center; border: 1px solid rgba(255,255,255,0.1); box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);">
                                    <p style="margin: 0; font-size: 10px; opacity: 0.6; text-transform: uppercase; font-weight: 700; letter-spacing: 1px;">Población Total</p>
                                    <p style="margin: 0; font-size: 28px; font-weight: 900; color: #fff;">${(pData.POB1 || 0).toLocaleString()}</p>
                                </div>

                                <div style="height: 180px; width: 100%; position: relative; background: rgba(0,0,0,0.2); rounded: 12px; padding: 10px;">
                                    <canvas id="popup-chart-${f.properties.CVEGEO}"></canvas>
                                </div>

                                <div style="margin-top: 15px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.1); font-size: 9px; text-align: right; opacity: 0.5; font-weight: bold;">
                                    <i class="fas fa-database text-[#F6C453]"></i> FUENTE: CENSO INEGI 2020
                                </div>
                            </div>
                        `;

                        const popup = L.popup({
                            maxWidth: 350,
                            className: 'municipio-chart-popup',
                            offset: [0, -10]
                        })
                            .setLatLng(e.latlng)
                            .setContent(popupContent);

                        popup.on('add', () => {
                            // Usar un pequeño delay para asegurar visibilidad y tamaño
                            setTimeout(() => {
                                const canvasId = `popup-chart-${f.properties.CVEGEO}`;
                                const canvas = document.getElementById(canvasId);
                                if (canvas && window.ui && window.ui.renderMunicipioChart) {
                                    // Limpiar instancia previa si existe
                                    if (typeof Chart !== 'undefined') {
                                        const prev = Chart.getChart(canvas);
                                        if (prev) prev.destroy();
                                    }
                                    window.ui.renderMunicipioChart(canvas, pData, true);
                                } else {
                                    console.error("Canvas o ui.renderMunicipioChart no disponibles para este popup");
                                }
                            }, 50);
                        });

                        popup.openOn(map);
                    } else {
                        l.bindPopup(`<div style="padding:10px"><b>${f.properties.NOMGEO}</b><br>Datos no disponibles.</div>`).openPopup();
                    }

                    if (window.ui && window.ui.mostrarInfoMunicipio) {
                        window.ui.mostrarInfoMunicipio(f.properties.CVEGEO, f.properties.NOMGEO);
                    } else if (typeof mostrarInfoMunicipio === 'function') {
                        mostrarInfoMunicipio(f.properties.CVEGEO, f.properties.NOMGEO);
                    }
                });
                // Quitamos el bindPopup estático para controlar la apertura manualmente arriba
                // l.bindPopup(f.properties.NOMGEO); 
            }
        }).addTo(layers.municipios);
        layers.municipios.addTo(map);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    }).catch(e => console.warn("Municipal_opt.geojson error", e));
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

    fetch('Municipal_opt.geojson').then(r => r.json()).then(data => {
        const layer = L.geoJSON(data, {
            style: (feature) => {
                const nom = feature.properties.NOMGEO;
                let regionColor = null;
                for (const [key, val] of Object.entries(uvRegionsData)) {
                    if (val.municipios.some(m => normalizar(m) === normalizar(nom))) {
                        regionColor = val.color;
                        feature.properties.uvRegion = key;
                        break;
                    }
                }
                return regionColor ? { color: 'white', weight: 1, fillColor: regionColor, fillOpacity: 0.6 } : { color: 'transparent', weight: 0, fillColor: '#ccc', fillOpacity: 0.1 };
            },
            onEachFeature: (f, l) => {
                if (f.properties.uvRegion) {
                    l.on('click', () => {
                        toggleFacultades(f.properties.uvRegion);
                        mostrarInfoRegionUV(f.properties.uvRegion);
                        l.setStyle({ fillOpacity: 0.8 });
                        setTimeout(() => l.setStyle({ fillOpacity: 0.6 }), 500);
                    });
                    l.bindTooltip(f.properties.NOMGEO, { direction: 'center', className: 'text-xs' });
                }
            }
        }).addTo(layers.regionesUV);
        layers.regionesUV.addTo(map);
        try { map.fitBounds(layer.getBounds(), { padding: [30, 30] }); } catch (e) { }
    }).catch(e => console.warn("Error UV municipios", e));
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
        console.error('❌ Error procesando capa espacial:', error);
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
