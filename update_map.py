import re

with open('js/map.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace layers definition
old_layers = '''var layers = {
    nacional: L.featureGroup(),
    estatal: L.featureGroup(),
    municipios: L.featureGroup(),
    regionesUV: L.featureGroup(),
    regionesVer: L.featureGroup(),
    servicios: { 1: L.layerGroup(), 2: L.layerGroup(), 3: L.layerGroup(), 4: L.layerGroup(), 5: L.layerGroup() }
};'''

new_layers = '''var layers = {
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
    servicios: { 1: L.layerGroup(), 2: L.layerGroup(), 3: L.layerGroup(), 4: L.layerGroup(), 5: L.layerGroup() }
};'''
content = content.replace(old_layers, new_layers)

# Replace clearAll
old_clear = '''function clearAll() {
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
}'''

new_clear = '''function clearAll() {
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
}'''
content = content.replace(old_clear, new_clear)

# Add checkMarginacionOverlay to the end of existing scale functions
funcs_to_hook = ['showNational', 'showState', 'showMunicipalities', 'showUVRegions', 'showVeracruzRegions']
for func in funcs_to_hook:
    # We find the definition and insert the call before its closing brace.
    # Actually, a safer way is to find the function signature and its end.
    pass # we can do this simply by replacing 'checkMarginacionOverlay();' if it's already there, or finding the exact place.

# Actually, it's easier to just add the functions at the end of the file.
new_funcs = '''
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
'''
if "function showChiapasState()" not in content:
    content += new_funcs

with open('js/map.js', 'w', encoding='utf-8') as f:
    f.write(content)

print("map.js updated successfully")
