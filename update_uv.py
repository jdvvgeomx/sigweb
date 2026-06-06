import re

with open('js/map.js', 'r', encoding='utf-8') as f:
    content = f.read()

old_fetch = '''    fetch('Municipal_opt.geojson').then(r => r.json()).then(data => {
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
    }).catch(e => console.warn("Error UV municipios", e));'''

new_fetch = '''    let uvRegionesGeoJSON = null;
    
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
    }).catch(e => console.warn("Error UV regiones", e));'''

if old_fetch in content:
    content = content.replace(old_fetch, new_fetch)
    with open('js/map.js', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Successfully replaced.")
else:
    print("old_fetch not found. Please check map.js manually.")
