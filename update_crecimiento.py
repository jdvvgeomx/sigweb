import re

with open('js/map.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Add to layers
content = content.replace("marginacion: L.featureGroup(),", "marginacion: L.featureGroup(),\n    crecimiento: L.featureGroup(),")

# Add to clearAll
content = content.replace("try { map.removeLayer(layers.marginacion); } catch (e) { }", "try { map.removeLayer(layers.marginacion); } catch (e) { }\n    try { map.removeLayer(layers.crecimiento); } catch (e) { }")

# Add hook to existing checkMarginacionOverlay()
content = content.replace("checkMarginacionOverlay();", "checkMarginacionOverlay();\n    checkCrecimientoOverlay();")

# Add new functions
new_funcs = '''
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
                layer.bindTooltip(
                    <b></b><br>
                    <hr style="margin:2px 0;border-color:rgba(255,255,255,0.2);">
                    Población 2000: <br>
                    Población 2010: <br>
                    Población 2020: <br>
                    Crecimiento (2000-2020): <b> habs.</b><br>
                    Aumento Porcentual: <b>%</b>
                , { sticky: true, className: 'custom-tooltip' });
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
'''
if "function toggleCrecimiento()" not in content:
    content += new_funcs

with open('js/map.js', 'w', encoding='utf-8') as f:
    f.write(content)

print("map.js updated successfully for crecimiento")
