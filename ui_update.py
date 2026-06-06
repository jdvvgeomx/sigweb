import re

with open('js/ui.js', 'r', encoding='utf-8') as f:
    content = f.read()

new_legends = '''    } else if (tipo === 'chiapas_estatal') {
        content = <b>Chiapas Estatal</b><br><span class="legend-color-box" style="background:#f97316"></span> Chiapas;
    } else if (tipo === 'chiapas_municipios') {
        content = <b>Municipios de Chiapas</b><br><span class="legend-color-box" style="background:#fdba74"></span> Limites Municipales;
    } else if (tipo === 'chiapas_regiones') {
        content = <b>16 Regiones de Chiapas</b><br><span class="legend-color-box" style="background:linear-gradient(90deg, #c2410c, #f97316)"></span> Múltiples Colores;
    } else if (tipo === 'chiapas_olvidados') {
        content = <b>Municipios Olvidados</b><br><span class="legend-color-box" style="background:#ef4444"></span> Municipios Prioritarios;
    } else if (tipo === 'regiones_veracruz') {'''

content = content.replace("} else if (tipo === 'regiones_veracruz') {", new_legends)

with open('js/ui.js', 'w', encoding='utf-8') as f:
    f.write(content)

print("Legends added")
