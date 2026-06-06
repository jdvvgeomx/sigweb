import re

with open('js/map.js', 'r', encoding='utf-8') as f:
    content = f.read()

funcs_to_hook = [
    ('actualizarLeyenda(\'nacional\');', 'actualizarLeyenda(\'nacional\');\n    checkMarginacionOverlay();'),
    ('actualizarLeyenda(\'estatal\');', 'actualizarLeyenda(\'estatal\');\n    checkMarginacionOverlay();'),
    ('actualizarLeyenda(\'municipios\');', 'actualizarLeyenda(\'municipios\');\n    checkMarginacionOverlay();'),
    ('actualizarLeyenda(\'regiones_uv\');', 'actualizarLeyenda(\'regiones_uv\');\n    checkMarginacionOverlay();'),
    ('actualizarLeyenda(\'regiones_veracruz\');', 'actualizarLeyenda(\'regiones_veracruz\');\n    checkMarginacionOverlay();')
]

for old, new in funcs_to_hook:
    content = content.replace(old, new)

with open('js/map.js', 'w', encoding='utf-8') as f:
    f.write(content)

print("Hooks added")
