import json
import os

filepath = 'marginacion_municipal_nacional_2020.geojson'
print(f"Original size: {os.path.getsize(filepath) / 1024 / 1024:.2f} MB")

with open(filepath, 'r', encoding='utf-8') as f:
    data = json.load(f)

def round_coords(coords):
    if isinstance(coords, list):
        if len(coords) > 0 and isinstance(coords[0], (int, float)):
            return [round(c, 5) for c in coords]
        return [round_coords(c) for c in coords]
    return coords

for feature in data.get('features', []):
    geom = feature.get('geometry')
    if geom and 'coordinates' in geom:
        geom['coordinates'] = round_coords(geom['coordinates'])

with open('marginacion_municipal_nacional_2020_opt.geojson', 'w', encoding='utf-8') as f:
    json.dump(data, f, separators=(',', ':'))

print(f"Optimized size: {os.path.getsize('marginacion_municipal_nacional_2020_opt.geojson') / 1024 / 1024:.2f} MB")
