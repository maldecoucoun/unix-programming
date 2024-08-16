ascii_art = """
 ┌───┐  ┌───┐  ┌───┐         ┌───┐  ┌───┐  ┌────
 │   │  │      │   │    •    │      │   │  │
     │  ├───┐  ├───┤  ─────  ├───┐  │   │  └───┐
     │  │   │  │   │    •    │   │  │   │      │
     │  └───┘  └───┘         └───┘  └───┘  └───┘
"""

# Split the ASCII art into lines
lines = ascii_art.strip().split('\n')

# Define the start and end indices for each unit
unit_indices = [
    (0, 6),
    (7, 12),
    (14, 20),
    (22, 27),
    (28, 34),
    (35, 41),
    (43, 48)
]

# Extract each unit
units = []
for start, end in unit_indices:
    unit = ""
    for line in lines:
        unit += line[start:end]
    units.append(unit)

# Print each unit
for i, unit in enumerate(units, 1):
    print(f"Unit {i}:\n{unit}\n")
