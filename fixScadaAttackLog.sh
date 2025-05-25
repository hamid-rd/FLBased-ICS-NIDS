
#!/bin/bash

awk -F, 'BEGIN {OFS = FS}
NR == 1 {print; next}  # Keep header unchanged

{
    # Determine hour based on row number
    if (NR <= 8268) {
        hour = 3
    } else if (NR <= 8291) {
        hour = 4
    } else {
        hour = 5
    }

    # Split timestamp into parts
    split($1, parts, /[:.]/)
    minutes = parts[1] + 0
    seconds = parts[2] + 0
    fraction = substr(parts[3] "00", 1, 3)  # Pad to 3 digits

    # Rebuild the timestamp with date and dynamic hour
    $1 = sprintf("2023-03-21 %02d:%02d:%02d.%s", hour, minutes, seconds, fraction)
    print
}' "./ModbusDataset/attack/compromised-scada/attack logs/03-21-2023/03-21-2023-1-original.csv" > \
"./ModbusDataset/attack/compromised-scada/attack logs/03-21-2023/03-21-2023-1-fixed.csv"
