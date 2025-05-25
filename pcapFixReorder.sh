#!/bin/bash
directories=("./ModbusDataset/benign" "./ModbusDataset/attack")
# Path to pcapfix and reordercap executables
pcapfix_cmd="pcapfix"
reordercap_cmd="reordercap"

# Loop through each top-level directory
for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        # Find all .pcap files recursively under the directory
        find "$dir" -type f -name "*.pcap" | while read -r pcap_file; do
            # Get the subdirectory containing the .pcap file
            subdir=$(dirname "$pcap_file")
            echo "Processing: $pcap_file"

            # Run pcapfix on the file
            fixed_pcap="${pcap_file%.pcap}_fix.pcap"
            $pcapfix_cmd -d "$pcap_file" -o "$fixed_pcap"

            # Check if pcapfix created a new file; if not, use the original
            if [ ! -f "$fixed_pcap" ]; then
                echo "pcapfix did not create a fixed file. Using the original file for reordering."
                fixed_pcap="$pcap_file"
            fi

            # Create an 'input' folder in the file's subdirectory
            input_dir="$subdir/input"
            mkdir -p "$input_dir"

            # Set the reordered_pcap to be in the input directory with the desired name
            reordered_pcap="$input_dir/$(basename "${pcap_file%.pcap}_fix_ord.pcap")"

            # Run reordercap to write directly to the input directory
            $reordercap_cmd "$fixed_pcap" "$reordered_pcap"

            echo "Reordered file created in: $reordered_pcap"

            # Remove the intermediate fixed file if it was created
            if [ "$fixed_pcap" != "$pcap_file" ] && [ -f "$fixed_pcap" ]; then
                rm "$fixed_pcap"
                echo "Removed intermediate fixed file: $fixed_pcap"
            fi
        done
    else
        echo "Directory $dir does not exist"
    fi
done
