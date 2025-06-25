#!/bin/bash

directories=("./ModbusDataset/benign" "./ModbusDataset/attack")


# Loop through each top-level directory
for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        # Find all .pcap files recursively under the directory
        find "$dir" -type f -name "*.pcap" | while read -r pcap_file; do
		# Get the subdirectory containing the .pcap file
            	subdir=$(dirname "$pcap_file")
		if compgen -G "$subdir/output/*.csv" > /dev/null; then
			continue
		fi
		if compgen -G "$subdir/input/*_fix_ord.pcap" > /dev/null; then
                        echo "Processing $subdir/input/"
			# Create an 'output' folder in the file's subdirectory
                	output_dir="$subdir/output"
                	mkdir -p "$output_dir"

		        # Run the docker command on the specific files
        		docker run --rm -v "$subdir:/tmp/pcap" cicflometer /tmp/pcap/input /tmp/pcap/output -d -e JAVA_OPTS="-Xmx8g -XX:+UseG1GC -XX:MaxGCPauseMillis=200"
        		echo "Processed files in $output_dir"
		else
        		echo "No *_fix_ord.pcap files found in $subdir/input. Skipping..."
    		fi

        done
    else
        echo "Directory $dir does not exist"
    fi
done
