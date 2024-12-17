#!/bin/bash

# 1. Automate HDD and Memory Analysis:

# 1.1 Checks if the user is root, if not exit.

HOME=$(pwd)
user=$(whoami)
START=$(date)

if [ "$user" == "root" ]; then
    echo "You are root... let's continue"
else
    echo "You are not root... exiting"
    exit 1
fi
     
# 1.2 Allow the user to specify the filename, check if the file exists:
echo "Please enter the path to the file you wish to investigate:"
read file

if [ -f "$file" ]; then
    echo "The file '$file' exists."
else
    echo "The file '$file' does not exist."
    exit 1
fi

# 1.3 Create a function to install the forensics tools if missing:
install_tools() {
    tools=("bulk-extractor" "binwalk" "foremost" "strings" "volatility")

    for tool in "${tools[@]}"; do
        # Check if the tool is installed:
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool is not installed. Installing..."

            # Install the missing tool:
            if [[ "$tool" == "volatility" ]]; then
                # Install volatility:
                git clone https://github.com/yarinm1708/vol2.5.git > /dev/null 2>&1
                cd vol2.5 || exit 1
                chmod +x volatility_2.5_linux_x64
                echo "Volatility installed and set up successfully."

            else
                # Install other tools using apt-get:
                sudo apt-get install "$tool" -y > /dev/null 2>&1
                echo "$tool installed successfully."
            fi

        else
            echo "$tool is already installed."
        fi
    done
}

install_tools


# 1.4 Function to extract data using different carvers + 1.5 Data should be saved into a directory:
# Create output directories if they do not exist
mkdir -p $HOME/forensics_case/binwalk
mkdir -p $HOME/forensics_case/bulk_extractor
mkdir -p $HOME/forensics_case/foremost
mkdir -p "$HOME/forensics_case/volatility" > /dev/null 2>&1

echo "Running binwalk on $file..."
binwalk $file -o $HOME/forensics_case/binwalk > $HOME/forensics_case/binwalk/binwalk_output.txt 2>&1

echo "Running bulk_extractor on $file..."
bulk_extractor -q $file -o $HOME/forensics_case/bulk_extractor > /dev/null 2>&1

echo "Running foremost on $file..."
foremost -i $file -o $HOME/forensics_case/foremost > /dev/null 2>&1

# 1.6 Check if there is a PCAP file and display its location and size:
echo "Checking for PCAP file..."

# Search for any .pcap file in the bulk_extractor folder
pcap_file=$(ls $HOME/forensics_case/bulk_extractor | grep -i "\.pcap")

if [ -z "$pcap_file" ]; then
    echo "Couldn't find a PCAP file..."
else
    echo "PCAP file was found!"
    echo "Location: $HOME/forensics_case/bulk_extractor/$pcap_file"
    
    # Display the size of the PCAP file
    file_size=$(ls -lh $HOME/forensics_case/bulk_extractor/$pcap_file | awk '{print $5}')
    echo "File size: $file_size"
fi

# 1.7 Check for human-readable strings:
echo "Starting the forensic analysis process..."

# Define the directories to search for EXE files
directories=(
    "$HOME/forensics_case/binwalk"
    "$HOME/forensics_case/bulk_extractor"
    "$HOME/forensics_case/foremost"
)

# Analyze EXE files for human-readable strings and save to txt file
echo "Searching for EXE files and extracting strings..."

for dir in "${directories[@]}"; do
    exe_files=$(find "$dir" -type f -name "*.exe")

    for exe in $exe_files; do
        # Extract all human-readable strings from EXE file
        strings "$exe" > "${exe}.txt" 2>/dev/null
    done
done

# Search for sensitive data (passwords and usernames) in the main investigated file
echo "Searching for sensitive data (passwords, usernames) in the main file..."

# Define the output file for sensitive data
output_file="$HOME/forensics_case/passwords_and_usernames.txt"

# Extract sensitive data from the investigated file
strings "$file" | grep -iE "password|username|user|passwords" > "$output_file" 2>/dev/null

# Notify user if sensitive data was found and saved
echo "Sensitive data saved to $output_file"

echo "Forensic analysis process completed."

# 2. Memory Analysis with Volatility
echo "Checking if the file can be analyzed with Volatility..."

if ./volatility_2.5_linux_x64 -f "$file" --info > /dev/null 2>&1; then
    echo "The file can be analyzed with Volatility."
else
    echo "The file cannot be analyzed with Volatility."
    exit 1
fi

# 2.2 Find the memory profile and save it into a variable:
echo "Finding the memory profile..."

memory_profile=$(./volatility_2.5_linux_x64 -f /home/kali/Desktop/memdump.mem imageinfo | grep Suggested | awk '{print $4}' | awk -F ',' '{print $1}')



if [ -z "$memory_profile" ]; then
    echo "Could not find a memory profile for the file."
    exit 1
else
    echo "The memory profile for the file is: $memory_profile"
fi

# 2.3 Display the running processes:
echo "Displaying running processes..."
/home/kali/Desktop/vol2.5/volatility_2.5_linux_x64 -f "$file" --profile="$memory_profile" pslist

# 2.4 Display network connections:
echo "Displaying network connections..."
/home/kali/Desktop/vol2.5/volatility_2.5_linux_x64 -f "$file" --profile="$memory_profile" connscan

# 2.5 Attempt to extract registry information:
echo "[+] Attempting to extract hive list:"

/home/kali/Desktop/vol2.5/volatility_2.5_linux_x64 -f "$file" --profile="$memory_profile" hivelist | tee "$HOME/forensics_case/volatility/hives.txt"

if [ "$?" != "0" ]; then
    echo "Couldn't extract hive list.."
    exit 1
else
    echo "[+] Attempting to extract usernames from the SAM file:"
    /home/kali/Desktop/vol2.5/volatility_2.5_linux_x64 -f "$file" --profile="$memory_profile" printkey -K "SAM\Domains\Account\Users\Names" | tee "$HOME/forensics_case/volatility/SAM_usernames.txt"

    echo "[+] Attempting to find executable names from the SYSTEM file:"
    /home/kali/Desktop/vol2.5/volatility_2.5_linux_x64 -f "$file" --profile="$memory_profile" printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"
fi



# 3. Results

# 3.1 Display general statistics:
echo "Finishing..."
echo "Start time: $START"
echo "End time: $(date)"
echo "[+] Listing contents of the directories created:"
ls -l $HOME/forensics_case > /dev/null 2>&1

# 3.2 Save all the results into a report:
echo "[+] Saving the report..."

# Create a report file
REPORT_FILE="$HOME/forensics_case/forensics_report.txt"

echo "Start time: $START" > "$REPORT_FILE"
echo "End time: $(date)" >> "$REPORT_FILE"
echo "Files extracted:" >> "$REPORT_FILE"
ls -l $HOME/forensics_case >> "$REPORT_FILE" 2>/dev/null

# 3.3 Zip the extracted files and the report file:
echo "[+] Zipping the files and report..."

ZIP_FILE="$HOME/forensics_case/forensics_case.zip"

# Create the zip file
zip -r "$ZIP_FILE" "$HOME/forensics_case" > /dev/null 2>&1

echo "[+] All files and the report have been zipped into $ZIP_FILE"

