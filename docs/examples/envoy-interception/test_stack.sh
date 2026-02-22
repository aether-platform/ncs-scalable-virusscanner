#!/bin/bash

# Test Priority File
echo "--- Testing Priority File (Clean) ---"
curl -X POST -H "x-priority: high" -d "This is a priority file." http://localhost:8080/upload -i
echo -e "\n"

# Test Normal File
echo "--- Testing Normal File (Clean) ---"
curl -X POST -d "This is a normal file." http://localhost:8080/upload -i
echo -e "\n"

# Test EICAR (Infected) File
echo "--- Testing EICAR (Infected) File ---"
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
curl -X POST --data-binary @eicar.txt http://localhost:8080/upload -i
echo -e "\n"

# Clean up
rm eicar.txt
