#!/bin/bash
# Usage: ./main -numItem <int> -lenData <int> -numPack <int> -numAgg <int> -alpha <int> -interType <string> -allowIntersection <0 or 1>
mkdir test_APSI

testNum=0

#Intersection 1
#CI is in common for these

isEncrypted=1

echo $testNum

for numParties in 16 32 64 128 256 512 1024; do
    ((testNum++))
    # numParties=$n
    outputFile="./test_APSI/test${testNum}.csv"
    
    # CSV header
    echo "Run,Inter Time,Aggregation Time,Query Size,Response Size,Aggregated Size" > "$outputFile"
    echo "numParties=$numParties" >> "$outputFile"

    for n in {1..10}; do
        output=$(./main_apsi -numParties $numParties -isEncrypted $isEncrypted)
        interTime=$(echo "$output" | grep "Inter Time" | awk -F': ' '{print $2}')
        aggTime=$(echo "$output" | grep "Aggregation Time" | awk -F': ' '{print $2}')
        
        querySize=$(echo "$output" | grep "Query Size" | awk -F': ' '{print $2}' | tr -d 'MB')
        responseSize=$(echo "$output" | grep "Response Size" | awk -F': ' '{print $2}' | tr -d 'MB')
        aggSize=$(echo "$output" | grep "Aggregated Size" | awk -F': ' '{print $2}' | tr -d 'MB')
        echo "$run,$interTime,$aggTime,$querySize,$responseSize,$aggSize" >> "$outputFile"
    done
    
done

echo COMPLETED
