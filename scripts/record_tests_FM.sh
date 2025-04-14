#!/bin/bash
# Usage: ./main -numItem <int> -lenData <int> -numPack <int> -numAgg <int> -alpha <int> -interType <string> -allowIntersection <0 or 1>
mkdir test_FM

testNum=0
#Intersection 1

allowIntersection=1
echo $testNum

#CI is in common for these
interType=CI

for n in {20..24}; do
    ((testNum++))
    numItem=$n
    lenData=4
    numPack=8
    numAgg=1  
    alpha=3
    #interType=CI
    #allowIntersection=1

    echo numItem=$numItem, lenData=$lenData, numPack=$numPack, numAgg=$numAgg, alpha=$alpha, interType=$interType, allowIntersection=$allowIntersection >> ./test_FM/test"$testNum".txt

    for n in {1..5}; do
        ./main -numItem $numItem -lenData $lenData -numPack $numPack -numAgg $numAgg -alpha $alpha -interType $interType -allowIntersection $allowIntersection | grep -E "Time Elapsed|Inter Result" | awk -F': ' 'NR % 2 == 1 {time = $2} NR % 2 == 0 {print time "," $2}' >> ./test_FM/test"$testNum".txt
    done
    
done

echo COMPLETED
