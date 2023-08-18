#!/bin/bash

pip3 install numpy scikit-learn progressbar pandas pyfim

echo "extract feature"
python3 extract_feature.py

round=0
cosfile="cos_"
while true
do
    echo "round $round"
    echo "group and generate regexp"
    python3 generate_regexp.py $round
    echo "optimize label"
    python3 optimize_class_cos.py $round
    if [ ! -s $cosfile$round".log" ]
    then
        echo "optimize over"
        break
    fi
    round=`expr $round + 1`
done
rm -rf decision_set/*
echo "generate decision set"
python3 generate_decision_set.py $round
echo "generate elastic rule"
python3 generate_elastic_rule.py
