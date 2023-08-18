# coding=utf-8
import math

import shutil
import numpy
from pyids.algorithms.rule_comparator import IDSComparator
from sklearn.datasets import load_files
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
import numpy as np
import pandas as pd
from pyids.algorithms.ids_classifier import mine_CARs
from pyids.data_structures.ids_rule import IDSRule
from pyids.algorithms.ids import IDS
from pyarc.qcba.data_structures import QuantitativeDataFrame
import time
import os
import sys

log_dir = "./malware/ioc_regexp_1"

if len(sys.argv) >= 2:
    log_dir = "./malware/ioc_regexp_%s" % sys.argv[1]

test_dir = ""


def get_classes(min_count):
    result = []
    for family in os.listdir(log_dir):
        count = 0
        for files in os.listdir(log_dir + '/' + family):
            count += 1
        if count >= min_count:
            result.append(family)
    return result


def tokenize(text):
    tmp = text.strip()
    if tmp == '':
        return []
    return tmp.split('\n')


def print_log(log):
    print("%s:%s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), log))


def predict(rules, quant_dataframe, default_class=-1):
    sorted_rules = IDSComparator().sort(rules, order_type="f1")
    predicted_classes = []
    for _, row in quant_dataframe.dataframe.iterrows():
        appended = False
        for rule in sorted_rules:
            antecedent_dict = dict(rule.car.antecedent)
            counter = True
            for name, value in row.iteritems():
                if name in antecedent_dict:
                    rule_value = antecedent_dict[name]
                    counter &= rule_value == str(value)
            if counter:
                _, predicted_class = rule.car.consequent
                predicted_classes.append(int(float(predicted_class)))
                appended = True
                break
        if not appended:
            predicted_classes.append(default_class)
    return numpy.array(predicted_classes)


def simplify_ids_rules(ids_rules):
    result = []
    tmp = []
    minlen = 999
    for rule in ids_rules:
        if rule.car.support == 1.0:
            tmp.append(rule)
            if rule.car.rulelen < minlen:
                minlen = rule.car.rulelen
    for _rule in tmp:
        if _rule.car.rulelen == minlen:
            result.append(_rule)
            break
    if len(result) == 0:
        result = ids_rules
    return result


categories = get_classes(0)
print_log("load dataset")
dataset = load_files(log_dir, categories=categories, shuffle=True, encoding='utf-8',
                     decode_error='ignore',
                     random_state=42)

print_log("convert dataset to vector")
count_vect = CountVectorizer(tokenizer=tokenize, lowercase=False)
X_counts = count_vect.fit_transform(dataset.data)
data_array = X_counts.toarray()
features = {int(v): k for k, v in count_vect.vocabulary_.items()}

print_log("split dataset")
indices = np.arange(len(data_array))
train_data_array, test_data_array, y_train, y_test, idx_train, idx_test = train_test_split(data_array, dataset.target,
                                                                                           indices, test_size=0.20,
                                                                                           random_state=None,
                                                                                           stratify=dataset.target)

print_log("convert vector to array")
train_data_array_with_class = np.zeros((len(train_data_array), len(train_data_array[0]) + 1))
train_data_array_with_class[:, :-1] = train_data_array

# 添加类标签
for i in range(len(train_data_array_with_class)):
    train_data_array_with_class[i][-1] = y_train[i]

exclude_overlay = True
if exclude_overlay:
    print_log("handle overlay")
    family_feature_sum = {}
    # 计算重叠特征
    for i in range(len(dataset.target_names)):
        tmp = train_data_array_with_class[np.where(train_data_array_with_class[:, -1] == i)]
        _sum = np.sum(tmp, axis=0)
        family_feature_sum[i] = _sum[:-1]

    overlay_feature = {}
    for i in family_feature_sum.keys():
        tmp = family_feature_sum[i]
        for j in range(len(tmp)):
            if tmp[j] > 0:
                if overlay_feature.get(j) is None:
                    overlay_feature[j] = []
                overlay_feature.get(j).append(dataset.target_names[i])

    overlay_feature_index = []
    for key in overlay_feature.keys():
        tmp = overlay_feature[key]
        if len(tmp) > 1:
            overlay_feature_index.append(key)

    print_log("overlay indexes:%s" % len(overlay_feature_index))

    # 备份列
    for i in overlay_feature_index:
        bak = train_data_array_with_class[:, i]
        # print(train_data_array_with_class[:,i].sum())
        train_data_array_with_class[:, i] = train_data_array_with_class[:, i] * 0
        for j in range(len(train_data_array_with_class)):
            if train_data_array_with_class[j][:-1].sum() == 0:
                train_data_array_with_class[:, i] = bak
                break
        # print(train_data_array_with_class[:,i].sum())
        # print('###')

    # 检查是否有空特征样本
    empty_family = {}
    for i in range(len(train_data_array_with_class)):
        if train_data_array_with_class[i][:-1].sum() == 0:
            empty_family[i] = train_data_array_with_class
    print_log("empty classes:%s" % len(empty_family.keys()))
    print_log("empty classes:%s" % empty_family.keys())

print_log("handle ids")
rules = []
lambda_array = [1, 1, 1, 0, 0, 1, 1]
df_columns = [str(x) for x in range(train_data_array.shape[1])] + ['class']
for i in range(len(dataset.target_names)):
    tmp_array = train_data_array_with_class[np.where(train_data_array_with_class[:, -1] == i)]
    print_log(dataset.target_names[i] + " start, " + str(len(tmp_array)) + " samples")
    # set reg ioc to 2
    for j in features.keys():
        if features[j].startswith("1"):
            for row in range(tmp_array.shape[0]):
                if tmp_array[row][j] == 1:
                    tmp_array[row][j] = 2
    # insert a fake array
    tmp_array = np.insert(tmp_array, 0, np.zeros((1, tmp_array.shape[1])), 0)
    tmp_array[0][-1] = -1
    df = pd.DataFrame(tmp_array, columns=df_columns)
    quant_dataframe = QuantitativeDataFrame(df)
    cars, if_all = mine_CARs(df, rule_cutoff=50, if_optimize=True)
    best_car = None
    for car in cars:
        if int(car.support) == 1 and int(car.confidence) == 1:
            if best_car is None:
                best_car = car
            rf = [features[int(x)] for x in car.antecedent.itemset.keys()]
            rf_sum = [int(x[0]) for x in rf]
            if rf_sum == 0:
                best_car = car
                break
    if best_car is not None:
        rules.append(IDSRule(best_car))
        print_log(dataset.target_names[i] + " finish, use %s rule from original %s rules, " % (
            1, len(cars)))
        continue
    while True:
        ids = IDS(algorithm="SLS")
        ids.fit(quant_dataframe=quant_dataframe, class_association_rules=cars, lambda_array=lambda_array)

        if len(ids.clf.rules) == 0:
            pass
        else:
            true_rules = simplify_ids_rules(ids.clf.rules)
            rules += true_rules
            print_log(dataset.target_names[i] + " finish, use %s rules from original %s rules, " % (
                len(true_rules), len(ids.clf.rules)))
            break


rule_dir = './decision_set/'
if os.path.exists(rule_dir):
    shutil.rmtree(rule_dir)
for i in rules:
    _class = int(float(i.car.consequent.value))
    _rules = i.car.antecedent.itemset.keys()
    _class_name = dataset.target_names[_class]
    _rule_content = [features[int(x)] for x in _rules]
    _rid = i.car.rid
    if not os.path.exists(rule_dir+ _class_name):
        os.makedirs(rule_dir + _class_name)
    _f = open(rule_dir + _class_name + '/%s.txt' % _rid, 'w')
    for _r in _rule_content:
        _f.write(_r + '\n')
    _f.close()
