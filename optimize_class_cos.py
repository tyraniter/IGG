# coding=utf-8
import os
import shutil
import progressbar
import math
import sys

round = 1


if len(sys.argv) >= 2:
    round = int(sys.argv[1])

malware_log_base = 'malware'
cuckoo_log_parse_dir = 'ioc_regexp_%s' % round
cuckoo_log_parse_dir_o = 'ioc_%s' % round
cuckoo_log_parse_dir_bm25 = 'ioc_%s' % (round + 1)
template_dir = 'template'
class_dir = './'
change = []
all_families = []

template_length = {}


# v1 template v2 sample
def weight_cosine_similarity(family, vector1, vector2, weight_dict):
    template_pow = template_length.get(family,0)
    if template_pow == 0:
        for weight in weight_dict:
            template_pow += pow(weight, 2)
        template_length[family]=template_pow
    numerator = 0
    for v in vector2:
        if v in vector1:
            numerator += weight_dict[vector1.index(v)]
    return numerator / (math.sqrt(len(vector2)) * math.sqrt(template_pow))


def calculate_weight(vector):
    tmp = {}
    c = len(vector)
    for v in vector:
        if tmp.get(v) is not None:
            tmp[v] = tmp[v] + 1
        else:
            tmp[v] = 1
    for v in tmp.keys():
        tmp[v] = tmp[v] / c
    _vector = list(tmp.keys())
    weight = [tmp[x] for x in _vector]
    return _vector, weight


def get_top_family(vector, family, vectors, weights, classes):
    result_family = family
    cs = 0
    # for _family in vectors.keys():
    for _family in classes:
        if vectors.get(_family) is not None:
            _vector = vectors[_family]
            weight = weights[_family]
            similarity = weight_cosine_similarity(_family, _vector, vector, weight)
            if similarity > cs:
                cs = similarity
                result_family = _family
    return result_family


def generate_template():
    vectors = {}
    weights = {}
    if not os.path.exists(malware_log_base + '/' + template_dir):
        os.makedirs(malware_log_base + '/' + template_dir)
    p = progressbar.ProgressBar()
    for family in p(os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir)):
        tmp = []
        f = open(malware_log_base + '/' + template_dir + '/' + family, 'w')
        for log in os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family):
            ff = open(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family + '/' + log)
            content = ff.read()
            f.write(content)
            tmp += content.strip().split('\n')
            ff.close()
        vector, weight = calculate_weight(tmp)
        f.close()
        vectors[family] = vector
        weights[family] = weight
    return vectors, weights


def handle_log(md5, family, vectors, weights, classes):
    f = open(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family + '/' + md5)
    query = f.read().strip().split('\n')
    f.close()
    if len(classes) > 1:
        true_family = get_top_family(query, family, vectors, weights, classes)
    else:
        true_family = classes[0]
    if not os.path.exists(malware_log_base + '/' + cuckoo_log_parse_dir_bm25 + '/' + true_family):
        os.makedirs(malware_log_base + '/' + cuckoo_log_parse_dir_bm25 + '/' + true_family)
    shutil.copy(malware_log_base + '/' + cuckoo_log_parse_dir_o + '/' + family + '/' + md5,
                malware_log_base + '/' + cuckoo_log_parse_dir_bm25 + '/' + true_family + '/' + md5)
    global change
    if true_family != family:
        change.append('%s,%s,%s' % (md5, family, true_family))


if __name__ == '__main__':
    vectors, weights = generate_template()
    md5s = {}
    f = open(class_dir + '/' + 'class.verbose.csv')

    classes = []
    for family in os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir):
        classes.append(family)

    for line in f.readlines():
        md5 = line.strip().split(',')[0]
        classes = line.strip().split(',')[1:]
        md5s[md5] = classes
    for family in os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir):
        p = progressbar.ProgressBar()
        for md5 in p(os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family)):
            if md5s.get(md5) is not None:
                handle_log(md5, family, vectors, weights, md5s[md5])
            else:
                handle_log(md5, family, vectors, weights, [family])
    f = open('cos_%s.log' % round, 'w')
    for i in change:
        f.write(i + '\n')
    f.close()
