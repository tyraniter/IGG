# coding=utf-8

import os
import progressbar
import sys

round = 1

if len(sys.argv) >= 2:
    round = int(sys.argv[1])

malware_log_base = 'malware'
cuckoo_log_parse_dir = 'ioc_%s' % round
cuckoo_log_parse_dir_regexp = 'ioc_regexp_%s' % round
template_dir = 'template'

uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
lowercase = 'abcdefghijklmnopqrstuvwxyz'
digits = '0123456789'
logs = {}
iocs = []
parsed_iocs = {}


def predict(iocs):
    label = [-(x + 1) for x in range(len(iocs))]
    tmp_iocs = {}
    for i, ioc in enumerate(iocs):
        tmp_iocs[ioc] = i
    class_index = 0
    max_length = len(iocs[0].split('\\'))
    if max_length == 1:
        return [0 for x in range(len(iocs))]
    for i in range(max_length, 1, -1):
        tmp_result = {}
        for tmp_ioc in tmp_iocs.keys():
            tmp = tmp_ioc.split('\\')
            path_prefix = tmp[:i - 1]
            value = tmp[i - 1]
            path_suffix = tmp[i:]
            template = '\\'.join(path_prefix + ['%s'] + path_suffix)
            if tmp_result.get(template) is None:
                tmp_result[template] = []
            tmp_result[template].append(tmp_ioc)
        for template in tmp_result.keys():
            if len(tmp_result[template]) > 1:
                for i in tmp_result[template]:
                    label[tmp_iocs[i]] = class_index
                    del tmp_iocs[i]
                class_index += 1
    return label


def check_alphabet(pattern):
    if_upper = False
    if_lower = False
    if_digit = False
    if_other = False
    for ioc in pattern:
        for letter in ioc:
            if letter in uppercase:
                if_upper = True
            elif letter in lowercase:
                if_lower = True
            elif letter in digits:
                if_digit = True
            else:
                if_other = True
    return '.' if if_other else (
            '[' + ('A-Z' if if_upper else '') + ('a-z' if if_lower else '') + ('0-9' if if_digit else '') + ']')


def check_length(pattern):
    tmp = []
    for i in pattern:
        tmp.append(len(i))
    tmp = list(set(tmp))
    if len(list(set(tmp))) == 1:
        return '{%s}' % tmp[0]
    else:
        tmp.sort()
        if tmp[-1] - tmp[0] + 1 == len(tmp):
            return '{%s,%s}' % (tmp[0], tmp[-1])
        else:
            return '*'


def check_range(nums):
    nums.sort()


def check_prefix(pattern):
    prefix = ''
    for each in zip(*pattern):
        if len(set(each)) == 1:
            prefix += each[0]
        else:
            return prefix, [x[len(prefix):] for x in pattern]
    return prefix, [x[len(prefix):] for x in pattern]


def check_suffix(pattern):
    reverse_pattern = [x[::-1] for x in pattern]
    suffix = ''
    for each in zip(*reverse_pattern):
        if len(set(each)) == 1:
            suffix += each[0]
        else:
            return suffix[::-1], [x[len(suffix):][::-1] for x in reverse_pattern]
    return suffix[::-1], [x[len(suffix):][::-1] for x in reverse_pattern]


def generate_pattern(pattern):
    pattern = list(set(pattern))
    if len(pattern) == 1:
        return [pattern[0], pattern[0]]
    else:
        prefix, new_pattern = check_prefix(pattern)
        suffix, new_pattern = check_suffix(new_pattern)
        pattern_length = check_length(new_pattern)
        pattern_content = check_alphabet(new_pattern)
    # return ['%s%s%s%s' % (prefix, pattern_content, pattern_length, suffix),
    #         '%s(%s)%s' % (prefix, '|'.join(new_pattern), suffix)]
    return ['%s%s%s%s' % (prefix, pattern_content, pattern_length, suffix)]


'''
固定长度 随机小写 [a-z]{len}
固定长度 随机大写 [A-Z]{len}
固定长度 随机数字 [0-9]{len}
固定长度 随机大小写 [A-Za-z]{len}
固定长度 随机小写数字 [a-z0-9]{len}
固定长度 随机大写数字 [A-Z0-9]{len}
固定长度 随机大小写数字 [A-Za-z0-9]{len}
固定长度 随机字符 .{len}

随机长度 随机小写
随机长度 随机大写
随机长度 随机数字
随机长度 随机大小写
随机长度 随机小写数字
随机长度 随机大写数字
随机长度 随机大小写数字
随机长度 随机字符.*
'''


def generate_patterns(value_list, value_label):
    result = {}
    tmp_list = {}
    for index, label in enumerate(value_label):
        if tmp_list.get(label) is None:
            tmp_list[label] = []
        tmp_list[label].append(value_list[index])
    for label in tmp_list.keys():
        tmp = tmp_list[label]
        patterns = generate_pattern(tmp)
        if len(patterns) == 1:
            patterns[0] = "***" + patterns[0]
        result[label] = patterns
    return result


def generate_template():
    if not os.path.exists(malware_log_base + '/' + template_dir):
        os.makedirs(malware_log_base + '/' + template_dir)
    p = progressbar.ProgressBar()
    for family in p(os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir)):
        f = open(malware_log_base + '/' + template_dir + '/' + family, 'w')
        for log in os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family):
            ff = open(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family + '/' + log)
            f.write(ff.read())
            ff.close()
        f.close()


def handle_template(family):
    iocs = []
    iocs_index = {}
    ioc_type_list = {}

    f = open(malware_log_base + '/' + template_dir + '/' + family)
    tmp = f.readlines()
    f.close()

    for ioc in tmp:
        if ioc.strip() != '':
            iocs.append(ioc.strip())
    iocs = list(set(iocs))

    for ioc in iocs:
        ioc_type = ioc.split('##')[0]
        ioc_value = ioc.split('##')[1:]
        if ioc_type_list.get(ioc_type) is None:
            ioc_type_list[ioc_type] = {}

        iocs_index[ioc] = []
        iocs_index[ioc].append(ioc_type)

        length_pattern = '|'.join([str(len(x.split('\\'))) + ',' + os.path.splitext(x)[1] for x in ioc_value])
        iocs_index[ioc].append(length_pattern)
        if ioc_type_list[ioc_type].get(length_pattern) is None:
            ioc_type_list[ioc_type][length_pattern] = {}
        for index, value in enumerate(ioc_value):
            if ioc_type_list[ioc_type][length_pattern].get(index) is None:
                ioc_type_list[ioc_type][length_pattern][index] = []
            ioc_type_list[ioc_type][length_pattern][index].append(value)
    for ioc_type in ioc_type_list.keys():
        tmp_value_dict = ioc_type_list[ioc_type]
        for length_pattern in tmp_value_dict.keys():
            tmp_value_length_list = tmp_value_dict[length_pattern]
            for value_index in tmp_value_length_list.keys():
                tmp_value_list = list(set(tmp_value_length_list[value_index]))
                value_label = predict(tmp_value_list)
                value_pattern = generate_patterns(tmp_value_list, value_label)
                ioc_type_list[ioc_type][length_pattern][value_index] = {'label': list(value_label),
                                                                        'pattern': value_pattern,
                                                                        'value_list': tmp_value_list}
    return iocs_index, ioc_type_list


def regenerate_log(family,if_preserve_old):
    iocs_index, ioc_type_list = handle_template(family)
    if not os.path.exists(malware_log_base + '/' + cuckoo_log_parse_dir_regexp + '/' + family):
        os.makedirs(malware_log_base + '/' + cuckoo_log_parse_dir_regexp + '/' + family)
    p = progressbar.ProgressBar()
    for md5 in p(os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family)):
        f = open(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family + '/' + md5)
        iocs = f.readlines()
        f.close()

        f = open(malware_log_base + '/' + cuckoo_log_parse_dir_regexp + '/' + family + '/' + md5, 'w')
        tmp = []
        for ioc in iocs:
            tmp_ioc = iocs_index[ioc.strip()]
            ioc_type = tmp_ioc[0]
            length_pattern = tmp_ioc[1]
            ioc_regexp = [ioc_type, ioc_type]
            ioc_value = ioc.strip().split('##')[1:]
            if_reg = 0
            for index, value in enumerate(ioc_value):
                label_index = ioc_type_list[ioc_type][length_pattern][index]['value_list'].index(value)
                pattern_index = ioc_type_list[ioc_type][length_pattern][index]['label'][label_index]
                pattern_list = ioc_type_list[ioc_type][length_pattern][index]['pattern'][pattern_index]
                if pattern_list[0].startswith("***"):
                    if_reg = 1
                ioc_regexp[0] = ioc_regexp[0] + '##' + pattern_list[0].lstrip("***")
            tmp.append(str(if_reg) + "##" + ioc_regexp[0] + '\n')
            # 原始ioc
            if if_preserve_old:
                tmp.append("0##"+ioc)
        for i in list(set(tmp)):
            f.write(i)
        f.close()


def regenerate_log_all(if_preserve_old):
    for family in os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir):
        try:
            regenerate_log(family, if_preserve_old)
        except:
            print(sys.exc_info(), family)


if __name__ == '__main__':
    generate_template()
    regenerate_log_all(False)
