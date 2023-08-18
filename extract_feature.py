# coding=utf-8
from datetime import datetime
import os
import json
import progressbar

class_file = 'class.csv'
# malware文件夹
malware_log_base = 'malware'
# 白软件文件夹
benign_log_base = 'benign'
# cuckoo原始日志
cuckoo_log_dir = 'cuckoo'
# vt 用于获取sha256
report_log_dir = 'report'
# 解析结果
cuckoo_log_parse_dir = 'ioc_0'

# 下列行为从原始日志提取
api_list = {
    # ('process','ShellExecuteExW'),
    ('filesystem', 'CopyFileExW'): 'files_copied',
    ('filesystem', 'DeleteFileW'): 'files_deleted',
    ('filesystem', 'CreateFileW'): '',
    ('filesystem', 'WriteFile'): 'files_written',
    ('filesystem', 'WriteFileEx'): 'files_written',
    # ('modules_loaded','LoadLibraryA'),
    # ('modules_loaded','LoadLibraryW'),
    # ('synchronization','CreateMutexW'),
    # ('synchronization','OpenMutexW'),
    ('process', 'CreateProcessInternalW'): 'processes_created',
    # ('process','CreateRemoteThread'),
    ('process', 'TerminateProcess'): 'processes_terminated',
    ('registry', 'RegOpenKeyExW'): '',
    ('registry', 'RegOpenKeyExA'): '',
    ('registry', 'RegCreateKeyExW'): 'registry_keys_create',
    ('registry', 'RegSetValueExA'): 'registry_set_value',
    ('registry', 'RegSetValueExW'): 'registry_set_value',
    ('registry', 'RegDeleteKeyA'): 'registry_delete_key',
    ('registry', 'RegDeleteKeyW'): 'registry_delete_key',
    # ('services','OpenServiceW'),
    # ('hooking','SetWindowsHookExW'),
    # ('hooking','SetWindowsHookExA'),
}

whitelist = {'processes_created': ['C:\WINDOWS\system32\drwtsn32']}


def filter(ioc):
    try:
        ioc = ioc.strip()
        ioc = ioc.replace('c:\\', 'C:\\')
        ioc = ioc.replace('C:\\<FILE>', '<FILE>')
        ioc = ioc.replace('janettedoe', '<USER>')
        ioc = ioc.replace('DOCUME~1\\<USER>~1\\LOCALS~1', 'Documents and Settings\\<USER>\\Local Settings')
        ioc = ioc.replace('DOCUME~1\\JANETT~1\\LOCALS~1', 'Documents and Settings\\<USER>\\Local Settings')
        ioc = ioc.replace('docume~1\\janett~1\\locals~1', 'Documents and Settings\\<USER>\\Local Settings')
        ioc = ioc.replace('C:\\PROGRA~1\\COMMON~1\\MICROS~1', 'C:\\Program Files\\Common Files\\microsoft shared')
        return ioc
    except:
        print(ioc)


def parse_api(behavior, whitelist=[]):
    process_handler = {}
    file_write_handler = {}
    reg_set_handler = {}
    ioc = []
    for i in behavior['processes']:
        parent_process = i['process_name']
        for j in i['calls']:
            if (j['category'], j['api']) in api_list.keys() and j['status'] == 'SUCCESS':
                # file
                # create
                if (j['category'], j['api']) == ('filesystem', 'CreateFileW'):
                    tmp_file_name = ''
                    tmp_file_mode = ''
                    for k in j['arguments']:
                        if k['name'] == 'lpFileName':
                            tmp_file_name = k['value']
                        if k['name'] == 'dwDesiredAccess':
                            tmp_file_mode = k['value']
                    if 'GENERIC_WRITE' in tmp_file_mode:
                        file_write_handler[j['return']] = tmp_file_name
                # copy
                elif (j['category'], j['api']) == ('filesystem', 'CopyFileExW'):
                    arg = ''
                    arg2 = ''
                    for k in j['arguments']:
                        if k['name'] == 'lpNewFileName':
                            arg2 = k['value']
                        if k['name'] == 'lpExistingFileName':
                            arg = k['value']
                    ioc.append('%s##%s##%s\n' % (api_list[(j['category'], j['api'])], filter(arg), filter(arg2)))
                # write
                elif (j['category'], j['api']) in [('filesystem', 'WriteFile'), ('filesystem', 'WriteFileEx')]:
                    arg = ''
                    tmp_file_handler = ''
                    for k in j['arguments']:
                        if k['name'] == 'hFile':
                            tmp_file_handler = k['value']
                            break
                    if tmp_file_handler in file_write_handler.keys():
                        ioc.append('%s##%s\n' % (
                            api_list[(j['category'], j['api'])], filter(file_write_handler[tmp_file_handler])))
                # delete
                elif (j['category'], j['api']) == ('filesystem', 'DeleteFileW'):
                    arg = ''
                    for k in j['arguments']:
                        if k['name'] == 'lpFileName':
                            arg = k['value']
                            break
                    ioc.append('%s##%s\n' % (api_list[(j['category'], j['api'])], filter(arg)))
                # process
                # create
                elif (j['category'], j['api']) == ('process', 'CreateProcessInternalW'):
                    arg = ''
                    app = ''
                    for k in j['arguments']:
                        if k['name'] == 'lpApplicationName':
                            app = k['value']
                        if k['name'] == 'lpCommandLine':
                            arg = k['value']
                    # app,arg = handle_process(app,arg)
                    process_handler[j["return"]] = app
                    ioc.append('%s##%s##%s##%s\n' % (
                        api_list[(j['category'], j['api'])], parent_process, filter(app), filter(arg)))
                # terminal
                elif (j['category'], j['api']) == ('process', 'TerminateProcess'):
                    for k in j['arguments']:
                        if k['name'] == 'szExeFile':
                            arg = k['value']
                    ioc.append('%s##%s\n' % (api_list[(j['category'], j['api'])], filter(arg)))
                # registry
                # open/create
                elif (j['category'], j['api']) in (
                        ('registry', 'RegOpenKeyExW'), ('registry', 'RegOpenKeyExA'), ('registry', 'RegCreateKeyExW')):
                    lpSubKey = ''
                    hKey = ''
                    for k in j['arguments']:
                        if k['name'] == 'lpSubKey':
                            lpSubKey = k['value']
                        if k['name'] == 'hKey':
                            hKey = k['value']
                    if hKey.startswith('0x'):
                        hKey = reg_set_handler.get(hKey, hKey)
                    reg_set_handler[j['return']] = hKey + '\\' + lpSubKey
                # set
                elif (j['category'], j['api']) in [('registry', 'RegSetValueExA'), ('registry', 'RegSetValueExW')]:
                    arg = ''
                    tmp_reg_handler = ''
                    for k in j['arguments']:
                        if k['name'] == 'hKey':
                            tmp_reg_handler = k['value']
                        if k['name'] == 'lpValueName':
                            tmp_reg_key = k['value']
                        if k['name'] == 'lpData':
                            tmp_reg_value = k['value']
                    if tmp_reg_handler in reg_set_handler.keys():
                        ioc.append('%s##%s##%s##%s\n' % (
                            api_list[(j['category'], j['api'])], reg_set_handler[tmp_reg_handler],
                            filter(tmp_reg_key),
                            filter(tmp_reg_value)))
                # delete
                elif (j['category'], j['api']) in [('registry', 'RegDeleteKeyA'), ('registry', 'RegDeleteKeyW')]:
                    arg = ''
                    tmp_reg_handler = ''
                    for k in j['arguments']:
                        if k['name'] == 'hKey':
                            tmp_reg_handler = k['value']
                        if k['name'] == 'lpSubKey':
                            tmp_reg_key = k['value']
                    if tmp_reg_handler in reg_set_handler.keys():
                        ioc.append('%s##%s##%s\n' % (
                            api_list[(j['category'], j['api'])], reg_set_handler[tmp_reg_handler], tmp_reg_key,))
                else:
                    ioc.append('%s##%s\n' % (api_list[(j['category'], j['api'])], j['arguments']))
    ioc = [x for x in list(set(ioc)) if x not in whitelist]
    return ioc


def print_log(message):
    print('%s------%s' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), message))


# 解析合法软件日志 建立白名单
def parse_benign():
    print_log('Begin parse benign log')
    if not os.path.exists(benign_log_base + '/' + cuckoo_log_parse_dir):
        os.makedirs(benign_log_base + '/' + cuckoo_log_parse_dir)

    p = progressbar.ProgressBar()

    for md5 in p(os.listdir(benign_log_base + '/' + cuckoo_log_dir)):
        try:
            # read report and get sha256
            report = open(benign_log_base + '/' + report_log_dir + '/' + md5)
            report_content = json.loads(report.read())
            report.close()
            sha256 = report_content['sha256']

            # open cuckoo log
            log = open(benign_log_base + '/' + cuckoo_log_dir + '/' + md5)
            content = log.read()
            log.close()

            # parse cuckoo to json
            content = content.replace(sha256, '<FILE>')
            json_content = json.loads(content)

            # parse ioc
            ioc = parse_api(json_content['behavior'])

            if len(ioc) > 0:
                f = open(benign_log_base + '/' + cuckoo_log_parse_dir + '/' + md5, 'w')
                for i in ioc:
                    f.write(i)
                f.close()
        except:
            #print(md5, sys.exc_info())
            pass

    print_log('Parse benign log succesfully')

    # load parsed ioc
    print_log('Begin load benign ioc')
    whitelist = []

    p = progressbar.ProgressBar()
    for md5 in p(os.listdir(benign_log_base + '/' + cuckoo_log_parse_dir)):
        ioc_report = open(benign_log_base + '/' + cuckoo_log_parse_dir + '/' + md5)
        ioc_content = ioc_report.readlines()
        ioc_report.close()
        for ioc in ioc_content:
            if ioc not in whitelist:
                whitelist.append(ioc)
    print_log('Loading %s benign ioc succesfully' % len(whitelist))

    f = open('whitelist.txt', 'w')
    for i in whitelist:
        f.write(i)
    f.close()
    return whitelist


# 读取原始json日志 解析行为
def parse_malware(whitelist):
    print_log('Begin parse malware log')
    f = open(class_file)
    malware_list = f.readlines()
    f.close()

    p = progressbar.ProgressBar()
    for i in p(malware_list):
        try:
            md5 = i.strip().split(',')[0]
            family = i.strip().split(',')[1:]
            if family[0] == '' or family[0].startswith("SINGLETON"):
                continue
            for ff in [family[0]]:
                if not os.path.exists(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + ff):
                    os.makedirs(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + ff)
            # if md5 !='2b72c12b37232f78e1777f8ee3404953':
            # continue
            # print family
            # read report and get sha256
            report = open(malware_log_base + '/' + report_log_dir + '/' + md5)
            report_content = json.loads(report.read())
            report.close()
            sha256 = report_content['sha256']

            # open cuckoo log
            log = open(malware_log_base + '/' + cuckoo_log_dir + '/' + md5)
            content = log.read()
            log.close()

            # parse cuckoo to json
            content = content.replace(sha256, '<FILE>')
            json_content = json.loads(content)

            # parse ioc

            ioc = parse_api(json_content['behavior'], whitelist=whitelist)
            if len(ioc) > 0:
                for ff in [family[0]]:
                    f = open(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + ff + '/' + md5, 'w')
                    for i in ioc:
                        f.write(i)
                    f.close()

            if len(ioc) > 0:
                for ff in [family[0]]:
                    f = open(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + ff + '/' + md5, 'w')
                    for i in ioc:
                        f.write(i)
                    f.close()
        except:
            #print(md5, sys.exc_info())
            pass
    print_log('Parse malware log succesfully')


def clean_empty():
    for family in os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir):
        if not os.listdir(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family):
            os.rmdir(malware_log_base + '/' + cuckoo_log_parse_dir + '/' + family)


def main():
    whitelist = parse_benign()
    parse_malware(whitelist)
    clean_empty()


if __name__ == '__main__':
    main()
