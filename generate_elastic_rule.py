# coding=utf-8

import uuid
import json
import os

rule_dir = "decision_set"

eql_rule_template = {
    "id": "",
    "updated_at": "2022-03-21T16:08:29.816Z",
    "updated_by": "elastic",
    "created_at": "2022-03-21T16:08:27.788Z",
    "created_by": "elastic",
    "name": "",
    "tags": [],
    "interval": "5m",
    "enabled": True,
    "description": "",
    "risk_score": 21,
    "severity": "low",
    "license": "",
    "output_index": ".siem-signals-default",
    "meta": {
        "from": "1m",
        "kibana_siem_app_url": "http://192.168.198.3:5601/app/security"
    },
    "author": [],
    "false_positives": [],
    "from": "now-360s",
    "rule_id": "",
    "max_signals": 100,
    "risk_score_mapping": [],
    "severity_mapping": [],
    "threat": [],
    "to": "now",
    "references": [],
    "version": 1,
    "exceptions_list": [],
    "immutable": False,
    "type": "eql",
    "language": "eql",
    "index": [
        "winlogbeat-*"
    ],
    "query": "",
    "filters": [],
    "throttle": "no_actions",
    "actions": []
}

kql_rule_template = {
    "id": "",
    "updated_at": "2022-03-21T16:08:29.816Z",
    "updated_by": "elastic",
    "created_at": "2022-03-21T16:08:27.788Z",
    "created_by": "elastic",
    "name": "",
    "tags": [],
    "interval": "5m",
    "enabled": True,
    "description": "",
    "risk_score": 21,
    "severity": "low",
    "license": "",
    "output_index": ".siem-signals-default",
    "meta": {
        "from": "1m",
        "kibana_siem_app_url": "http://192.168.198.3:5601/app/security"
    },
    "author": [],
    "false_positives": [],
    "from": "now-360s",
    "rule_id": "",
    "max_signals": 100,
    "risk_score_mapping": [],
    "severity_mapping": [],
    "threat": [],
    "to": "now",
    "references": [],
    "version": 1,
    "exceptions_list": [],
    "immutable": False,
    "type": "query",
    "language": "lucene",
    "index": [
        "winlogbeat-*"
    ],
    "query": "",
    "filters": [],
    "throttle": "no_actions",
    "actions": []
}

all_template = {
    "exported_count": 0,
    "exported_rules_count": 0,
    "missing_rules": [],
    "missing_rules_count": 0,
    "exported_exception_list_count": 0,
    "exported_exception_list_item_count": 0,
    "missing_exception_list_item_count": 0,
    "missing_exception_list_items": [],
    "missing_exception_lists": [],
    "missing_exception_lists_count": 0
}

eql_condition_template = '''[%s where %s and %s] by winlog.event_data.TopProcessGuid'''
kql_template = '''%s && %s'''

event_code_eql = {
    "files_written": '''event.code == "11"''',
    "files_copied": '''event.code == "11"''',
    "files_deleted": '''event.code == "23"''',
    "registry_create_value": '''event.code == "12" and registry.event_type=="CreateValue"''',
    "registry_set_value": '''event.code == "13"''',
    "registry_delete_key": '''event.code == "12" and registry.event_type=="DeleteValue"''',
    "processes_created": '''event.code == "1"''',
    "processes_terminated": '''event.code == "5"''',
}

event_code_kql = {
    "files_written": '''event.code:"11"''',
    "files_copied": '''event.code:"11"''',
    "files_deleted": '''event.code:"23"''',
    "registry_create_value": '''event.code:"12" && registry.event_type:"CreateValue"''',
    "registry_set_value": '''event.code:"13"''',
    "registry_delete_key": '''event.code:"12" && registry.event_type:"DeleteValue"''',
    "processes_created": '''event.code:"1"''',
    "processes_terminated": '''event.code:"5"''',
}

event_category = {
    "files_written": "file",
    "files_copied": "file",
    "files_deleted": "file",
    "registry_create_value": "registry",
    "registry_set_value": "registry",
    "registry_delete_key": "registry",
    "processes_created": "process",
    "processes_terminated": "process"
}


def getRule(name, query, template):
    rule = template
    rule["id"] = str(uuid.uuid1())
    rule["name"] = name
    rule["rule_id"] = str(uuid.uuid1())
    rule["description"] = name
    rule["query"] = query
    return json.dumps(rule)


def parseFile(file, family):
    f = open(file, "r")
    lines = f.readlines()
    f.close()
    if len(lines) == 1:
        return getKQL(lines[0]), True
    if len(lines) > 1:
        return getEQL(lines), False


def getEQL(lines):
    condition = []
    for line in lines:
        word = line.strip("\r\n").split("##")[1:]
        action = word[0]
        if action in ("files_written", "files_delete"):
            condition.append(eql_condition_template % (
            event_category[action], event_code_eql[action], '''file.path=="%s"''' % word[1].replace("\\", "\\\\")))
        if action in ("files_copied"):
            condition.append(eql_condition_template % (
            event_category[action], event_code_eql[action], '''file.path=="%s"''' % word[2].replace("\\", "\\\\")))
        if action in ("registry_create_value", "registry_set_value"):
            condition.append(eql_condition_template % (event_category[action], event_code_eql[action],
                                                       '''registry.path=="%s" and registry.value=="%s" and winlog.event_data.RegDetails=="%s"''' % (
                                                       word[1].replace("\\", "\\\\") + "\\\\" + word[2].replace("\\",
                                                                                                                "\\\\"),
                                                       word[2].replace("\\", "\\\\"), word[3].replace("\\", "\\\\"))))
        if action in ("registry_delete_key"):
            condition.append(eql_condition_template % (event_category[action], event_code_eql[action],
                                                       '''registry.path=="%s" and registry.value=="%s"''' % (
                                                       word[1].replace("\\", "\\\\"), word[2].replace("\\", "\\\\"))))
        if action in ("processes_created"):
            condition.append(eql_condition_template % (event_category[action], event_code_eql[action],
                                                       '''process.executable=="%s" and process.command_line:"%s"''' % (
                                                       word[2].replace("\\", "\\\\"), word[3].replace("\\", "\\\\"))))
        if action in ("processes_terminated"):
            condition.append(eql_condition_template % (event_category[action], event_code_eql[action],
                                                       '''process.executable=="%s"''' % word[1].replace("\\", "\\\\")))
    return "sequence\r\n" + "\r\n".join(condition)


def getKQL(line):
    word = line.strip("\r\n").split("##")[1:]
    action = word[0]
    if action in ("files_written", "files_deleted"):
        return kql_template % (event_code_kql[action], '''file.path:"%s"''' % word[1].replace("\\", "\\\\"))
    if action in ("files_copied"):
        return kql_template % (event_code_kql[action], '''file.path:"%s"''' % word[2].replace("\\", "\\\\"))
    if action in ("registry_create_value", "registry_set_value"):
        return kql_template % (event_code_kql[action],
                               '''registry.path:"%s" && registry.value:"%s" && winlog.event_data.RegDetails:"%s"''' % (
                               word[1].replace("\\", "\\\\") + "\\\\" + word[2].replace("\\", "\\\\"),
                               word[2].replace("\\", "\\\\"), word[3].replace("\\", "\\\\")))
    if action in ("registry_delete_key"):
        return kql_template % (event_code_kql[action], '''registry.path:"%s" && registry.value:"%s"''' % (
        word[1].replace("\\", "\\\\"), word[2].replace("\\", "\\\\")))
    if action in ("processes_created"):
        return kql_template % (event_code_kql[action], '''process.executable:"%s" && process.command_line:"%s"''' % (
        word[2].replace("\\", "\\\\"), word[3].replace("\\", "\\\\")))
    if action in ("processes_terminated"):
        return kql_template % (event_code_kql[action], '''process.executable:"%s"''' % word[1].replace("\\", "\\\\"))
    return ""


count = 0
f = open("rules.ndjson", 'w')

for family_dir in os.listdir(rule_dir):
    kql = []
    for rule_file in os.listdir(rule_dir + "/" + family_dir):
        query, if_kql = parseFile(rule_dir + "/" + family_dir + "/" + rule_file, family_dir)
        if if_kql:
            kql.append(" ( " + query + " ) ")
        else:
            f.write(getRule(family_dir, query, eql_rule_template) + "\n")
            count += 1
    queries = "||".join(kql)
    print(queries)
    f.write(getRule(family_dir, queries, kql_rule_template) + "\n")
    count += 1

all_template["exported_count"] = count
all_template["exported_rules_count"] = count
f.write(json.dumps(all_template))
f.close()
