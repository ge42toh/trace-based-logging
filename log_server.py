import os
import json
import yaml
import time
import threading
import xml.etree.ElementTree as ET
from flask import Flask, request
import traceback

LISTEN_PORT = 9379
LOG_DIR = "traces"
RAW_DIR = "raw_events"
FINISH_DRAIN_MS = 250

for d in [LOG_DIR, RAW_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

INSTANCE_CONFIG = {}
CHILD_PARENT_MAP = {}

INSTANCE_LOCKS = {}
LOCKS_REGISTRY_LOCK = threading.Lock()

def get_instance_lock(uuid):
    with LOCKS_REGISTRY_LOCK:
        if uuid not in INSTANCE_LOCKS:
            INSTANCE_LOCKS[uuid] = threading.Lock()
        return INSTANCE_LOCKS[uuid]

LIFECYCLE_MAPPING = {
    'calling': 'start',
    'done': 'complete',
    'failed': 'failure',
    'instantiation': 'start'
}

app = Flask(__name__)

def parse_logging_behavior(instance_uuid, xml_content):
    try:
        root = ET.fromstring(xml_content)
        exclusions = set()
        inclusions = set()
        loops = {}

        for elem in root.iter():
            if elem.tag.endswith('call') or elem.tag.endswith('subprocess'):
                call_id = elem.get('id')
                for child in elem.iter():
                    if '_exclude' in child.tag and child.text and child.text.strip().lower() in ('on', 'true'):
                        exclusions.add(call_id)
                    if '_include' in child.tag and child.text and child.text.strip().lower() in ('on', 'true'):
                        inclusions.add(call_id)
        
        loop_counter = 1
        for elem in root.iter():
            if elem.tag.endswith('loop'):
                loop_id = elem.get('eid')
                mode = elem.get('mode', 'pre_test')
                
                iteration_on = False
                for child in elem.iter():
                    if child.tag.endswith('_iteration') and child.text and child.text.strip().lower() in ('on', 'true'):
                        iteration_on = True
                
                tasks_in_loop = set()
                def collect_direct_tasks(parent):
                    for child in parent:
                        if child.tag.endswith('loop'):
                            nested_has_iteration = False
                            for ann in child.iter():
                                if ann.tag.endswith('_iteration') and ann.text and ann.text.strip().lower() in ('on', 'true'):
                                    nested_has_iteration = True
                                    break
                            if nested_has_iteration:
                                continue
                            nested_eid = child.get('eid')
                            if nested_eid:
                                tasks_in_loop.add(nested_eid)
                        if child.tag.endswith('call') or child.tag.endswith('subprocess'):
                            tid = child.get('id')
                            if tid:
                                tasks_in_loop.add(tid)
                        collect_direct_tasks(child)
                collect_direct_tasks(elem)
                        
                if loop_id:
                    loops[loop_id] = {
                        'iteration_on': iteration_on,
                        'mode': mode,
                        'tasks': tasks_in_loop,
                        'current_iteration': 1 if mode == 'post_test' else 0,
                        'name': f"loop{loop_counter}",
                        'pending_increment': False
                    }
                    loop_counter += 1

        if instance_uuid not in INSTANCE_CONFIG:
            INSTANCE_CONFIG[instance_uuid] = {'exclude': set(), 'include': set(), 'loops': {}}
        
        INSTANCE_CONFIG[instance_uuid]['exclude'].update(exclusions)
        INSTANCE_CONFIG[instance_uuid]['include'].update(inclusions)
        
        for l_id, l_data in loops.items():
            if l_id not in INSTANCE_CONFIG[instance_uuid]['loops']:
                INSTANCE_CONFIG[instance_uuid]['loops'][l_id] = l_data

    except Exception as e:
        print(f"⚠️ Error parsing XML: {e}")

def check_for_subprocess_link(parent_uuid, topic, event_name, content):
    if topic == 'activity' and event_name == 'receiving':
        received_data = content.get('received', [])
        
        activity_id = 'external'
        for key in ['activity', 'loop', 'gateway', 'task', 'id', 'node', 'eid', 'element']:
            if key in content and content[key] is not None:
                activity_id = str(content[key])
                break

        for item in received_data:
            possible_child_uuid = None
            if isinstance(item, dict):
                val = item.get('value')
                if not val: val = item.get('url')
                if val and isinstance(val, str) and len(val) > 10 and '/' in val:
                     possible_child_uuid = val.strip('/').split('/')[-1]

                if not possible_child_uuid and 'data' in item and isinstance(item['data'], str):
                    try:
                        inner_data = json.loads(item['data'])
                        if isinstance(inner_data, dict):
                            if 'CPEE-INSTANCE-UUID' in inner_data: possible_child_uuid = inner_data['CPEE-INSTANCE-UUID']
                            elif 'instance-uuid' in inner_data: possible_child_uuid = inner_data['instance-uuid']
                    except json.JSONDecodeError: pass

            elif isinstance(item, str) and len(item) > 10 and '/' in item:
                 possible_child_uuid = item.strip('/').split('/')[-1]

            if possible_child_uuid and possible_child_uuid not in CHILD_PARENT_MAP:
                CHILD_PARENT_MAP[possible_child_uuid] = {'parent_uuid': parent_uuid, 'parent_activity': activity_id}
                print(f"🔗 Link registered: Parent {parent_uuid} -> Child {possible_child_uuid}")

def get_header_dict(log_data, target_uuid):
    instance_id = log_data.get('instance', -1)
    instance_name = log_data.get('instance-name', '__NOTSPECIFIED__')
    return {
        'log': {
            'namespaces': {'stream': 'https://cpee.org/datastream/','ssn': 'http://www.w3.org/ns/ssn/','sosa': 'http://www.w3.org/ns/sosa/'},
            'xes': {'creator': 'cpee.org','features': 'nested-attributes'},
            'extension': {'time': 'http://www.xes-standard.org/time.xesext','concept': 'http://www.xes-standard.org/concept.xesext','id': 'http://www.xes-standard.org/identity.xesext','lifecycle': 'http://www.xes-standard.org/lifecycle.xesext','cpee': 'http://cpee.org/cpee.xesext'},
            'global': {'trace': {'concept:name': '__NOTSPECIFIED__','cpee:name': '__NOTSPECIFIED__'},'event': {'concept:instance': -1,'id:id': '__NOTSPECIFIED__','cpee:instance': '__NOTSPECIFIED__','lifecycle:transition': 'complete','time:timestamp': ''}},
            'trace': {'concept:name': str(instance_id),'cpee:name': instance_name,'cpee:instance': target_uuid}
        }
    }

def transform_to_event_dict(log_data, target_uuid):
    content = log_data.get('content', {})
    topic = log_data.get('topic', '')
    event_name = log_data.get('name', '')
    
    activity_id = 'external'
    for key in ['activity', 'loop', 'gateway', 'task', 'id', 'node', 'eid', 'element']:
        if key in content and content[key] is not None:
            activity_id = str(content[key])
            break
            
    event_dict = {
        'concept:instance': log_data.get('instance'),
        'id:id': activity_id,
        'cpee:instance': target_uuid,
        'cpee:lifecycle:transition': f"{topic}/{event_name}",
        'time:timestamp': log_data.get('timestamp')
    }
    event_dict['lifecycle:transition'] = LIFECYCLE_MAPPING.get(event_name, 'unknown')
    
    if topic == 'activity':
        event_dict['cpee:activity'] = content.get('activity', '')
        label = content.get('label') or content.get('parameters', {}).get('label')
        if label:
            event_dict['concept:name'] = label
        if 'endpoint' in content:
            event_dict['concept:endpoint'] = content['endpoint']
        act_uuid = content.get('activity-uuid')
        if act_uuid:
            event_dict['cpee:activity_uuid'] = act_uuid
        if event_name == 'calling':
            args = content.get('parameters', {}).get('arguments')
            if args:
                event_dict['data'] = args
        elif event_name == 'receiving':
            received = content.get('received', [])
            if received:
                event_dict['data'] = received
    elif topic == 'state' and event_name == 'change':
        event_dict['cpee:state'] = content.get('state', '')
    elif topic == 'gateway' and event_name == 'decide':
        decide_data = {}
        if 'result' in content: decide_data['result'] = content['result']
        if 'condition' in content: decide_data['condition'] = content['condition']
        if 'data' in content and isinstance(content['data'], dict): decide_data.update(content['data'])
        if decide_data:
            event_dict['data'] = decide_data
            
    return {'event': event_dict}


def merge_orphan_log(child_uuid, parent_uuid):
    child_files = [f for f in os.listdir(LOG_DIR) if f.endswith(f"{child_uuid}.yaml")]
    if not child_files: return

    child_filename = os.path.join(LOG_DIR, child_files[0])
    parent_files = [f for f in os.listdir(LOG_DIR) if f.endswith(f"{parent_uuid}.yaml")]
    if not parent_files: return
    
    parent_filename = os.path.join(LOG_DIR, parent_files[0])
    
    print(f"🧹 RETRO-MERGE: Integrating {child_uuid} into {parent_uuid}")
    try:
        with open(child_filename, 'r', encoding='utf-8') as f:
            content = f.read()
        parts = content.split('---\n')
        if len(parts) > 2:
            events = parts[2:]
            with open(parent_filename, 'a', encoding='utf-8') as f_parent:
                for ev in events:
                    f_parent.write('---\n')
                    f_parent.write(ev)
        os.remove(child_filename)
    except Exception as e:
        pass

def do_retro_merges(parent_uuid):
    for child_uuid, link_info in CHILD_PARENT_MAP.items():
        if link_info['parent_uuid'] == parent_uuid:
            act_id = link_info['parent_activity']
            if parent_uuid in INSTANCE_CONFIG and act_id in INSTANCE_CONFIG[parent_uuid]['include']:
                merge_orphan_log(child_uuid, parent_uuid)


def process_instance_events(instance_uuid):
    raw_file = os.path.join(RAW_DIR, f"{instance_uuid}.jsonl")
    if not os.path.exists(raw_file):
        return

    print(f"\n🚀 Generating trace for finished process: {instance_uuid}")

    with open(raw_file, 'r', encoding='utf-8') as f:
        events = [json.loads(line) for line in f if line.strip()]

    events.sort(key=lambda x: x.get('timestamp', ''))

    config = INSTANCE_CONFIG.get(instance_uuid, {'exclude': set(), 'include': set(), 'loops': {}})
    loops = config.get('loops', {})
    
    for l in loops.values():
        l['current_iteration'] = 1 if l['mode'] == 'post_test' else 0
        l['pending_increment'] = False

    written_files = set()

    for log_data in events:
        topic = log_data.get('topic')
        event_name = log_data.get('name')
        content = log_data.get('content', {})
        instance_name = log_data.get('instance-name', 'Unknown')

        if instance_name == "Enter info here":
            continue

        element_id = 'external'
        for key in ['activity', 'loop', 'gateway', 'task', 'id', 'node', 'eid', 'element']:
            if key in content and content[key] is not None:
                element_id = str(content[key])
                break

        if topic in ['activity', 'task']:
            for l_id, l_data in loops.items():
                if element_id in l_data['tasks']:
                    if l_data.get('pending_increment') and l_data['mode'] == 'post_test':
                        l_data['current_iteration'] += 1
                        l_data['pending_increment'] = False
                        print(f"🔄 {l_data['name']} (post_test): Next -> Iteration {l_data['current_iteration']}")

        if topic == 'gateway' and event_name == 'decide':
            loop_to_increment = element_id
            if loop_to_increment == 'external' and len(loops) == 1:
                loop_to_increment = list(loops.keys())[0]

            if loop_to_increment in loops:
                l_data = loops[loop_to_increment]
                
                result_val = content.get('result')
                if result_val is None: result_val = content.get('condition')
                if result_val is None and 'data' in content and isinstance(content['data'], dict):
                    result_val = content['data'].get('result')
                    if result_val is None: 
                        result_val = content['data'].get('condition')

                if result_val is not None:
                    result_bool = result_val.lower() == 'true' if isinstance(result_val, str) else bool(result_val)
                    
                    loop_name = l_data['name']
                    
                    if result_bool:
                        if l_data['mode'] == 'pre_test':
                            l_data['current_iteration'] += 1
                            print(f"🔄 {loop_name} (pre_test): Evaluation -> Iteration {l_data['current_iteration']}")
                        elif l_data['mode'] == 'post_test':
                            l_data['pending_increment'] = True
                    else:
                        print(f"🛑 {loop_name}: Ended -> No increment.")

        target_uuid = instance_uuid
        for l_id, l_data in loops.items():
            if element_id in l_data['tasks'] or element_id == l_id:
                if l_data['iteration_on']:
                    iter_num = max(1, l_data['current_iteration'])
                    target_uuid = f"{instance_uuid}_{l_data['name']}_{iter_num:02d}"
                break

        if topic in ['activity', 'task']:
            if element_id in config['exclude']:
                print(f"🚫 Exclude: Skipping '{element_id}'")
                continue

        log_filename = os.path.join(LOG_DIR, f"trace_{target_uuid}.yaml")
        is_new_file = log_filename not in written_files and not os.path.exists(log_filename)

        with open(log_filename, 'a', encoding='utf-8') as f:
            if is_new_file:
                header = get_header_dict(log_data, target_uuid)
                f.write('---\n')
                yaml.safe_dump(header, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
                written_files.add(log_filename)
                print(f"📁 Trace file created: {log_filename}")
            
            event_yaml = transform_to_event_dict(log_data, target_uuid)
            f.write('---\n')
            yaml.safe_dump(event_yaml, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    print(f"✅ YAML traces successfully generated for {instance_uuid}.")
    
    do_retro_merges(instance_uuid)


def schedule_phase2(instance_uuid):
    def runner():
        time.sleep(FINISH_DRAIN_MS / 1000.0)
        lock = get_instance_lock(instance_uuid)
        with lock:
            try:
                process_instance_events(instance_uuid)
            except Exception as e:
                print(f"❌ Phase 2 error for {instance_uuid}: {e}")
                traceback.print_exc()
    threading.Thread(target=runner, daemon=True).start()


@app.route('/', methods=['POST'])
def cpee_log_receiver():
    if 'notification' in request.form:
        try:
            json_string = request.form['notification']
            log_data = json.loads(json_string)

            current_uuid = log_data.get('instance-uuid')
            topic = log_data.get('topic')
            event_name = log_data.get('name')
            
            if not current_uuid: return "Missing UUID", 400
            
            lock = get_instance_lock(current_uuid)
            with lock:
                raw_file = os.path.join(RAW_DIR, f"{current_uuid}.jsonl")
                with open(raw_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(log_data) + '\n')

                if topic == 'description' and event_name in ['change', 'exposition']:
                    xml_desc = log_data.get('content', {}).get('description')
                    if xml_desc: parse_logging_behavior(current_uuid, xml_desc)

                check_for_subprocess_link(current_uuid, topic, event_name, log_data.get('content', {}))

            is_finished = (topic == 'state' and event_name == 'change' and
                           log_data.get('content', {}).get('state') == 'finished')
            if is_finished:
                schedule_phase2(current_uuid)

            return "OK", 200

        except Exception as e:
            print(f"❌ Error: {e}")
            traceback.print_exc()
            return f"Error: {e}", 500
    else:
        return "Missing notification", 400

if __name__ == '__main__':
    app.run(host='::1', port=LISTEN_PORT, debug=True, threaded=True)
