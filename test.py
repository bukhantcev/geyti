import requests

def apply_config(ip, ports:dict):
    url = f"http://{ip}/index.cgi/action"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    ports_info = {}
    for key, volume in ports.items():
        ports_info[key] = {
            "name": f"Port {key}",
            "direct": "out",
            "proto": "sacn",
            "universe": volume,
            "pps": "35",
            "sync": "off",
            "rdm": False,
            "dmx_fault_reset": False
        }
    print(ports_info)

    import json
    data = {
        "data": '''{
            "ports": ''' + json.dumps(ports_info) + ''',
            
            "action": "apply-config"
        }'''
    }
    print(data)
    reboot = {
        "data": '''{
                "action": "reboot"
            }'''
    }

    response = requests.post(url, data=data, headers=headers)
    print(response)
    import time
    time.sleep(3)
    response_reboot = requests.post(url, data=reboot, headers=headers)
    return response_reboot

