import json

d = json.load(open('core/testdata/ps_exec_test.json', encoding='utf-8-sig'))
matrix = d.get('matrix', {})
print("--- ALL CAPABILITIES IN PS REPORT ---")
for tech, caps in sorted(matrix.items()):
    for cap, info in sorted(caps.items()):
        status = info.get("status")
        tool = info.get("tool")
        if status == "available":
            print(f"[AVAILABLE] {tech}.{cap} -> tool={tool}")
        else:
            print(f"[{status}] {tech}.{cap} -> tool={tool}")

print("\n--- TOOL RESOLUTION IN PS REPORT ---")
res = d.get('resolver', {})
for tool_name, info in sorted(res.items()):
    status = info.get("status")
    print(f"[{status}] {tool_name} (version={info.get('version')}, source={info.get('source')})")
