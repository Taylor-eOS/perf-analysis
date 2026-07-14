import re
from collections import defaultdict

input_path = "game_trace.txt"
target_command = "WinMain"
target_object = "Rome"
output_addrs_path = "winmain_rome_addresses.txt"
output_edges_path = "winmain_rome_edges.txt"
root_re = re.compile(r"^\s*(\d+\.\d+)%\s+(\d+\.\d+)%\s+(\S+)\s+(\S+)\s+\[.\]\s+(\S+)")
addr_re = re.compile(r"^(0x[0-9a-fA-F]+|[0-9a-fA-F]{4,16})$")
min_plausible_addr = 0x100000
max_plausible_addr = 0xffffffff

def hex_norm(tok):
    if tok.startswith("0x"):
        tok = tok[2:]
    try:
        return int(tok, 16)
    except ValueError:
        return None

def is_plausible_code_addr(addr):
    return min_plausible_addr <= addr <= max_plausible_addr

def parse_frame_line(raw):
    idx = raw.find("--")
    if idx == -1:
        return None
    rest = raw[idx:]
    m = re.match(r"^-+(\d+\.\d+)%--(.*)$", rest)
    if m:
        return idx, float(m.group(1)), m.group(2).strip()
    m2 = re.match(r"^-+(.*)$", rest)
    if m2:
        return idx, 0.0, m2.group(1).strip()
    return None

node_pct = {}
edges = defaultdict(float)
hit_count = defaultdict(int)
in_target_block = False
depth_stack = []
root_addr = None

with open(input_path, "r") as f:
    lines = f.readlines()

for line in lines:
    raw = line.rstrip("\n")
    if raw.startswith("#"):
        continue
    if raw.strip() == "":
        in_target_block = False
        depth_stack = []
        root_addr = None
        continue
    m = root_re.match(raw)
    if m:
        pct_children, pct_self, command, shared_obj, symbol = m.groups()
        in_target_block = (command == target_command)
        depth_stack = []
        root_addr = None
        if in_target_block and shared_obj == target_object and addr_re.match(symbol):
            addr = hex_norm(symbol)
            if addr is not None and is_plausible_code_addr(addr):
                node_pct[addr] = max(node_pct.get(addr, 0.0), float(pct_children))
                hit_count[addr] += 1
                depth_stack.append((-1, addr))
                root_addr = addr
        continue
    if not in_target_block:
        continue
    if set(raw.strip()) <= {"|", " "}:
        continue
    lead = len(raw) - len(raw.lstrip(" "))
    body = raw.lstrip(" ")
    if body.startswith("0x") and "--" not in body:
        addr = hex_norm(body.strip())
        if addr is None or not is_plausible_code_addr(addr):
            depth_stack.append((lead, None))
            continue
        if addr == root_addr and len(depth_stack) == 1:
            continue
        while depth_stack and depth_stack[-1][0] >= lead:
            depth_stack.pop()
        parent = depth_stack[-1][1] if depth_stack else None
        if parent == addr:
            continue
        node_pct[addr] = max(node_pct.get(addr, 0.0), 0.0)
        hit_count[addr] += 1
        if parent is not None:
            edges[(parent, addr)] = max(edges[(parent, addr)], 0.0)
        depth_stack.append((lead, addr))
        continue
    parsed = parse_frame_line(raw)
    if parsed is None:
        continue
    col, pct, token = parsed
    while depth_stack and depth_stack[-1][0] >= col:
        depth_stack.pop()
    parent = depth_stack[-1][1] if depth_stack else None
    if addr_re.match(token):
        addr = hex_norm(token)
        if addr is None or addr == parent or not is_plausible_code_addr(addr):
            depth_stack.append((col, None))
            continue
        node_pct[addr] = max(node_pct.get(addr, 0.0), pct)
        hit_count[addr] += 1
        if parent is not None:
            edges[(parent, addr)] = max(edges[(parent, addr)], pct)
        depth_stack.append((col, addr))
    else:
        depth_stack.append((col, None))

with open(output_addrs_path, "w") as f:
    for addr, pct in sorted(node_pct.items(), key=lambda kv: (-kv[1], -hit_count[kv[0]])):
        f.write(f"0x{addr:x}\t{pct:.2f}%\thits={hit_count[addr]}\n")

with open(output_edges_path, "w") as f:
    for (caller, callee), pct in sorted(edges.items(), key=lambda kv: -kv[1]):
        f.write(f"0x{caller:x} -> 0x{callee:x}\t{pct:.2f}%\n")

print(f"unique {target_object} addresses under {target_command}: {len(node_pct)}")
print(f"unique edges (real parent-child pairs only): {len(edges)}")
