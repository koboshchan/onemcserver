import json
import os


class ProtocolLoader:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.data_paths = json.load(
            open(os.path.join(repo_path, "data/dataPaths.json"))
        )
        self.protocol_versions = json.load(
            open(os.path.join(repo_path, "data/pc/common/protocolVersions.json"))
        )
        self.proto_to_version = {
            v["version"]: v["minecraftVersion"]
            for v in self.protocol_versions
            if "version" in v
        }
        self._cache = {}

    def get_protocol(self, protocol_number):
        version_str = self.proto_to_version.get(protocol_number)
        if not version_str:
            version_str = "1.21.1"
        if version_str in self._cache:
            return self._cache[version_str]

        pc_data = self.data_paths.get("pc", {})
        version_entry = pc_data.get(version_str)
        if not version_entry:
            # Fallback to a close match if version_str is not in data_paths
            version_str = "1.21.1"
            version_entry = pc_data.get(version_str)

        protocol_rel_path = version_entry.get("protocol")
        protocol_path = os.path.join(
            self.repo_path, "data", protocol_rel_path, "protocol.json"
        )

        proto = json.load(open(protocol_path))
        self._cache[version_str] = proto
        return proto


loader = ProtocolLoader("minecraft-data-repo")


def _parse_version_tuple(version_str):
    parts = version_str.split(".")
    nums = []
    for p in parts:
        if not p.isdigit():
            return None
        nums.append(int(p))
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def _available_login_packet_versions():
    seen = set()
    out = []
    for item in loader.protocol_versions:
        ver = item.get("minecraftVersion")
        if not ver or ver in seen:
            continue
        lp = os.path.join(loader.repo_path, "data", "pc", ver, "loginPacket.json")
        if os.path.exists(lp):
            seen.add(ver)
            out.append(ver)
    return out


def _latest_patch_in_same_minor(version_str):
    base = _parse_version_tuple(version_str)
    if base is None:
        return version_str
    b_major, b_minor, _ = base
    best = None
    for ver in _available_login_packet_versions():
        vt = _parse_version_tuple(ver)
        if vt is None:
            continue
        v_major, v_minor, v_patch = vt
        if (v_major, v_minor) != (b_major, b_minor):
            continue
        if best is None or v_patch > best[0]:
            best = (v_patch, ver)
    return best[1] if best else version_str


def _best_patch_for_hint(version_str):
    """Pick same-major.minor loginPacket version closest to hint, preferring newer on ties."""
    base = _parse_version_tuple(version_str)
    if base is None:
        return version_str
    b_major, b_minor, b_patch = base

    candidates = []
    for ver in _available_login_packet_versions():
        vt = _parse_version_tuple(ver)
        if vt is None:
            continue
        v_major, v_minor, v_patch = vt
        if (v_major, v_minor) != (b_major, b_minor):
            continue
        # Sort by distance to hint patch, and for equal distance choose newer patch.
        candidates.append((abs(v_patch - b_patch), -v_patch, ver))

    if candidates:
        candidates.sort()
        return candidates[0][2]
    return version_str


def resolve_login_packet_version(protocol_number, client_version_hint=None):
    """Resolve the best minecraft-data version that has loginPacket.json for a protocol."""
    # Prefer an explicit client version hint from known-packs when available.
    if client_version_hint:
        hinted_lp = os.path.join(
            loader.repo_path, "data", "pc", client_version_hint, "loginPacket.json"
        )
        if os.path.exists(hinted_lp):
            return client_version_hint

        hinted_tuple = _parse_version_tuple(client_version_hint)
        if hinted_tuple is not None:
            return _best_patch_for_hint(client_version_hint)

    # Exact protocol -> version first, but use latest available patch in that
    # major.minor line because multiple Minecraft patch versions share protocol ids.
    exact_version = loader.proto_to_version.get(protocol_number)
    if exact_version:
        chosen = _latest_patch_in_same_minor(exact_version)
        exact_lp = os.path.join(
            loader.repo_path, "data", "pc", chosen, "loginPacket.json"
        )
        if os.path.exists(exact_lp):
            return chosen

    # Otherwise choose the closest known protocol that has loginPacket.json.
    candidates = []
    for item in loader.protocol_versions:
        pv = item.get("version")
        ver = item.get("minecraftVersion")
        if pv is None or not ver:
            continue
        lp = os.path.join(loader.repo_path, "data", "pc", ver, "loginPacket.json")
        if not os.path.exists(lp):
            continue
        candidates.append((abs(int(pv) - int(protocol_number)), -int(pv), ver))

    if candidates:
        candidates.sort()
        return candidates[0][2]

    # Last-resort stable fallback.
    return "1.21.1"


def load_login_packet(protocol_number, client_version_hint=None):
    version_str = resolve_login_packet_version(protocol_number, client_version_hint)
    lp_path = os.path.join(
        loader.repo_path, "data", "pc", version_str, "loginPacket.json"
    )
    return version_str, json.load(open(lp_path))


def get_packet_id(protocol_number, state, direction, packet_name):
    """
    Looks up packet ID for a given state (handshaking, status, login, configuration, play)
    and direction (toClient, toServer).
    """
    try:
        proto = loader.get_protocol(protocol_number)
        state_data = proto.get(state, {}).get(direction, {})
        types = state_data.get("types", {})

        # Deep search for packet name mappings
        def find_mappings_recursive(obj):
            if isinstance(obj, dict):
                if "mappings" in obj and isinstance(obj["mappings"], dict):
                    for pid, name in obj["mappings"].items():
                        if name == packet_name:
                            return int(pid, 16) if pid.startswith("0x") else int(pid)
                for v in obj.values():
                    res = find_mappings_recursive(v)
                    if res is not None:
                        return res
            elif isinstance(obj, list):
                for v in obj:
                    res = find_mappings_recursive(v)
                    if res is not None:
                        return res
            return None

        # Prioritize looking in the 'packet' type definition
        if "packet" in types:
            res = find_mappings_recursive(types["packet"])
            if res is not None:
                return res

        return find_mappings_recursive(types)
    except Exception as e:
        print(f"[!] get_packet_id error: {e}")
    return None
