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


def find_mappings(obj):
    if isinstance(obj, dict):
        if "mappings" in obj:
            return obj["mappings"]
        for v in obj.values():
            res = find_mappings(v)
            if res:
                return res
    elif isinstance(obj, list):
        for v in obj:
            res = find_mappings(v)
            if res:
                return res
    return None


def get_packet_id(protocol_number, state, direction, packet_name):
    try:
        proto = loader.get_protocol(protocol_number)
        state_data = proto.get(state, {}).get(direction, {})
        mappings = find_mappings(state_data)
        if mappings:
            for pid_hex, name in mappings.items():
                if name == packet_name:
                    return int(pid_hex, 16)
    except Exception:
        pass
    return None
