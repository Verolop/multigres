"""Temporary cold-build experiment: inspect OCI outputs without executing them."""

import hashlib
import json
import struct
import sys
import tarfile

archive_path, image, case, source_sha, output = sys.argv[1:]
commands = ["multigateway", "multipooler", "pgctld", "multiorch", "multigres", "multiadmin", "portpoolserver"]
if image == "multigres":
    expected = {"multigres/bin/" + name for name in commands if name not in {"pgctld", "portpoolserver"}}
elif image == "pgctld":
    expected = {"usr/local/bin/pgctld"}
elif image == "multiadmin-web":
    expected = set()
else:
    expected = {"usr/local/bin/" + name for name in commands}

with tarfile.open(archive_path) as archive:
    def blob(digest):
        algorithm, value = digest.split(":", 1)
        assert algorithm == "sha256"
        return archive.extractfile("blobs/sha256/" + value)

    def manifests(document):
        if "manifests" in document:
            for descriptor in document["manifests"]:
                yield from manifests(json.load(blob(descriptor["digest"])))
        elif "layers" in document:
            yield document

    platforms = {}
    for manifest in manifests(json.load(archive.extractfile("index.json"))):
        config = json.load(blob(manifest["config"]["digest"]))
        architecture = config.get("architecture")
        if config.get("os") != "linux" or architecture not in {"amd64", "arm64"}:
            continue
        assert architecture not in platforms, "Duplicate image platform"
        binaries = {}
        for layer in manifest["layers"]:
            with tarfile.open(fileobj=blob(layer["digest"]), mode="r|*") as files:
                for member in files:
                    name = member.name.removeprefix("./").lstrip("/")
                    if name not in expected or not member.isfile():
                        continue
                    data = files.extractfile(member).read()
                    assert data[:6] == b"\x7fELF\x02\x01", name + ": expected little-endian ELF64"
                    machine = struct.unpack_from("<H", data, 18)[0]
                    assert machine == {"amd64": 62, "arm64": 183}[architecture], name + ": wrong architecture"
                    phoff = struct.unpack_from("<Q", data, 32)[0]
                    phentsize, phnum = struct.unpack_from("<HH", data, 54)
                    assert all(struct.unpack_from("<I", data, phoff + i * phentsize)[0] != 3
                               for i in range(phnum)), name + ": unexpected dynamic interpreter"
                    binaries[name] = hashlib.sha256(data).hexdigest()
        assert set(binaries) == expected, (image, architecture, sorted(expected - set(binaries)))
        platforms[architecture] = {"binaries": binaries}
    assert set(platforms) == {"amd64", "arm64"}, platforms.keys()

result = {"image": image, "case": case, "source_sha": source_sha, "platforms": platforms}
with open(output, "w") as handle:
    json.dump(result, handle, indent=2)
    handle.write("\n")
print(json.dumps(result, indent=2))
