#!/usr/bin/env python3
"""Run CAdES interoperability with checksum-pinned AutoFirma 1.9.1 reference jars.

Requires Java 17+, Cargo and the native signing-test dependencies. Downloads are
test-only, cached under .test-artifacts, and never linked into Firmica.
"""

import hashlib
import os
from pathlib import Path
import subprocess
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".test-artifacts/cades-reference/lib"
BASE = "https://repo.maven.apache.org/maven2/"
ARTIFACTS = {
    "es/gob/afirma/afirma-core/1.9.1/afirma-core-1.9.1.jar":
        "1e2af31ff1962ccccfd35568b154262a8e632558695412e0e95e076c3eb4be2b",
    "es/gob/afirma/afirma-crypto-core-pkcs7/1.9.1/afirma-crypto-core-pkcs7-1.9.1.jar":
        "57a4161b3edf0adc48814803771ffadcdb05c625691436191bfd4433bf70b89d",
    "es/gob/afirma/afirma-crypto-core-pkcs7-tsp/1.9.1/afirma-crypto-core-pkcs7-tsp-1.9.1.jar":
        "6a633a059d18dfedaf0dadd61fc589c305f4a3aabbb26d7bca8c8e6b58f62df9",
    "es/gob/afirma/afirma-crypto-cades/1.9.1/afirma-crypto-cades-1.9.1.jar":
        "04e290bb597688b7091578f38f9e9705a094c460f2d920d2ae3d262cefd3456a",
    "es/gob/afirma/lib/afirma-lib-jmimemagic/0.0.10/afirma-lib-jmimemagic-0.0.10.jar":
        "878e4e8a55130d7d03052f79baa51b270daf664b5a4fddbd4c760634041bd046",
    "com/madgag/spongycastle/core/1.58.0.0/core-1.58.0.0.jar":
        "199617dd5698c5a9312b898c0a4cec7ce9dd8649d07f65d91629f58229d72728",
    "com/madgag/spongycastle/prov/1.58.0.0/prov-1.58.0.0.jar":
        "092fd09e7006b0814980513b013d4c2b3ffd24a49a635ab4b2d204bb51af1727",
    "com/madgag/spongycastle/bcpkix-jdk15on/1.58.0.0/bcpkix-jdk15on-1.58.0.0.jar":
        "89b776cc46caf6f9c29de3fdfe3aad06313b05646778a60873fcfd41f09a87ce",
}


def main():
    CACHE.mkdir(parents=True, exist_ok=True)
    jars = []
    for artifact, expected in ARTIFACTS.items():
        destination = CACHE / artifact.rsplit("/", 1)[1]
        if destination.exists():
            data = destination.read_bytes()
        else:
            with urllib.request.urlopen(BASE + artifact, timeout=30) as response:
                data = response.read(16 * 1024 * 1024 + 1)
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"Reference artifact checksum mismatch: {destination.name}")
        if not destination.exists():
            destination.write_bytes(data)
        jars.append(str(destination))
    # Enumerate verified jars rather than trusting other files in the cache.
    environment = dict(os.environ, FIRMICA_CADES_REFERENCE_CLASSPATH=os.pathsep.join(jars))
    subprocess.run([
        "cargo", "test", "--locked", "-p", "firmica-cades", "--test", "encoding",
        "autofirma_reference", "--", "--ignored", "--test-threads=1",
    ], cwd=ROOT, env=environment, check=True, timeout=180)


if __name__ == "__main__":
    main()
