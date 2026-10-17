// Pinned, unmodified AutoScript used by native interoperability tests.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
const revision = '0d7f3cf01fb65d2be5b245622d2c8f490f36e718';
const digest = '649ace348a9e4478436ed0fab32922b401e31f3ef6461949882a9bd95c8be5ec';
const sourcePath = 'afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js';
const root = path.resolve(import.meta.dirname, '../..');
const artifact = path.join(root, '.test-artifacts');

export async function autoscript() {
  const cached = process.env.FIRMICA_AUTOSCRIPT || path.join(artifact, 'autoscript.js');
  let bytes;
  try { bytes = await readFile(cached); }
  catch (error) {
    if (process.env.FIRMICA_AUTOSCRIPT || error.code !== 'ENOENT') throw error;
    const response = await fetch(`https://raw.githubusercontent.com/ctt-gob-es/clienteafirma/${revision}/${sourcePath}`);
    assert.ok(response.ok, `upstream download: ${response.status}`);
    bytes = Buffer.from(await response.arrayBuffer());
    assert.equal(createHash('sha256').update(bytes).digest('hex'), digest);
    await mkdir(artifact, { recursive: true });
    await writeFile(cached, bytes);
  }
  assert.equal(createHash('sha256').update(bytes).digest('hex'), digest, 'AutoScript must be unmodified');
  return bytes;
}
