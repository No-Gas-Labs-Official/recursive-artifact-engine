import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { observeBytes } from '../../src/evidence.js';
const execute = promisify(execFile);
// Independent fixture generator: synthetic DEX, not the private reference APK.
const fixture = String.raw`
import io,zipfile,struct,hashlib,zlib,base64,sys
mode=sys.argv[1]
strings=[b'Lexample/Main;',b'STAGE_1_INDEPENDENT']
data=bytearray(112+8+4+32)
data[:8]=b'dex\n035\0'
struct.pack_into('<I',data,36,112);struct.pack_into('<I',data,40,0x12345678)
struct.pack_into('<II',data,56,2,112);struct.pack_into('<II',data,64,1,120);struct.pack_into('<II',data,96,1,124)
for i,s in enumerate(strings):
 struct.pack_into('<I',data,112+4*i,len(data));data.extend(bytes([len(s)])+s+b'\0')
struct.pack_into('<I',data,32,len(data))
data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
if mode=='bad-dex':data[40]=0
b=io.BytesIO()
with zipfile.ZipFile(b,'w') as z:
 z.writestr('AndroidManifest.xml',b'fixture')
 z.writestr('classes.dex',data)
 if mode=='duplicate':z.writestr('classes.dex',data)
 if mode=='traversal':z.writestr('../escape',b'x')
print(base64.b64encode(b.getvalue()).decode())
`;
test('APK parser observes actual DEX definitions and strings; rejects malformed containers', async () => {
  const apk = async mode => Buffer.from((await execute('python3',['-I','-c',fixture,mode])).stdout.trim(),'base64');
  const observed = await observeBytes(await apk('ok'),'apk');
  assert.deepEqual(observed.extraction.dex['classes.dex'].classes,['Lexample/Main;']);
  assert.ok(observed.extraction.dex['classes.dex'].strings.includes('STAGE_1_INDEPENDENT'));
  for (const mode of ['duplicate','traversal','bad-dex']) await assert.rejects(observeBytes(await apk(mode),'apk'),/extraction_failed/);
});
