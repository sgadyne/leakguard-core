import {test} from 'node:test';
import assert from 'node:assert/strict';
import {backupBytes,exactOrigin,inside,pageAllowed} from './policy.ts';

test('backend origin is IPv4 loopback without token/path or credentials',()=>{
  assert.equal(exactOrigin('http://127.0.0.1:15379'),'http://127.0.0.1:15379');
  for(const input of ['http://localhost:15379','https://127.0.0.1:15379','http://127.0.0.1:15379/secret',
    'http://user@127.0.0.1:15379','http://127.0.0.1:15379#token','http://127.0.0.1:15379/'])
    assert.throws(()=>exactOrigin(input));
  assert.equal(pageAllowed('http://127.0.0.1:15379/#sources','http://127.0.0.1:15379'),true);
  assert.equal(pageAllowed('http://127.0.0.1:15379/?token=x','http://127.0.0.1:15379'),false);
});
test('encrypted backup accepts one fixed filename and canonical bounded base64',()=>{
  assert.equal(backupBytes({filename:'leakguard-vault.lgbak',base64:'AQID'}).length,3);
  for(const input of [{filename:'../vault.lgbak',base64:'AQID'},{filename:'leakguard-vault.lgbak',base64:'AB=='},
    {filename:'leakguard-vault.lgbak',base64:'AQID\n'},{filename:'leakguard-vault.lgbak',base64:'AQID',path:'/tmp/a'}])
    assert.throws(()=>backupBytes(input));
  assert.equal(inside('/profile','/profile2/python'),false);
  assert.equal(inside('/profile','/profile/runtime/python'),true);
});
