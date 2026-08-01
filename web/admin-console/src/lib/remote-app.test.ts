import { describe, it, expect } from 'vitest'
import { remoteAppArgsLookSecret } from './remote-app'

describe('remoteAppArgsLookSecret', () => {
  it('allows empty and integrated-auth args', () => {
    for (const a of ['', '   ', undefined, null, '-E', '-S sql01.corp.local -E', '--nowelcome', '/log C:\\logs\\app.log']) {
      expect(remoteAppArgsLookSecret(a)).toBe(false)
    }
  })

  it('flags password-looking args', () => {
    for (const a of [
      '-P hunter2',
      '-p hunter2',
      '--password hunter2',
      '--pass=hunter2',
      '/password:hunter2',
      '/pass hunter2',
      '-U sa -P hunter2',
      'password=hunter2',
      'PWD=hunter2',
      '-S db;PWD=secret',
    ]) {
      expect(remoteAppArgsLookSecret(a)).toBe(true)
    }
  })
})
