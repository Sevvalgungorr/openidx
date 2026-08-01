import {
  KeyRound, Lock, Monitor, Route, Server, Shield, Terminal, User, Video,
  type LucideIcon,
} from 'lucide-react'

import type { PamEntry } from './api'

export interface ConnectionPathStep {
  icon: LucideIcon
  title: string
  desc: string
}

/**
 * The launch chain for a session entry, as displayable steps. This is the
 * "how does clicking Connect actually work" story told with the entry's own
 * configuration: access gate → credential source → session broker → network
 * path → target. Pure function of the entry so it stays testable.
 */
export function connectionPathSteps(entry: PamEntry): ConnectionPathStep[] {
  const remoteApp = typeof entry.settings['remote-app'] === 'string'
    ? String(entry.settings['remote-app']).replace(/^\|\|/, '')
    : ''
  const steps: ConnectionPathStep[] = [
    entry.require_approval
      ? { icon: Lock, title: 'Approval gate', desc: 'Connect requires an approved access request (JIT). The grant is time-bounded and auto-revoked.' }
      : { icon: User, title: 'You click Connect', desc: 'Access is allowed by your role (RBAC) — no approval step configured for this entry.' },
    entry.credential_entry_name
      ? { icon: KeyRound, title: `Linked credential: ${entry.credential_entry_name}`, desc: 'This entry borrows another entry’s vaulted secret. It is decrypted server-side at connect time and never shown to you.' }
      : entry.has_secret
        ? { icon: KeyRound, title: 'Vaulted secret', desc: 'The entry’s own secret is decrypted server-side at connect time and injected — never shown to you.' }
        : { icon: KeyRound, title: 'No stored credential', desc: 'The target will prompt for credentials inside the session.' },
    entry.renderer === 'wasm-ssh'
      ? { icon: Terminal, title: 'Browser terminal', desc: 'Clientless SSH terminal in this console tab (no Guacamole session).' }
      : remoteApp
        ? { icon: Monitor, title: `RemoteApp: ${remoteApp}`, desc: `Guacamole opens only the published "${remoteApp}" application instead of a full ${entry.entry_type.toUpperCase()} desktop.` }
        : { icon: Monitor, title: `Guacamole ${entry.entry_type.toUpperCase()} session`, desc: 'The session runs in the browser through the Guacamole gateway.' },
  ]
  if (entry.record_session) {
    steps.push({ icon: Video, title: 'Session recording', desc: 'The full session is recorded (including keys) and sealed for audit.' })
  }
  steps.push(
    entry.ziti_enabled
      ? { icon: Shield, title: 'Ziti overlay (zero-trust)', desc: 'Traffic reaches the target over the OpenZiti overlay — the target exposes no IP/port to the network.' }
      : { icon: Route, title: 'Direct reach', desc: 'The gateway connects straight to the target address.' },
    { icon: Server, title: entry.hostname ? `${entry.hostname}${entry.port ? `:${entry.port}` : ''}` : 'Target', desc: entry.username ? `Signed in as ${entry.username}${entry.domain ? ` (${entry.domain})` : ''}.` : 'Target system.' },
  )
  return steps
}
