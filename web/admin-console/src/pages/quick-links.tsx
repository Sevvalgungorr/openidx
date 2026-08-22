import { useMemo, useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import * as Icons from 'lucide-react'
import { ExternalLink, Search, Link2, Play } from 'lucide-react'
import { Card, CardContent } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Dialog, DialogContent } from '../components/ui/dialog'
import { api, QuickLink } from '../lib/api'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'
import { TerminalSession } from '../components/remote/terminal-session'

// Resolve a lucide icon by name (admin picks one); fall back to Link2.
function iconFor(name: string) {
  const C = (Icons as unknown as Record<string, React.ComponentType<{ className?: string }>>)[name]
  return C || Link2
}

export function QuickLinksPage() {
  const [search, setSearch] = useState('')
  const [terminalLink, setTerminalLink] = useState<QuickLink | null>(null)
  const { toast } = useToast()

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['quick-links-mine'],
    queryFn: () => api.quickLinks.listMine(),
  })

  const connect = useMutation({
    mutationFn: (id: string) => api.pam.connect(id),
    onSuccess: (res) => {
      const url = res.connect_url || res.url
      if (url) window.open(url, '_blank', 'noopener')
      else toast({ title: 'Nothing to launch', variant: 'destructive' })
    },
    onError: (e: Error & { body?: { approval_required?: boolean } }) => {
      if (e.body?.approval_required || /requires approval/i.test(e.message)) {
        toast({ title: 'Approval required', description: 'Request access to this connection first.', variant: 'destructive' })
      } else {
        toast({ title: 'Launch failed', description: e.message, variant: 'destructive' })
      }
    },
  })

  const open = (link: QuickLink) => {
    if (link.type === 'external' && link.url) {
      if (link.open_in_new) window.open(link.url, '_blank', 'noopener')
      else window.location.href = link.url
      return
    }
    if (link.type === 'pam' && link.pam_entry_id) {
      // Clientless: wasm-ssh opens the in-browser terminal; else the guac/URL flow.
      if (link.pam_renderer === 'wasm-ssh') setTerminalLink(link)
      else connect.mutate(link.pam_entry_id)
    }
  }

  const links = (data?.quick_links || []).filter((l) =>
    !search ||
    l.title.toLowerCase().includes(search.toLowerCase()) ||
    l.description.toLowerCase().includes(search.toLowerCase()) ||
    l.category.toLowerCase().includes(search.toLowerCase()),
  )

  // Group by category for a scannable layout.
  const grouped = useMemo(() => {
    const g: Record<string, QuickLink[]> = {}
    for (const l of links) (g[l.category] ||= []).push(l)
    return Object.entries(g).sort(([a], [b]) => a.localeCompare(b))
  }, [links])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Quick Links</h1>
        <p className="text-muted-foreground">Jump to support and collaboration systems, and launch connections in your browser.</p>
      </div>

      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input className="pl-10" placeholder="Search links, systems, categories…" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>

      {isLoading ? (
        <p className="text-center py-12 text-muted-foreground">Loading…</p>
      ) : isError ? (
        <QueryError error={error} resource="quick links" />
      ) : links.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Link2 className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <p className="text-lg font-medium">No quick links yet</p>
            <p className="text-muted-foreground">An administrator can add them under Quick Links management.</p>
          </CardContent>
        </Card>
      ) : (
        grouped.map(([category, items]) => (
          <div key={category} className="space-y-3">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">{category}</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {items.map((link) => {
                const Icon = iconFor(link.icon)
                return (
                  <Card key={link.id} className="hover:shadow-lg transition-shadow cursor-pointer group" onClick={() => open(link)}>
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3">
                        <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center shrink-0">
                          <Icon className="h-5 w-5 text-primary" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="font-medium truncate">{link.title}</p>
                            {link.type === 'pam' ? (
                              <Badge variant="secondary" className="text-xs">{link.pam_renderer === 'wasm-ssh' ? 'terminal' : 'connect'}</Badge>
                            ) : (
                              <Badge variant="outline" className="text-xs">link</Badge>
                            )}
                          </div>
                          <p className="text-sm text-muted-foreground line-clamp-2 mt-1">{link.description || '\u00a0'}</p>
                          <div className="mt-2 text-sm text-primary flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            {link.type === 'pam' ? <><Play className="h-3.5 w-3.5" /> Launch</> : <><ExternalLink className="h-3.5 w-3.5" /> Open</>}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>
        ))
      )}

      {/* Clientless in-browser SSH terminal for wasm-ssh PAM quick links. */}
      <Dialog open={!!terminalLink} onOpenChange={(o) => { if (!o) setTerminalLink(null) }}>
        <DialogContent className="max-w-4xl p-0 overflow-hidden">
          {terminalLink?.pam_entry_id && (
            <TerminalSession entryId={terminalLink.pam_entry_id} entryName={terminalLink.title} onClose={() => setTerminalLink(null)} />
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
