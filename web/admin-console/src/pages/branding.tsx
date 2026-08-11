import { useEffect, useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Palette } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { LoadingSpinner } from '../components/ui/loading-spinner'

interface Organization {
  id: string
  name: string
  slug: string
}

interface Branding {
  logo_url: string
  favicon_url: string
  primary_color: string
  secondary_color: string
  background_color: string
  background_image_url: string
  login_page_title: string
  login_page_message: string
  portal_title: string
  custom_css: string
  custom_footer: string
  powered_by_visible: boolean
}

const emptyBranding: Branding = {
  logo_url: '', favicon_url: '', primary_color: '#2563eb', secondary_color: '#1e40af',
  background_color: '#ffffff', background_image_url: '', login_page_title: '',
  login_page_message: '', portal_title: '', custom_css: '', custom_footer: '',
  powered_by_visible: true,
}

export function BrandingPage() {
  const { toast } = useToast()
  const [orgID, setOrgID] = useState<string>('')
  const [form, setForm] = useState<Branding>(emptyBranding)

  // The org list is backend-scoped: a tenant admin sees only their org; a
  // platform admin (super_admin) sees all and can pick which tenant to brand.
  const { data: orgData, isLoading: orgsLoading } = useQuery({
    queryKey: ['organizations', 'branding'],
    queryFn: () => api.get<Organization[]>('/api/v1/organizations'),
  })
  const orgs = orgData ?? []

  useEffect(() => {
    if (!orgID && orgs.length > 0) setOrgID(orgs[0].id)
  }, [orgs, orgID])

  const { data: branding, isLoading: brandingLoading } = useQuery({
    queryKey: ['branding', orgID],
    queryFn: () => api.get<Branding>(`/api/v1/tenants/${orgID}/branding`),
    enabled: orgID !== '',
  })

  // The branding query is chained to the org query: it stays disabled until the
  // effect above picks an org. react-query reports isLoading=false for a
  // disabled query, so gating on brandingLoading alone paints the form with
  // empty defaults for one tick and then replaces it with the spinner. Users
  // see a flash of blank inputs; tests see the cards attach and immediately
  // detach. Treat "we know there is an org but have not asked for its branding
  // yet" as loading too.
  const waitingForOrg = orgID === '' && orgs.length > 0

  useEffect(() => {
    if (branding) setForm({ ...emptyBranding, ...branding })
  }, [branding])

  const save = useMutation({
    mutationFn: () => api.put(`/api/v1/tenants/${orgID}/branding`, form),
    onSuccess: () => toast({ title: 'Branding saved' }),
    onError: (e: unknown) => toast({ title: 'Save failed', description: String(e), variant: 'destructive' }),
  })

  const set = <K extends keyof Branding>(k: K, v: Branding[K]) => setForm((f) => ({ ...f, [k]: v }))

  if (orgsLoading) return <LoadingSpinner />

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <Palette className="h-6 w-6" /> Branding
        </h1>
        {orgs.length > 1 && (
          <Select value={orgID} onValueChange={setOrgID}>
            <SelectTrigger className="w-56"><SelectValue placeholder="Organization" /></SelectTrigger>
            <SelectContent>
              {orgs.map((o) => <SelectItem key={o.id} value={o.id}>{o.name}</SelectItem>)}
            </SelectContent>
          </Select>
        )}
      </div>

      {brandingLoading || waitingForOrg ? (
        <LoadingSpinner />
      ) : (
        <form
          className="space-y-6"
          onSubmit={(e) => { e.preventDefault(); save.mutate() }}
        >
          <Card>
            <CardHeader><CardTitle>Logo & colors</CardTitle></CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-2">
              <Field label="Logo URL"><Input value={form.logo_url} onChange={(e) => set('logo_url', e.target.value)} placeholder="https://…/logo.svg" /></Field>
              <Field label="Favicon URL"><Input value={form.favicon_url} onChange={(e) => set('favicon_url', e.target.value)} placeholder="https://…/favicon.ico" /></Field>
              <Field label="Background image URL"><Input value={form.background_image_url} onChange={(e) => set('background_image_url', e.target.value)} /></Field>
              <Field label="Primary color"><Input type="color" value={form.primary_color} onChange={(e) => set('primary_color', e.target.value)} /></Field>
              <Field label="Secondary color"><Input type="color" value={form.secondary_color} onChange={(e) => set('secondary_color', e.target.value)} /></Field>
              <Field label="Background color"><Input type="color" value={form.background_color} onChange={(e) => set('background_color', e.target.value)} /></Field>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Login & portal copy</CardTitle></CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-2">
              <Field label="Login page title"><Input value={form.login_page_title} onChange={(e) => set('login_page_title', e.target.value)} /></Field>
              <Field label="Portal title"><Input value={form.portal_title} onChange={(e) => set('portal_title', e.target.value)} /></Field>
              <Field label="Login page message" className="md:col-span-2">
                <textarea className="min-h-20 w-full rounded-md border bg-background p-2 text-sm" value={form.login_page_message} onChange={(e) => set('login_page_message', e.target.value)} />
              </Field>
              <Field label="Custom footer" className="md:col-span-2">
                <textarea className="min-h-16 w-full rounded-md border bg-background p-2 text-sm" value={form.custom_footer} onChange={(e) => set('custom_footer', e.target.value)} />
              </Field>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={form.powered_by_visible} onChange={(e) => set('powered_by_visible', e.target.checked)} />
                Show “Powered by OpenIDX”
              </label>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Custom CSS</CardTitle></CardHeader>
            <CardContent>
              <textarea className="min-h-40 w-full rounded-md border bg-background p-2 font-mono text-xs" value={form.custom_css} onChange={(e) => set('custom_css', e.target.value)} placeholder="/* custom CSS injected into the login & portal pages */" />
            </CardContent>
          </Card>

          <div className="flex justify-end">
            <Button type="submit" disabled={save.isPending || orgID === ''}>
              {save.isPending ? 'Saving…' : 'Save branding'}
            </Button>
          </div>
        </form>
      )}
    </div>
  )
}

function Field({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={className}>
      <label className="mb-1 block text-sm font-medium text-muted-foreground">{label}</label>
      {children}
    </div>
  )
}
