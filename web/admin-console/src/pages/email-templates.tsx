import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { Mail, Eye, RotateCcw, Save, Palette } from 'lucide-react'

interface EmailTemplate {
  id: string
  name: string
  slug: string
  subject: string
  html_body: string
  text_body: string
  category: string
  variables: string[]
  enabled: boolean
  updated_by: string | null
  created_at: string
  updated_at: string
}

interface EmailBranding {
  id?: string
  org_id?: string
  logo_url: string
  primary_color: string
  accent_color: string
  header_text: string
  footer_text: string
}

const categoryLabels: Record<string, string> = {
  authentication: 'Authentication',
  lifecycle: 'Lifecycle',
  general: 'General',
}

export function EmailTemplatesPage() {
  const queryClient = useQueryClient()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [editSubject, setEditSubject] = useState('')
  const [editHtml, setEditHtml] = useState('')
  const [editText, setEditText] = useState('')
  const [previewHtml, setPreviewHtml] = useState('')
  const [showBranding, setShowBranding] = useState(false)
  const [branding, setBranding] = useState<EmailBranding>({
    logo_url: '', primary_color: '#1e40af', accent_color: '#3b82f6', header_text: '', footer_text: '',
  })

  const { data: templatesData, isLoading, isError, error } = useQuery({
    queryKey: ['email-templates'],
    queryFn: () => api.get<{ data: EmailTemplate[] }>('/api/v1/email-templates'),
  })

  const { data: brandingData } = useQuery({
    queryKey: ['email-branding'],
    queryFn: () => api.get<EmailBranding>('/api/v1/email-branding'),
  })

  // Sync branding data when loaded
  if (brandingData && brandingData.primary_color && branding.primary_color === '#1e40af' && brandingData.primary_color !== '#1e40af') {
    setBranding(brandingData)
  }

  const updateMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string; subject: string; html_body: string; text_body: string }) =>
      api.put(`/api/v1/email-templates/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-templates'] })
    },
  })

  const resetMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/email-templates/${id}/reset`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-templates'] })
      setSelectedId(null)
    },
  })

  const brandingMutation = useMutation({
    mutationFn: (data: EmailBranding) => api.put('/api/v1/email-branding', data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['email-branding'] }),
  })

  const handleSelectTemplate = (t: EmailTemplate) => {
    setSelectedId(t.id)
    setEditSubject(t.subject)
    setEditHtml(t.html_body)
    setEditText(t.text_body || '')
    setPreviewHtml('')
  }

  const handleSave = () => {
    if (!selectedId) return
    updateMutation.mutate({ id: selectedId, subject: editSubject, html_body: editHtml, text_body: editText })
  }

  const handlePreview = async () => {
    if (!selectedId) return
    const result = await api.post<{ html: string }>(`/api/v1/email-templates/${selectedId}/preview`, {})
    setPreviewHtml(result.html)
  }

  if (isLoading) return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  if (isError) return <QueryError error={error} resource="email templates" />

  const templates = templatesData?.data || []
  const selectedTemplate = templates.find(t => t.id === selectedId)

  // Group by category
  const grouped: Record<string, EmailTemplate[]> = {}
  templates.forEach(t => {
    const cat = t.category || 'general'
    if (!grouped[cat]) grouped[cat] = []
    grouped[cat].push(t)
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Email Templates</h1>
          <p className="text-muted-foreground">Customize email notifications sent to users</p>
        </div>
        <Button variant="outline" onClick={() => setShowBranding(!showBranding)}>
          <Palette className="h-4 w-4 mr-2" />{showBranding ? 'Hide Branding' : 'Branding Settings'}
        </Button>
      </div>

      {/* Branding Settings */}
      {showBranding && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><Palette className="h-5 w-5" />Email Branding</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Logo URL</label>
                <input className="w-full border rounded px-3 py-2 mt-1 text-sm" placeholder="https://example.com/logo.png"
                  value={branding.logo_url} onChange={e => setBranding({ ...branding, logo_url: e.target.value })} />
              </div>
              <div>
                <label className="text-sm font-medium">Header Text</label>
                <input className="w-full border rounded px-3 py-2 mt-1 text-sm" placeholder="OpenIDX"
                  value={branding.header_text} onChange={e => setBranding({ ...branding, header_text: e.target.value })} />
              </div>
              <div>
                <label className="text-sm font-medium">Primary Color</label>
                <div className="flex gap-2 mt-1">
                  <input type="color" value={branding.primary_color} onChange={e => setBranding({ ...branding, primary_color: e.target.value })} />
                  <input className="flex-1 border rounded px-3 py-2 text-sm" value={branding.primary_color}
                    onChange={e => setBranding({ ...branding, primary_color: e.target.value })} />
                </div>
              </div>
              <div>
                <label className="text-sm font-medium">Accent Color</label>
                <div className="flex gap-2 mt-1">
                  <input type="color" value={branding.accent_color} onChange={e => setBranding({ ...branding, accent_color: e.target.value })} />
                  <input className="flex-1 border rounded px-3 py-2 text-sm" value={branding.accent_color}
                    onChange={e => setBranding({ ...branding, accent_color: e.target.value })} />
                </div>
              </div>
            </div>
            <div>
              <label className="text-sm font-medium">Footer Text</label>
              <textarea className="w-full border rounded px-3 py-2 mt-1 text-sm h-16"
                value={branding.footer_text} onChange={e => setBranding({ ...branding, footer_text: e.target.value })} />
            </div>
            <Button onClick={() => brandingMutation.mutate(branding)} disabled={brandingMutation.isPending}>
              <Save className="h-4 w-4 mr-2" />{brandingMutation.isPending ? 'Saving...' : 'Save Branding'}
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Template List */}
        <Card className="lg:col-span-1">
          <CardHeader><CardTitle className="flex items-center gap-2"><Mail className="h-5 w-5" />Templates</CardTitle></CardHeader>
          <CardContent>
            {Object.entries(grouped).map(([cat, tmpls]) => (
              <div key={cat} className="mb-4">
                <p className="text-xs font-semibold text-muted-foreground uppercase mb-2">{categoryLabels[cat] || cat}</p>
                <div className="space-y-1">
                  {tmpls.map(t => (
                    <div key={t.id}
                      className={`p-2 rounded cursor-pointer text-sm ${selectedId === t.id ? 'bg-blue-50 border border-blue-200' : 'hover:bg-muted'}`}
                      onClick={() => handleSelectTemplate(t)}>
                      <div className="flex items-center justify-between">
                        <span className="font-medium">{t.name}</span>
                        <Badge variant={t.enabled ? 'default' : 'secondary'} className="text-xs">{t.enabled ? 'Active' : 'Disabled'}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">{t.slug}</p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Template Editor */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>{selectedTemplate ? `Edit: ${selectedTemplate.name}` : 'Select a template to edit'}</span>
              {selectedTemplate && (
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={handlePreview}><Eye className="h-3 w-3 mr-1" />Preview</Button>
                  <Button size="sm" variant="outline" onClick={() => resetMutation.mutate(selectedId!)}><RotateCcw className="h-3 w-3 mr-1" />Reset</Button>
                  <Button size="sm" onClick={handleSave} disabled={updateMutation.isPending}>
                    <Save className="h-3 w-3 mr-1" />{updateMutation.isPending ? 'Saving...' : 'Save'}
                  </Button>
                </div>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {selectedTemplate ? (
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium">Subject</label>
                  <input className="w-full border rounded px-3 py-2 mt-1 text-sm"
                    value={editSubject} onChange={e => setEditSubject(e.target.value)} />
                </div>

                {selectedTemplate.variables?.length > 0 && (
                  <div>
                    <label className="text-sm font-medium">Available Variables</label>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {selectedTemplate.variables.map(v => (
                        <Badge key={v} variant="outline" className="text-xs cursor-pointer hover:bg-blue-50"
                          onClick={() => setEditHtml(editHtml + `{{.${v}}}`)}>
                          {'{{.'}{v}{'}}'}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <label className="text-sm font-medium">HTML Body</label>
                  <textarea className="w-full border rounded px-3 py-2 mt-1 text-sm font-mono h-48"
                    value={editHtml} onChange={e => setEditHtml(e.target.value)} />
                </div>

                <div>
                  <label className="text-sm font-medium">Plain Text Body</label>
                  <textarea className="w-full border rounded px-3 py-2 mt-1 text-sm font-mono h-24"
                    value={editText} onChange={e => setEditText(e.target.value)} />
                </div>

                {/* Preview */}
                {previewHtml && (
                  <div>
                    <label className="text-sm font-medium">Preview</label>
                    <div className="border rounded p-4 mt-1 bg-background" dangerouslySetInnerHTML={{ __html: previewHtml }} />
                  </div>
                )}
              </div>
            ) : (
              <div className="py-12 text-center text-muted-foreground">
                <Mail className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                <p>Select a template from the left to edit</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
