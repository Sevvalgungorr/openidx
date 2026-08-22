import { useEffect, useState } from 'react'
import { Smartphone, Plus, Trash2, Loader2, Bell, QrCode } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { useToast } from '../hooks/use-toast'
import { api, PushMFADevice, PushMFAEnrollment } from '../lib/api'

export function PushDevicesPage() {
  const { toast } = useToast()
  const [devices, setDevices] = useState<PushMFADevice[]>([])
  const [loading, setLoading] = useState(true)
  const [showEnrollForm, setShowEnrollForm] = useState(false)
  const [enrolling, setEnrolling] = useState(false)
  const [deleting, setDeleting] = useState<string | null>(null)

  // QR self-enrollment state (Google/MS-Authenticator style).
  const [qrPayload, setQrPayload] = useState<string | null>(null)
  const [qrExpiresAt, setQrExpiresAt] = useState<number>(0)
  const [qrLoading, setQrLoading] = useState(false)

  // Enrollment form state
  const [deviceName, setDeviceName] = useState('')
  const [deviceModel, setDeviceModel] = useState('')
  const [platform, setPlatform] = useState<'ios' | 'android' | 'web'>('web')
  const [deviceToken, setDeviceToken] = useState('')

  const fetchDevices = async () => {
    try {
      setLoading(true)
      const data = await api.getPushDevices()
      setDevices(data || [])
    } catch {
      toast({ title: 'Error', description: 'Failed to load push devices', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDevices()
  }, [])

  const handleEnroll = async () => {
    if (!deviceName.trim() || !deviceToken.trim()) return

    try {
      setEnrolling(true)
      const enrollment: PushMFAEnrollment = {
        device_token: deviceToken,
        platform,
        device_name: deviceName,
        device_model: deviceModel || undefined,
      }
      await api.registerPushDevice(enrollment)
      toast({ title: 'Success', description: 'Push device enrolled successfully' })
      setShowEnrollForm(false)
      setDeviceName('')
      setDeviceModel('')
      setDeviceToken('')
      fetchDevices()
    } catch {
      toast({ title: 'Error', description: 'Failed to enroll push device', variant: 'destructive' })
    } finally {
      setEnrolling(false)
    }
  }

  // startQrEnrollment mints an enrollment ticket and shows the QR the
  // authenticator app scans. We then poll the device list so the card can
  // auto-dismiss once the phone completes enrollment.
  const startQrEnrollment = async () => {
    try {
      setQrLoading(true)
      setShowEnrollForm(false)
      const ticket = await api.startPushEnrollment()
      setQrPayload(ticket.qr_payload)
      setQrExpiresAt(Date.now() + ticket.expires_in * 1000)
    } catch {
      toast({ title: 'Error', description: 'Failed to start QR enrollment', variant: 'destructive' })
    } finally {
      setQrLoading(false)
    }
  }

  const cancelQrEnrollment = () => {
    setQrPayload(null)
    setQrExpiresAt(0)
  }

  // While a QR is showing, poll for the new device and expire the ticket.
  useEffect(() => {
    if (!qrPayload) return
    const before = devices.length
    const interval = setInterval(async () => {
      if (Date.now() > qrExpiresAt) {
        setQrPayload(null)
        toast({ title: 'QR expired', description: 'Generate a new code to enroll.' })
        return
      }
      try {
        const data = await api.getPushDevices()
        if ((data?.length || 0) > before) {
          setDevices(data || [])
          setQrPayload(null)
          toast({ title: 'Device enrolled', description: 'Your authenticator is now registered.' })
        }
      } catch {
        // transient; keep polling until expiry
      }
    }, 3000)
    return () => clearInterval(interval)
  }, [qrPayload, qrExpiresAt, devices.length, toast])

  const handleDelete = async (deviceId: string) => {
    try {
      setDeleting(deviceId)
      await api.deletePushDevice(deviceId)
      toast({ title: 'Success', description: 'Push device removed' })
      setDevices(devices.filter(d => d.id !== deviceId))
    } catch {
      toast({ title: 'Error', description: 'Failed to remove push device', variant: 'destructive' })
    } finally {
      setDeleting(null)
    }
  }

  const getPlatformLabel = (p: string) => {
    switch (p) {
      case 'ios': return 'iOS'
      case 'android': return 'Android'
      case 'web': return 'Web'
      default: return p
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Push Notification Devices</h1>
          <p className="text-muted-foreground">Manage devices for push notification MFA verification</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={startQrEnrollment} disabled={qrLoading || !!qrPayload}>
            {qrLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <QrCode className="mr-2 h-4 w-4" />}
            Enroll via Authenticator App
          </Button>
          <Button variant="outline" onClick={() => setShowEnrollForm(true)} disabled={showEnrollForm}>
            <Plus className="mr-2 h-4 w-4" /> Manual Enroll
          </Button>
        </div>
      </div>

      {qrPayload && (
        <Card>
          <CardHeader>
            <CardTitle>Scan with your authenticator app</CardTitle>
            <CardDescription>
              Open the OpenIDX Authenticator on your phone, tap &ldquo;Scan QR&rdquo;, and point it at this code.
              The device registers itself automatically. The code expires in a few minutes.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-4">
            <div className="rounded-lg bg-background p-4">
              <QRCodeSVG value={qrPayload} size={200} />
            </div>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Waiting for your device to enroll…
            </div>
            <Button variant="ghost" onClick={cancelQrEnrollment}>Cancel</Button>
          </CardContent>
        </Card>
      )}

      {showEnrollForm && (
        <Card>
          <CardHeader>
            <CardTitle>Enroll Push Notification Device</CardTitle>
            <CardDescription>
              Register a device to receive push notification MFA challenges
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="device-name">Device Name</Label>
                <Input
                  id="device-name"
                  placeholder="e.g., My iPhone, Work Phone"
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  disabled={enrolling}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="device-model">Device Model (optional)</Label>
                <Input
                  id="device-model"
                  placeholder="e.g., iPhone 15, Pixel 8"
                  value={deviceModel}
                  onChange={(e) => setDeviceModel(e.target.value)}
                  disabled={enrolling}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="platform">Platform</Label>
                <select
                  id="platform"
                  className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  value={platform}
                  onChange={(e) => setPlatform(e.target.value as 'ios' | 'android' | 'web')}
                  disabled={enrolling}
                >
                  <option value="web">Web</option>
                  <option value="ios">iOS</option>
                  <option value="android">Android</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="device-token">Device Token</Label>
                <Input
                  id="device-token"
                  placeholder="Push notification token"
                  value={deviceToken}
                  onChange={(e) => setDeviceToken(e.target.value)}
                  disabled={enrolling}
                />
              </div>
            </div>
            <div className="flex gap-2">
              <Button onClick={handleEnroll} disabled={enrolling || !deviceName.trim() || !deviceToken.trim()}>
                {enrolling ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Enrolling...
                  </span>
                ) : (
                  'Enroll Device'
                )}
              </Button>
              <Button variant="outline" onClick={() => setShowEnrollForm(false)} disabled={enrolling}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="h-5 w-5" />
            Registered Push Devices
          </CardTitle>
          <CardDescription>
            {devices.length} device{devices.length !== 1 ? 's' : ''} enrolled
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : devices.length === 0 ? (
            <div className="text-center py-8">
              <Bell className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground">No push notification devices enrolled yet.</p>
              <p className="text-sm text-muted-foreground mt-1">
                Enroll a device to use push notifications for MFA verification.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {devices.map((device) => (
                <div
                  key={device.id}
                  className="flex items-center justify-between p-4 border rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-green-100 rounded-lg">
                      <Smartphone className="h-5 w-5 text-green-600" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{device.device_name}</p>
                        <span className="text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground">
                          {getPlatformLabel(device.platform)}
                        </span>
                        {device.enabled ? (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700">Active</span>
                        ) : (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700">Disabled</span>
                        )}
                        {device.trusted && (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-blue-100 text-blue-700">Trusted</span>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {device.device_model && <>{device.device_model} &middot; </>}
                        Enrolled {new Date(device.created_at).toLocaleDateString()}
                        {device.last_used_at && (
                          <> &middot; Last used {new Date(device.last_used_at).toLocaleDateString()}</>
                        )}
                      </p>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-red-600 hover:text-red-700 hover:bg-red-50"
                    onClick={() => handleDelete(device.id)}
                    disabled={deleting === device.id}
                  >
                    {deleting === device.id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
