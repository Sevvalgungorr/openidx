import { ReactNode, useState } from 'react'
import {
  AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogFooter,
  AlertDialogTitle, AlertDialogDescription, AlertDialogAction, AlertDialogCancel,
} from './ui/alert-dialog'
import { Textarea } from './ui/textarea'
import { Label } from './ui/label'

interface ConfirmActionProps {
  title: string
  description: string
  impact?: ReactNode
  confirmLabel?: string
  destructive?: boolean
  requireReason?: boolean
  onConfirm: (reason?: string) => void | Promise<unknown>
  children: (open: () => void) => ReactNode
}

/**
 * The single component every destructive/privileged mutation routes through.
 * Security-critical actions pass `requireReason` so the confirmation is auditable.
 */
export function ConfirmAction({
  title, description, impact, confirmLabel = 'Confirm',
  destructive, requireReason, onConfirm, children,
}: ConfirmActionProps) {
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const disabled = busy || (!!requireReason && reason.trim() === '')

  const handleConfirm = async () => {
    setBusy(true)
    try {
      await onConfirm(requireReason ? reason.trim() : undefined)
      setOpen(false)
      setReason('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      {children(() => setOpen(true))}
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            <AlertDialogDescription>{description}</AlertDialogDescription>
          </AlertDialogHeader>
          {impact}
          {requireReason && (
            <div className="space-y-1">
              <Label htmlFor="confirm-reason">Reason (required)</Label>
              <Textarea
                id="confirm-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Why are you doing this? (recorded in the audit log)"
              />
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={disabled}
              onClick={(e) => { e.preventDefault(); void handleConfirm() }}
              className={destructive ? 'bg-red-600 hover:bg-red-700 focus:ring-red-600' : undefined}
            >
              {confirmLabel}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
