import { Button } from './ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from './ui/dialog'

interface SessionExpiredDialogProps {
  open: boolean
  onSignIn: () => void
}

/**
 * Non-dismissable modal shown when a request 401s mid-session. Gives the user one
 * clear path back (re-authenticate) instead of leaving them on masked-empty pages.
 */
export function SessionExpiredDialog({ open, onSignIn }: SessionExpiredDialogProps) {
  if (!open) return null
  return (
    <Dialog open={open}>
      <DialogContent
        className="[&>button]:hidden"
        onPointerDownOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>Your session ended</DialogTitle>
          <DialogDescription>Please sign in again to continue.</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button onClick={onSignIn}>Sign in</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
