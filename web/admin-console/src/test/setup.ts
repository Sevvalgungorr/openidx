import '@testing-library/jest-dom'
import { vi, afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'
import userEvent, { PointerEventsCheckLevel } from '@testing-library/user-event'

// Cleanup after each test
afterEach(() => {
  cleanup()
})

// Default user-event to skip the pointer-events check. Under React 19, Radix's
// Dialog/Select/DropdownMenu set `pointer-events: none` on the trigger (or body)
// while their portal is mounting; user-event then refuses to click with
// "element has pointer-events: none", failing tests that were green on React 18.
// The visual guard is irrelevant in jsdom, so disable it globally by wrapping
// userEvent.setup to inject pointerEventsCheck: Never unless a test overrides it.
const baseUserEventSetup = userEvent.setup.bind(userEvent)
;(userEvent as { setup: typeof userEvent.setup }).setup = ((options = {}) =>
  baseUserEventSetup({
    pointerEventsCheck: PointerEventsCheckLevel.Never,
    ...options,
  })) as typeof userEvent.setup

// Mock IntersectionObserver
class MockIntersectionObserver {
  observe = vi.fn()
  disconnect = vi.fn()
  unobserve = vi.fn()
}

Object.defineProperty(window, 'IntersectionObserver', {
  writable: true,
  value: MockIntersectionObserver,
})

// Mock matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock ResizeObserver
class MockResizeObserver {
  observe = vi.fn()
  disconnect = vi.fn()
  unobserve = vi.fn()
}

Object.defineProperty(window, 'ResizeObserver', {
  writable: true,
  value: MockResizeObserver,
})

// Mock scrollTo
window.scrollTo = vi.fn() as unknown as typeof window.scrollTo

// Mock crypto.getRandomValues for PKCE
Object.defineProperty(window, 'crypto', {
  value: {
    getRandomValues: (arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * 256)
      }
      return arr
    },
    subtle: {
      digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    },
  },
})

// Mock hasPointerCapture for Radix UI components (jsdom lacks pointer-capture APIs)
if (!HTMLElement.prototype.hasPointerCapture) {
  HTMLElement.prototype.hasPointerCapture = vi.fn(() => false)
}
if (!HTMLElement.prototype.setPointerCapture) {
  HTMLElement.prototype.setPointerCapture = vi.fn()
}
if (!HTMLElement.prototype.releasePointerCapture) {
  HTMLElement.prototype.releasePointerCapture = vi.fn()
}

// Mock getAnimations for Radix UI (jsdom lacks the Web Animations API)
if (!Element.prototype.getAnimations) {
  Element.prototype.getAnimations = vi.fn(() => [])
}

// Mock scrollIntoView for Radix UI Select. jsdom (unlike happy-dom) does not
// implement Element.prototype.scrollIntoView, and @radix-ui/react-select calls
// it when the listbox mounts, which otherwise throws an unhandled rejection
// ("candidate?.scrollIntoView is not a function") and fails Select-based tests.
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = vi.fn()
}

// Mock pointer events for Radix UI
if (!window.PointerEvent) {
  ;(window as any).PointerEvent = class PointerEvent extends MouseEvent {
    constructor(
      type: string,
      init: MouseEventInit & { pointerId?: number; pointerType?: string }
    ) {
      super(type, init)
    }
  } as any
}

// Guard against a focus-trap recursion under React 19 + jsdom. Radix's
// focus-scope (used by Dialog/Select/DropdownMenu) listens for `focusin` and,
// when focus escapes the trapped container, calls focus() to pull it back. In
// jsdom, focus() dispatches `focusin` synchronously, so if the "last focused"
// element is itself outside the container (common right before unmount, or
// across React 19's changed event timing) the handler re-enters without end
// and blows the stack -- which cascaded into an OOM for the whole suite. Wrap
// HTMLElement.prototype.focus with a reentrancy guard so a focus() triggered
// while another focus() is already on the stack becomes a no-op.
const nativeFocus = HTMLElement.prototype.focus
let focusInProgress = false
HTMLElement.prototype.focus = function patchedFocus(
  this: HTMLElement,
  options?: FocusOptions
) {
  if (focusInProgress) return
  focusInProgress = true
  try {
    nativeFocus.call(this, options)
  } finally {
    focusInProgress = false
  }
}

// Mock HTMLCanvasElement.getContext. jsdom does not implement canvas, so any
// component that reaches for a 2D context (xterm.js in the terminal/PAM pages)
// throws "Not implemented: HTMLCanvasElement.prototype.getContext". Under the
// React 19 + Vitest 4 RPC path that error object serialized into a runaway
// recursion that OOM'd the whole run, so stub the context to a no-op surface.
if (typeof HTMLCanvasElement !== 'undefined') {
  HTMLCanvasElement.prototype.getContext = vi.fn(() => ({
    fillRect: vi.fn(),
    clearRect: vi.fn(),
    getImageData: vi.fn((_x: number, _y: number, w: number, h: number) => ({
      data: new Array(w * h * 4),
    })),
    putImageData: vi.fn(),
    createImageData: vi.fn(() => ({ data: [] })),
    setTransform: vi.fn(),
    drawImage: vi.fn(),
    save: vi.fn(),
    fillText: vi.fn(),
    restore: vi.fn(),
    beginPath: vi.fn(),
    moveTo: vi.fn(),
    lineTo: vi.fn(),
    closePath: vi.fn(),
    stroke: vi.fn(),
    translate: vi.fn(),
    scale: vi.fn(),
    rotate: vi.fn(),
    arc: vi.fn(),
    fill: vi.fn(),
    measureText: vi.fn(() => ({ width: 0 })),
    transform: vi.fn(),
    rect: vi.fn(),
    clip: vi.fn(),
  })) as unknown as typeof HTMLCanvasElement.prototype.getContext
}

