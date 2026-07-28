import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom'
import {
  Settings,
  LogOut,
  Shield,
  Menu,
  User,
  Network,
  ChevronDown,
  Search,
  X,
} from 'lucide-react'
import { useState, Suspense } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '../lib/auth'
import { api } from '../lib/api'
import { useAppStore } from '../lib/store'
import { roleLevel, ROLE_LEVELS } from '../lib/roles'
import { filterNavigation, type ViewMode } from '../config/navigation'
import { CommandPalette } from './command-palette'
import { NotificationBell } from './notification-bell'
import { TenantSelector } from './tenant-selector'
import { ErrorBoundary } from './error-boundary'
import { LoadingSpinner } from './ui/loading-spinner'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Avatar, AvatarFallback } from './ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu'

function ZitiStatusIndicator() {
  const navigate = useNavigate()
  const { data: zitiStatus } = useQuery({
    queryKey: ['ziti-status-header'],
    queryFn: () => api.get<{ enabled: boolean; controller_reachable?: boolean; services_count: number; identities_count: number }>('/api/v1/access/ziti/status'),
    refetchInterval: 30000,
  })
  const { data: browzerStatus } = useQuery({
    queryKey: ['browzer-status-header'],
    queryFn: () => api.get<{ enabled: boolean; configured?: boolean }>('/api/v1/access/ziti/browzer/status'),
    refetchInterval: 30000,
    enabled: !!zitiStatus?.enabled,
  })

  if (!zitiStatus?.enabled) return null

  return (
    <button
      onClick={() => navigate('/ziti-network')}
      className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg hover:bg-gray-100 transition-colors text-sm"
      title="Ziti Network Status"
    >
      <Network className="h-4 w-4 text-blue-600" />
      {zitiStatus.controller_reachable ? (
        <span className="h-2 w-2 rounded-full bg-green-500" />
      ) : (
        <span className="h-2 w-2 rounded-full bg-red-500" />
      )}
      {browzerStatus?.enabled && browzerStatus?.configured && (
        <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4 bg-blue-50 text-blue-700 border-blue-200">
          BrowZer
        </Badge>
      )}
    </button>
  )
}

// Console lenses: Administration is the full console, Management the operator
// slice, Reporting the auditor slice. Options above the user's level are
// hidden; users below operator get no switcher at all.
const VIEW_OPTIONS: { mode: ViewMode; label: string; minLevel: number }[] = [
  { mode: 'admin', label: 'Admin', minLevel: ROLE_LEVELS.admin },
  { mode: 'management', label: 'Manage', minLevel: ROLE_LEVELS.operator },
  { mode: 'reporting', label: 'Report', minLevel: ROLE_LEVELS.auditor },
]

function ViewModeSwitcher({ level }: { level: number }) {
  const { viewMode, setViewMode } = useAppStore()
  const options = VIEW_OPTIONS.filter((o) => level >= o.minLevel)
  if (level < ROLE_LEVELS.operator) return null

  return (
    <div
      className="flex rounded-lg border bg-gray-50 p-0.5"
      role="group"
      aria-label="Console view"
    >
      {options.map((option) => (
        <button
          key={option.mode}
          onClick={() => setViewMode(option.mode)}
          className={`flex-1 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
            viewMode === option.mode
              ? 'bg-white text-blue-700 shadow-sm'
              : 'text-gray-500 hover:text-gray-800'
          }`}
          aria-pressed={viewMode === option.mode}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}

export function Layout() {
  const { user, logout, hasRole } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [query, setQuery] = useState('')
  const { viewMode, collapsedDomains, toggleDomain } = useAppStore()
  const navigate = useNavigate()
  const location = useLocation()

  const roles = user?.roles ?? []
  const level = roleLevel(roles)
  // Only operator+ can narrow the console; everyone else gets their natural scope.
  const effectiveViewMode: ViewMode = level >= ROLE_LEVELS.operator ? viewMode : 'admin'
  const searching = query.trim().length > 0

  const groups = filterNavigation({ roles, viewMode: effectiveViewMode, query })

  const isPlatformAdmin = level >= ROLE_LEVELS.super_admin || hasRole('super_admin')
  const isAdmin = level >= ROLE_LEVELS.admin

  const initials = user?.name
    ?.split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase() || 'U'

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside
        className={`${
          sidebarOpen ? 'w-64' : 'w-16'
        } flex flex-col bg-white border-r transition-all duration-300`}
      >
        {/* Logo */}
        <div className="flex h-16 items-center justify-between px-4 border-b">
          {sidebarOpen && (
            <div className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-blue-600" />
              <span className="text-xl font-bold">OpenIDX</span>
            </div>
          )}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label="Toggle sidebar"
          >
            <Menu className="h-5 w-5" />
          </Button>
        </div>

        {/* View switcher + quick search */}
        {sidebarOpen && (
          <div className="space-y-2 px-4 pt-3">
            <ViewModeSwitcher level={level} />
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-gray-400" />
              <Input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search menu..."
                aria-label="Search menu"
                className="h-9 pl-8 pr-8 [&::-webkit-search-cancel-button]:hidden"
              />
              {searching ? (
                <button
                  onClick={() => setQuery('')}
                  className="absolute right-2 top-2.5 text-gray-400 hover:text-gray-600"
                  aria-label="Clear menu search"
                >
                  <X className="h-4 w-4" />
                </button>
              ) : (
                <kbd className="pointer-events-none absolute right-2 top-2 hidden rounded border bg-gray-50 px-1.5 py-0.5 text-[10px] font-medium text-gray-400 sm:block">
                  ⌘K
                </kbd>
              )}
            </div>
          </div>
        )}

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto p-4 space-y-1">
          {groups.length === 0 && sidebarOpen && (
            <p className="px-3 py-2 text-sm text-gray-400">No menu items match.</p>
          )}
          {groups.map((group, gIdx) => {
            // While searching, everything relevant stays visible.
            const collapsed = !searching && collapsedDomains.includes(group.id)
            return (
              <div key={group.id}>
                {group.label && sidebarOpen && (
                  <button
                    onClick={() => toggleDomain(group.id)}
                    className="mt-4 flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-xs font-semibold uppercase tracking-wider text-gray-500 hover:bg-gray-50 hover:text-gray-700"
                    aria-expanded={!collapsed}
                  >
                    <group.icon className="h-3.5 w-3.5" />
                    <span className="flex-1 text-left">{group.label}</span>
                    <ChevronDown
                      className={`h-3.5 w-3.5 transition-transform ${collapsed ? '-rotate-90' : ''}`}
                    />
                  </button>
                )}
                {!sidebarOpen && gIdx > 0 && <div className="my-2 border-t" />}
                {(!collapsed || !sidebarOpen) &&
                  group.sections.map((section, sIdx) => (
                    <div key={`${group.id}-${sIdx}`}>
                      {section.label && sidebarOpen && (
                        <div className="px-3 pt-2 pb-1 text-[11px] font-medium uppercase tracking-wider text-gray-400">
                          {section.label}
                        </div>
                      )}
                      {section.items.map((item) => (
                        <NavLink
                          key={item.href}
                          to={item.href}
                          title={sidebarOpen ? undefined : item.name}
                          className={({ isActive }) =>
                            `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                              isActive
                                ? 'bg-blue-50 text-blue-700'
                                : 'text-gray-600 hover:bg-gray-100'
                            }`
                          }
                        >
                          <item.icon className="h-5 w-5 flex-shrink-0" />
                          {sidebarOpen && <span className="text-sm">{item.name}</span>}
                        </NavLink>
                      ))}
                    </div>
                  ))}
              </div>
            )
          })}
        </nav>

        {/* User menu */}
        <div className="p-4 border-t">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className={`w-full ${sidebarOpen ? 'justify-start' : 'justify-center'}`}
              >
                <Avatar className="h-8 w-8">
                  <AvatarFallback>{initials}</AvatarFallback>
                </Avatar>
                {sidebarOpen && (
                  <div className="ml-3 text-left">
                    <p className="text-sm font-medium">{user?.name}</p>
                    <p className="text-xs text-gray-500">{user?.email}</p>
                  </div>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>
                <div>My Account</div>
                {user?.roles && user.roles.length > 0 && (
                  <div className="text-xs font-normal text-gray-500 mt-0.5">
                    {user.roles.join(', ')}
                  </div>
                )}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => navigate('/profile')}>
                <User className="mr-2 h-4 w-4" />
                My Profile
              </DropdownMenuItem>
              {isAdmin && (
                <DropdownMenuItem onClick={() => navigate('/settings')}>
                  <Settings className="mr-2 h-4 w-4" />
                  Settings
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={logout} className="text-red-600">
                <LogOut className="mr-2 h-4 w-4" />
                Logout
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar with tenant selector, status indicators and notification bell */}
        <header className="h-16 border-b bg-white flex items-center justify-end px-8 gap-4">
          {isPlatformAdmin && <TenantSelector />}
          {isAdmin && <ZitiStatusIndicator />}
          <NotificationBell />
        </header>
        <main className="flex-1 overflow-auto">
          <div className="p-8">
            {/* Keyed by route so a page-level render error shows a fallback
                instead of white-screening the whole console, and clears when
                the user navigates away. */}
            <ErrorBoundary key={location.pathname}>
              {/* Inner Suspense so a lazy page load spins only the content area —
                  the sidebar/header stay rendered (vs the app-level full-screen fallback). */}
              <Suspense
                fallback={
                  <div className="flex justify-center py-12">
                    <LoadingSpinner size="lg" />
                  </div>
                }
              >
                <Outlet />
              </Suspense>
            </ErrorBoundary>
          </div>
        </main>
      </div>

      {/* Global ⌘K / Ctrl-K jump-to-page palette (role-filtered). */}
      <CommandPalette />
    </div>
  )
}
