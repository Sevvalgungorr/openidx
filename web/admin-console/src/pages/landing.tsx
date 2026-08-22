import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../lib/auth'
import {
  Shield,
  Lock,
  Users,
  Globe,
  CheckCircle,
  ArrowRight,
  Zap,
  Eye,
  Network,
  FileCheck,
  Menu,
  X,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent } from '../components/ui/card'

interface Feature {
  icon: React.ReactNode
  title: string
  description: string
}

interface Stat {
  value: string
  label: string
}

const features: Feature[] = [
  {
    icon: <Shield className="h-6 w-6" />,
    title: 'Zero Trust Architecture',
    description: 'Never trust, always verify. Every access request is fully authenticated, authorized, and encrypted before granting access.',
  },
  {
    icon: <Users className="h-6 w-6" />,
    title: 'Identity & Access Management',
    description: 'Centralized user provisioning, role-based access control, and lifecycle management for all your applications.',
  },
  {
    icon: <Lock className="h-6 w-6" />,
    title: 'Multi-Factor Authentication',
    description: 'Support for TOTP, WebAuthn, push notifications, SMS, email, and hardware tokens for enhanced security.',
  },
  {
    icon: <Globe className="h-6 w-6" />,
    title: 'Single Sign-On (SSO)',
    description: 'One login to access all your applications with support for SAML, OIDC, and social identity providers.',
  },
  {
    icon: <Eye className="h-6 w-6" />,
    title: 'Real-time Monitoring',
    description: 'Comprehensive audit logging, session monitoring, and security analytics with instant alerts.',
  },
  {
    icon: <FileCheck className="h-6 w-6" />,
    title: 'Compliance & Governance',
    description: 'Automated access reviews, certification campaigns, and compliance reporting for SOC 2, HIPAA, and more.',
  },
  {
    icon: <Network className="h-6 w-6" />,
    title: 'API Gateway & Security',
    description: 'Powerful API gateway with rate limiting, IP whitelisting, and OAuth 2.0 token validation.',
  },
  {
    icon: <Zap className="h-6 w-6" />,
    title: 'High Performance',
    description: 'Built for scale with sub-millisecond latency and 99.99% uptime SLA guarantee.',
  },
]

const stats: Stat[] = [
  { value: '99.99%', label: 'Uptime SLA' },
  { value: '<50ms', label: 'Response Time' },
  { value: '50+', label: 'Security Features' },
  { value: '70%', label: 'Cost Savings' },
]

const integrations = [
  'Active Directory',
  'LDAP',
  'Okta',
  'Azure AD',
  'Google Workspace',
  'Salesforce',
  'Slack',
  'Microsoft Teams',
]

export function LandingPage() {
  const { isAuthenticated, login } = useAuth()
  const navigate = useNavigate()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20)
    }
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard', { replace: true })
    }
  }, [isAuthenticated, navigate])

  const handleLogin = () => {
    login()
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-white">
      {/* Navigation */}
      <nav
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled ? 'bg-background/95 backdrop-blur-sm shadow-md' : 'bg-transparent'
        }`}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <span className="text-xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                OpenIDX
              </span>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-8">
              <a href="#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Features
              </a>
              <a href="#integration" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Integrations
              </a>
              <a href="#pricing" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Pricing
              </a>
              <a href="#docs" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Documentation
              </a>
            </div>

            <div className="hidden md:flex items-center gap-4">
              <Button variant="ghost" size="sm" onClick={() => navigate('/login')}>
                Sign In
              </Button>
              <Button
                size="sm"
                className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                onClick={handleLogin}
              >
                Get Started Free
              </Button>
            </div>

            {/* Mobile menu button */}
            <button
              className="md:hidden p-2"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-background border-b">
            <div className="px-4 py-4 space-y-3">
              <a href="#features" className="block text-sm text-muted-foreground hover:text-foreground">
                Features
              </a>
              <a href="#integration" className="block text-sm text-muted-foreground hover:text-foreground">
                Integrations
              </a>
              <a href="#pricing" className="block text-sm text-muted-foreground hover:text-foreground">
                Pricing
              </a>
              <a href="#docs" className="block text-sm text-muted-foreground hover:text-foreground">
                Documentation
              </a>
              <div className="pt-3 space-y-2">
                <Button variant="ghost" size="sm" className="w-full" onClick={() => navigate('/login')}>
                  Sign In
                </Button>
                <Button
                  size="sm"
                  className="w-full bg-gradient-to-r from-blue-600 to-indigo-600"
                  onClick={handleLogin}
                >
                  Get Started Free
                </Button>
              </div>
            </div>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-4xl mx-auto">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-blue-50 text-blue-700 text-sm font-medium mb-6">
              <Zap className="h-4 w-4" />
              <span>Enterprise-Grade Security at 70% Less Cost</span>
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-foreground leading-tight mb-6">
              Zero Trust Access Platform for{' '}
              <span className="bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                Modern Enterprises
              </span>
            </h1>

            <p className="text-lg sm:text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
              OpenIDX provides complete Identity and Access Management with SSO, MFA, access governance,
              and compliance reporting. Open source, self-hosted, enterprise-ready.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12">
              <Button
                size="lg"
                className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-base px-8"
                onClick={handleLogin}
              >
                Start Free Trial
                <ArrowRight className="ml-2 h-5 w-5" />
              </Button>
              <Button size="lg" variant="outline" className="text-base px-8" onClick={() => navigate('/login')}>
                Live Demo
              </Button>
            </div>

            <div className="flex flex-wrap items-center justify-center gap-6 text-sm text-muted-foreground">
              <div className="flex items-center gap-1">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span>No credit card required</span>
              </div>
              <div className="flex items-center gap-1">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span>14-day free trial</span>
              </div>
              <div className="flex items-center gap-1">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span>Setup in minutes</span>
              </div>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-16">
            {stats.map((stat, index) => (
              <Card key={index} className="text-center">
                <CardContent className="pt-6">
                  <div className="text-2xl sm:text-3xl font-bold text-primary">{stat.value}</div>
                  <div className="text-sm text-muted-foreground mt-1">{stat.label}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4 sm:px-6 lg:px-8 bg-background">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-foreground mb-4">
              Complete Security Platform
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Everything you need to secure access to your applications, data, and infrastructure
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature, index) => (
              <Card key={index} className="border-none shadow-sm hover:shadow-md transition-shadow">
                <CardContent className="p-6">
                  <div className="h-12 w-12 rounded-lg bg-blue-100 text-primary flex items-center justify-center mb-4">
                    {feature.icon}
                  </div>
                  <h3 className="font-semibold text-lg mb-2">{feature.title}</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">{feature.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Integration Section */}
      <section id="integration" className="py-20 px-4 sm:px-6 lg:px-8 bg-muted">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl font-bold text-foreground mb-4">
              Integrates with Your Stack
            </h2>
            <p className="text-lg text-muted-foreground">
              Connect with 100+ enterprise applications and identity providers
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-4 max-w-4xl mx-auto">
            {integrations.map((integration, index) => (
              <div
                key={index}
                className="px-6 py-3 bg-background rounded-full shadow-sm text-sm font-medium text-foreground"
              >
                {integration}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <Card className="bg-gradient-to-r from-blue-600 to-indigo-700 border-0 text-white">
            <CardContent className="p-12 text-center">
              <h2 className="text-3xl font-bold mb-4">Ready to Secure Your Access?</h2>
              <p className="text-blue-100 mb-8 text-lg">
                Join thousands of organizations trusting OpenIDX for their identity and access management needs
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Button
                  size="lg"
                  variant="secondary"
                  className="bg-background text-primary hover:bg-muted px-8"
                  onClick={handleLogin}
                >
                  Start Free Trial
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
                <Button
                  size="lg"
                  variant="outline"
                  className="border-white text-white hover:bg-background/10 px-8"
                  onClick={() => navigate('/login')}
                >
                  Schedule Demo
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-4 sm:px-6 lg:px-8 bg-gray-900 text-muted-foreground">
        <div className="max-w-7xl mx-auto">
          <div className="grid md:grid-cols-4 gap-8 mb-8">
            <div>
              <div className="flex items-center gap-2 mb-4">
                <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center">
                  <Shield className="h-5 w-5 text-white" />
                </div>
                <span className="text-xl font-bold text-white">OpenIDX</span>
              </div>
              <p className="text-sm">
                Open source Zero Trust Access Platform for modern enterprises.
              </p>
            </div>

            <div>
              <h4 className="font-semibold text-white mb-4">Product</h4>
              <ul className="space-y-2 text-sm">
                <li><a href="#features" className="hover:text-white transition-colors">Features</a></li>
                <li><a href="#pricing" className="hover:text-white transition-colors">Pricing</a></li>
                <li><a href="#docs" className="hover:text-white transition-colors">Documentation</a></li>
                <li><a href="#" className="hover:text-white transition-colors">API Reference</a></li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold text-white mb-4">Company</h4>
              <ul className="space-y-2 text-sm">
                <li><a href="#" className="hover:text-white transition-colors">About</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Blog</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Careers</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Contact</a></li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold text-white mb-4">Legal</h4>
              <ul className="space-y-2 text-sm">
                <li><a href="#" className="hover:text-white transition-colors">Privacy Policy</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Terms of Service</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Security</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Compliance</a></li>
              </ul>
            </div>
          </div>

          <div className="border-t border-gray-800 pt-8 flex flex-col sm:flex-row items-center justify-between gap-4">
            <p className="text-sm">
              &copy; 2025 OpenIDX. All rights reserved.
            </p>
            <div className="flex items-center gap-4 text-sm">
              <span>Powered by</span>
              <a href="https://github.com/openidx" className="text-blue-400 hover:text-blue-300">
                OpenIDX
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default LandingPage
