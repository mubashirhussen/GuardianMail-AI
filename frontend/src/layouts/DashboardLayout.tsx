import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '../contexts/AuthContext';
import { dashboardService } from '../services/dashboard';
import {
  LayoutDashboard,
  Inbox,
  Radio,
  AlertTriangle,
  Link as LinkIcon,
  Paperclip,
  Target,
  Lock,
  Search,
  Sparkles,
  ShieldAlert,
  Sliders,
  Code2,
  Activity,
  FileText,
  FileCheck2,
  Bell,
  Laptop,
  Settings as SettingsIcon,
  ChevronLeft,
  ChevronRight,
  Shield,
  Command,
  ChevronDown,
  LogOut,
  Menu,
  X,
  ShieldCheck
} from 'lucide-react';
import { CommandPalette } from '../components/CommandPalette';
import { NotificationCenter } from '../components/NotificationCenter';

interface NavSection {
  title: string;
  items: Array<{
    name: string;
    path: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string;
  }>;
}

export const DashboardLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, logout } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  // Fetch real security score from backend
  const { data: overview } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: () => dashboardService.getOverview(),
    staleTime: 60_000,
    retry: false,
    enabled: !!user,
  });
  const securityScore: number = overview?.security_score ?? 0;
  const scoreLabel = securityScore >= 90 ? 'Excellent' : securityScore >= 75 ? 'Good' : securityScore >= 50 ? 'Fair' : 'At Risk';
  const scoreColor = securityScore >= 90 ? 'text-emerald-400' : securityScore >= 75 ? 'text-emerald-400' : securityScore >= 50 ? 'text-amber-400' : 'text-red-400';

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen(true);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const navSections: NavSection[] = [
    {
      title: 'OVERVIEW',
      items: [
        { name: 'Dashboard', path: '/', icon: LayoutDashboard },
        { name: 'Inbox', path: '/inbox', icon: Inbox },
      ],
    },
    {
      title: 'DETECTION',
      items: [
        { name: 'Phishing Detection', path: '/detection', icon: Radio },
        { name: 'Threat Center', path: '/threats', icon: AlertTriangle },
        { name: 'Link Scanner', path: '/links', icon: LinkIcon },
        { name: 'Attachment Scanner', path: '/attachments', icon: Paperclip },
        { name: 'Threat Hunting', path: '/security/threat-hunting', icon: Target },
      ],
    },
    {
      title: 'SECURITY',
      items: [
        { name: 'Privacy Guardian', path: '/privacy', icon: Lock },
        { name: 'Investigations', path: '/investigations', icon: Search },
        { name: 'Threat Intelligence', path: '/threat-intelligence', icon: Sparkles },
      ],
    },
    {
      title: 'RESPONSE',
      items: [
        { name: 'Response Operations', path: '/enterprise/response-operations', icon: ShieldAlert },
        { name: 'Governance Policies', path: '/settings/security/policies', icon: Sliders },
        { name: 'Detection Engineering', path: '/security/detections', icon: Code2 },
      ],
    },
    {
      title: 'OPERATIONS',
      items: [
        { name: 'Analytics', path: '/enterprise/response-effectiveness', icon: Activity },
        { name: 'Reports', path: '/reports', icon: FileText },
        { name: 'Audit & Evidence', path: '/enterprise/governance', icon: FileCheck2 },
      ],
    },
    {
      title: 'ACCOUNT',
      items: [
        { name: 'Devices & Sessions', path: '/devices', icon: Laptop },
        { name: 'Sessions', path: '/sessions', icon: ShieldCheck },
        { name: 'Settings', path: '/settings', icon: SettingsIcon },
      ],
    },
  ];

  const userName = user?.full_name?.split(' ')[0] || user?.email?.split('@')[0] || 'Analyst';
  const userRole = user?.role ? (user.role.charAt(0).toUpperCase() + user.role.slice(1)) : 'User';
  const userEmail = user?.email || 'Session loading';

  return (
    <div className="min-h-screen flex bg-[#080c15] text-slate-100 font-sans">
      {/* Command Palette Modal */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
      />

      {/* Mobile Drawer Overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/80 backdrop-blur-sm z-40 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Left Sidebar */}
      <aside
        className={`fixed md:static inset-y-0 left-0 z-50 flex flex-col bg-[#0d1322] border-r border-[#172136] shrink-0 transition-all duration-200 ${
          sidebarCollapsed ? 'w-20' : 'w-64'
        } ${sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}`}
      >
        {/* Brand Header */}
        <div className="h-16 flex items-center justify-between px-5 border-b border-[#172136]">
          <Link to="/" className="flex items-center gap-2.5 min-w-0">
            <div className="h-8 w-8 rounded-lg bg-[#2563eb] flex items-center justify-center text-white shrink-0 shadow-md shadow-blue-600/20">
              <Shield className="h-4 w-4 fill-white stroke-[#2563eb]" />
            </div>
            {!sidebarCollapsed && (
              <span className="font-bold text-sm text-white tracking-tight truncate">
                GuardianMail <span className="text-[#3b82f6]">AI</span>
              </span>
            )}
          </Link>
          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="hidden md:flex p-1 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-[#151e33]"
            title={sidebarCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {sidebarCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
          <button
            onClick={() => setSidebarOpen(false)}
            className="md:hidden p-1 text-slate-400 hover:text-slate-200"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Navigation Sections */}
        <nav className="flex-1 px-3 py-3 space-y-4 overflow-y-auto">
          {navSections.map((sec) => (
            <div key={sec.title} className="space-y-1">
              {!sidebarCollapsed && (
                <div className="px-3 text-[10px] font-bold tracking-wider text-slate-500 uppercase font-mono">
                  {sec.title}
                </div>
              )}
              {sec.items.map((item) => {
                const Icon = item.icon;
                const active = location.pathname === item.path;
                return (
                  <Link
                    key={item.name}
                    to={item.path}
                    onClick={() => setSidebarOpen(false)}
                    className={`flex items-center gap-3 px-3 py-2 rounded-lg text-xs transition-all ${
                      active
                        ? 'bg-[#18233c] text-white border border-[#2b3c63] font-semibold shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-[#121929]'
                    }`}
                    title={sidebarCollapsed ? item.name : undefined}
                  >
                    <Icon
                      className={`h-4 w-4 shrink-0 transition-colors ${
                        active ? 'text-[#3b82f6]' : 'text-slate-400'
                      }`}
                    />
                    {!sidebarCollapsed && (
                      <span className="truncate">{item.name}</span>
                    )}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>

        {/* User Footer Panel */}
        <div className="p-3 border-t border-[#172136] bg-[#0a0f1b]">
          {!sidebarCollapsed ? (
            <div className="flex items-center justify-between p-2 rounded-lg bg-[#0f1627] border border-[#1b253b]">
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="h-7 w-7 rounded-lg bg-[#2563eb] text-white font-bold text-xs flex items-center justify-center shrink-0">
                  {userName[0]?.toUpperCase() || 'M'}
                </div>
                <div className="min-w-0">
                  <span className="text-xs font-semibold text-slate-200 block truncate">{userName}</span>
                  <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
                    <span>{userRole}</span>
                    <span className="text-emerald-400 text-[9px] font-mono font-bold">• Secure</span>
                  </div>
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="p-1 text-slate-400 hover:text-red-400 rounded transition"
                title="Logout"
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </div>
          ) : (
            <div className="flex justify-center">
              <div className="h-7 w-7 rounded-lg bg-[#2563eb] text-white font-bold text-xs flex items-center justify-center">
                {userName[0]?.toUpperCase() || 'M'}
              </div>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header Bar */}
        <header className="h-16 bg-[#0d1322]/90 backdrop-blur-md border-b border-[#172136] px-6 flex items-center justify-between shrink-0 sticky top-0 z-30">
          <div className="flex items-center gap-3 flex-1 max-w-lg min-w-0">
            <button
              className="md:hidden p-2 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-[#151e33]"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu className="h-5 w-5" />
            </button>

            {/* Global Search Bar */}
            <button
              onClick={() => setCommandPaletteOpen(true)}
              className="w-full flex items-center justify-between px-3.5 py-2 bg-[#090e1a] hover:bg-[#101728] border border-[#1a243a] text-slate-400 text-xs rounded-lg transition"
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <Search className="h-3.5 w-3.5 text-slate-500" />
                <span className="truncate">Search emails, senders, threats...</span>
              </div>
              <kbd className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-[#060a12] border border-[#1c273e] text-[10px] font-mono text-slate-500">
                <Command className="h-2.5 w-2.5" /> K
              </kbd>
            </button>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {/* Status Pill */}
            <div className={`hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0e172a] border border-[#1e293b] text-xs font-semibold ${securityScore > 0 ? scoreColor : 'text-slate-500'}`}>
              <ShieldCheck className="h-3.5 w-3.5" />
              {securityScore > 0 ? (
                <span>{securityScore} {scoreLabel}</span>
              ) : (
                <span className="text-slate-500">Connecting...</span>
              )}
            </div>

            {/* Notification Center */}
            <div className="relative">
              <button
                onClick={() => setNotificationsOpen(!notificationsOpen)}
                className="relative p-2 rounded-lg bg-[#090e1a] hover:bg-[#121929] border border-[#1a243a] text-slate-300 transition"
              >
                <Bell className="h-4 w-4" />
                <span className="absolute top-1 right-1 h-3.5 w-3.5 rounded-full bg-red-500 text-white text-[9px] font-bold flex items-center justify-center">
                  1
                </span>
              </button>
              <NotificationCenter
                isOpen={notificationsOpen}
                onClose={() => setNotificationsOpen(false)}
              />
            </div>

            {/* User Dropdown */}
            <div className="relative">
              <button
                onClick={() => setUserDropdownOpen(!userDropdownOpen)}
                className="flex items-center gap-2 p-1.5 pr-2.5 rounded-lg bg-[#090e1a] hover:bg-[#121929] border border-[#1a243a] transition"
              >
                <div className="h-7 w-7 rounded-lg bg-[#2563eb] text-white font-bold text-xs flex items-center justify-center shadow-sm">
                  {userName[0]?.toUpperCase() || 'M'}
                </div>
                <div className="hidden md:block text-left">
                  <span className="text-xs font-semibold text-slate-200 block leading-tight truncate">
                    {userName}
                  </span>
                  <span className="text-[10px] text-slate-400 leading-tight">{userRole}</span>
                </div>
                <ChevronDown className="h-3 w-3 text-slate-500 ml-1" />
              </button>

              {userDropdownOpen && (
                <div className="absolute right-0 top-12 w-56 bg-[#0d1322] border border-[#1a243a] rounded-xl shadow-2xl p-2 z-50 animate-fade-in space-y-1">
                  <div className="p-2 border-b border-[#1a243a]">
                    <p className="text-xs font-semibold text-white">{userName}</p>
                    <p className="text-[11px] text-slate-400 font-mono truncate">{userEmail}</p>
                  </div>
                  <Link
                    to="/devices"
                    onClick={() => setUserDropdownOpen(false)}
                    className="block px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-[#141d2d] rounded-lg transition"
                  >
                    Devices &amp; Sessions
                  </Link>
                  <Link
                    to="/security-score"
                    onClick={() => setUserDropdownOpen(false)}
                    className="block px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-[#141d2d] rounded-lg transition"
                  >
                    Security Score
                  </Link>
                  <Link
                    to="/settings"
                    onClick={() => setUserDropdownOpen(false)}
                    className="block px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-[#141d2d] rounded-lg transition"
                  >
                    Account Settings
                  </Link>
                  <button
                    onClick={handleLogout}
                    className="w-full flex items-center gap-2 px-3 py-2 text-xs text-red-400 hover:bg-red-500/10 rounded-lg transition text-left"
                  >
                    <LogOut className="h-3.5 w-3.5" />
                    <span>Sign Out</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Dynamic Page Workspace */}
        <main className="flex-1 p-6 md:p-8 overflow-y-auto max-w-[1400px] w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
};
