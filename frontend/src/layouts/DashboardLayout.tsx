import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import {
  LayoutDashboard,
  Mail,
  ShieldAlert,
  FileText,
  Laptop,
  Activity,
  User,
  LogOut,
  Menu,
  X,
  Sun,
  Moon,
  ShieldCheck
} from 'lucide-react';

export const DashboardLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, logout, isAdminOrAnalyst } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Email Scans', path: '/emails', icon: Mail },
    { name: 'Incident Center', path: '/incidents', icon: ShieldAlert },
    { name: 'Report Logs', path: '/reports', icon: FileText },
    { name: 'Devices & Sessions', path: '/devices', icon: Laptop },
  ];

  // Admin and SOC routes
  if (isAdminOrAnalyst()) {
    navItems.push({ name: 'System Diagnostics', path: '/system-health', icon: Activity });
  }

  const userRoleColor = {
    admin: 'bg-red-500/10 text-red-500 border border-red-500/20',
    soc_analyst: 'bg-yellow-500/10 text-yellow-500 border border-yellow-500/20',
    security_analyst: 'bg-blue-500/10 text-blue-500 border border-blue-500/20',
    user: 'bg-green-500/10 text-green-500 border border-green-500/20',
  }[user?.role || 'user'];

  return (
    <div className="min-h-screen flex bg-slate-950 text-slate-100 font-sans">
      {/* Sidebar for Desktop */}
      <aside className="hidden md:flex flex-col w-64 bg-slate-900 border-r border-slate-800 shrink-0">
        {/* Brand Header */}
        <div className="h-16 flex items-center gap-3 px-6 border-b border-slate-800">
          <ShieldCheck className="h-7 w-7 text-cyan-500 animate-pulse" />
          <span className="font-bold text-lg tracking-wider text-slate-50 bg-gradient-to-r from-slate-50 to-cyan-400 bg-clip-text text-transparent">
            GuardianMail AI
          </span>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-6 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = location.pathname === item.path;
            return (
              <Link
                key={item.name}
                to={item.path}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-150 ${
                  active
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className="h-4 w-4" />
                {item.name}
              </Link>
            );
          })}
        </nav>

        {/* User Card footer */}
        <div className="p-4 border-t border-slate-800">
          <div className="flex items-center gap-3 mb-3">
            <div className="h-9 w-9 rounded-full bg-slate-800 flex items-center justify-center font-bold text-cyan-400">
              {user?.full_name?.charAt(0) || 'U'}
            </div>
            <div className="overflow-hidden">
              <h4 className="text-xs font-semibold text-slate-200 truncate">{user?.full_name}</h4>
              <p className="text-[10px] text-slate-500 truncate">{user?.email}</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-medium text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-all border border-transparent hover:border-red-500/20"
          >
            <LogOut className="h-3.5 w-3.5" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main Container */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 flex items-center justify-between px-6 bg-slate-900/50 backdrop-blur-md border-b border-slate-800 shrink-0">
          {/* Left panel mobile menu control */}
          <div className="flex items-center gap-4">
            <button
              onClick={() => setSidebarOpen(true)}
              className="md:hidden p-2 rounded-lg text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="hidden md:flex items-center gap-2 text-xs text-slate-500 font-medium">
              <span className="h-2 w-2 rounded-full bg-green-500 animate-ping" />
              API Status: Active
            </div>
          </div>

          {/* Right actions */}
          <div className="flex items-center gap-4">
            {/* Role Badge */}
            {user && (
              <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full ${userRoleColor}`}>
                {user.role}
              </span>
            )}

            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              className="p-2 rounded-lg text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            >
              {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>

            {/* Profile link */}
            <Link
              to="/profile"
              className="p-2 rounded-lg text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            >
              <User className="h-4 w-4" />
            </Link>
          </div>
        </header>

        {/* Content Body */}
        <main className="flex-1 overflow-y-auto bg-slate-950 p-6 md:p-8">
          <div className="max-w-7xl mx-auto space-y-6">
            {children}
          </div>
        </main>
      </div>

      {/* Mobile Sidebar overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden bg-slate-950/60 backdrop-blur-sm">
          <div className="relative w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
            <div className="absolute top-4 right-4">
              <button
                onClick={() => setSidebarOpen(false)}
                className="p-2 rounded-lg text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Logo */}
            <div className="h-16 flex items-center gap-3 px-6 border-b border-slate-800">
              <ShieldCheck className="h-7 w-7 text-cyan-500" />
              <span className="font-bold text-lg text-slate-50">GuardianMail AI</span>
            </div>

            {/* Nav */}
            <nav className="flex-1 px-4 py-6 space-y-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = location.pathname === item.path;
                return (
                  <Link
                    key={item.name}
                    to={item.path}
                    onClick={() => setSidebarOpen(false)}
                    className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                      active
                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    {item.name}
                  </Link>
                );
              })}
            </nav>

            {/* Footer */}
            <div className="p-4 border-t border-slate-800">
              <div className="flex items-center gap-3 mb-3">
                <div className="h-9 w-9 rounded-full bg-slate-800 flex items-center justify-center font-bold text-cyan-400">
                  {user?.full_name?.charAt(0) || 'U'}
                </div>
                <div className="overflow-hidden">
                  <h4 className="text-xs font-semibold text-slate-200 truncate">{user?.full_name}</h4>
                  <p className="text-[10px] text-slate-500 truncate">{user?.email}</p>
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="w-full flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-medium text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-all border border-transparent hover:border-red-500/20"
              >
                <LogOut className="h-3.5 w-3.5" />
                Sign Out
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
