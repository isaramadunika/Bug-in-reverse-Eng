import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { 
  ShieldAlert, 
  Terminal, 
  BookOpen, 
  FileText, 
  DollarSign, 
  HelpCircle, 
  LogOut, 
  User as UserIcon, 
  Layers,
  Sparkles
} from 'lucide-react';

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const isAuthPage = ['/login', '/register', '/forgot-password', '/reset-password', '/verify-email'].includes(location.pathname);

  return (
    <header className="sticky top-0 z-40 w-full border-b border-white/10 bg-navy-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand Logo */}
        <Link to="/" className="flex items-center space-x-3 group">
          <div className="h-9 w-9 rounded-lg bg-gradient-to-tr from-brand-600 to-cyan-400 flex items-center justify-center p-0.5 shadow-glow-cyan">
            <div className="h-full w-full bg-navy-950 rounded-[7px] flex items-center justify-center">
              <ShieldAlert className="h-5 w-5 text-brand-400 group-hover:scale-110 transition-transform" />
            </div>
          </div>
          <div className="flex flex-col">
            <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
              Reverse<span className="text-brand-400">Bug</span>
            </span>
            <span className="text-[10px] uppercase font-mono tracking-widest text-brand-400/80 -mt-1">
              SecIntel v1.0
            </span>
          </div>
        </Link>

        {/* Public Navigation */}
        {!user && !isAuthPage && (
          <nav className="hidden md:flex items-center space-x-1 lg:space-x-2 text-sm text-slate-300">
            <Link to="/features" className="px-3 py-1.5 rounded-md hover:text-white hover:bg-white/5 transition-colors">
              Features
            </Link>
            <Link to="/how-it-works" className="px-3 py-1.5 rounded-md hover:text-white hover:bg-white/5 transition-colors">
              How It Works
            </Link>
            <Link to="/methodology" className="px-3 py-1.5 rounded-md hover:text-white hover:bg-white/5 transition-colors">
              Methodology
            </Link>
            <Link to="/sample-report" className="px-3 py-1.5 rounded-md hover:text-white hover:bg-white/5 transition-colors">
              Sample Report
            </Link>
            <Link to="/pricing" className="px-3 py-1.5 rounded-md hover:text-white hover:bg-white/5 transition-colors">
              Pricing
            </Link>
            <Link to="/docs" className="px-3 py-1.5 rounded-md hover:text-white hover:bg-white/5 transition-colors">
              Docs
            </Link>
          </nav>
        )}

        {/* User / Auth CTAs */}
        <div className="flex items-center space-x-3">
          {user ? (
            <div className="flex items-center space-x-3">
              <Link
                to="/dashboard"
                className="hidden sm:flex items-center space-x-1.5 text-xs font-medium text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 px-3 py-1.5 rounded-md border border-white/10 transition-colors"
              >
                <Layers className="h-3.5 w-3.5 text-brand-400" />
                <span>Dashboard</span>
              </Link>
              <Link
                to="/projects"
                className="hidden sm:flex items-center space-x-1.5 text-xs font-medium text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 px-3 py-1.5 rounded-md border border-white/10 transition-colors"
              >
                <FileText className="h-3.5 w-3.5 text-cyan-400" />
                <span>Projects</span>
              </Link>
              <Link
                to="/settings"
                className="flex items-center space-x-2 text-xs text-slate-300 hover:text-white bg-navy-900 border border-white/10 px-3 py-1.5 rounded-md"
              >
                <UserIcon className="h-3.5 w-3.5 text-brand-400" />
                <span className="font-medium max-w-[100px] truncate">{user.display_name}</span>
                {user.platform_role !== 'user' && (
                  <span className="bg-brand-500/20 text-brand-300 px-1.5 py-0.5 text-[10px] rounded uppercase font-mono">
                    {user.platform_role.replace('_', ' ')}
                  </span>
                )}
              </Link>
              <button
                onClick={async () => {
                  await logout();
                  navigate('/login');
                }}
                className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-md transition-colors"
                title="Sign Out"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          ) : (
            <div className="flex items-center space-x-2 sm:space-x-3 text-sm">
              <Link
                to="/login"
                className="px-3.5 py-1.5 text-slate-300 hover:text-white transition-colors"
              >
                Sign In
              </Link>
              <Link
                to="/register"
                className="relative inline-flex items-center justify-center px-4 py-1.5 font-medium text-xs text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-md shadow-glow-cyan transition-all"
              >
                <Sparkles className="h-3.5 w-3.5 mr-1.5 text-cyan-200" />
                Start Free Analysis
              </Link>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
