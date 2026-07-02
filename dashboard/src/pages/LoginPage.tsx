import { useState, FormEvent } from 'react';
import { useAuth } from '../context/AuthContext';
import { useAuditLog } from '../context/AuditLogContext';
import { Zap, Eye, EyeOff, Shield, Lock, User, AlertCircle, Loader2 } from 'lucide-react';

export function LoginPage() {
  const { login } = useAuth();
  const { log } = useAuditLog();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [attempts, setAttempts] = useState(0);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) { setError('Enter username and password'); return; }
    if (attempts >= 5) { setError('Too many failed attempts. Refresh the page to try again.'); return; }

    setLoading(true);
    setError('');

    // Simulate network delay
    await new Promise((r) => setTimeout(r, 600));

    const result = await login(username.trim(), password);
    setLoading(false);

    if (result.ok) {
      log(username.trim(), 'LOGIN', `Successful login from browser session`, 'info');
    } else {
      const next = attempts + 1;
      setAttempts(next);
      setError(next >= 5
        ? 'Account locked after 5 failed attempts. Refresh to reset.'
        : `${result.error} (${5 - next} attempts remaining)`);
      log(username.trim(), 'LOGIN', `Failed login attempt ${next}`, 'warning');
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      {/* Background grid */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:64px_64px]" />

      <div className="relative w-full max-w-md">
        {/* Card */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden shadow-2xl shadow-black/50">
          {/* Top accent */}
          <div className="h-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500" />

          <div className="p-8">
            {/* Logo */}
            <div className="flex flex-col items-center mb-8">
              <div className="w-16 h-16 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-2xl flex items-center justify-center shadow-lg shadow-cyan-500/30 mb-4">
                <Zap className="w-9 h-9 text-white" />
              </div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                InfiniteX WAF
              </h1>
              <p className="text-gray-500 text-sm mt-1">Security Console — Sign In</p>
            </div>

            {/* Security badges */}
            <div className="flex justify-center gap-3 mb-6">
              {[
                { icon: Shield, label: 'Protected' },
                { icon: Lock,   label: 'Encrypted' },
              ].map(({ icon: Icon, label }) => (
                <div key={label} className="flex items-center gap-1.5 text-xs text-gray-500 bg-gray-800/50 px-3 py-1.5 rounded-full border border-gray-700">
                  <Icon className="w-3 h-3 text-cyan-500" />
                  {label}
                </div>
              ))}
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Username */}
              <div>
                <label className="text-xs text-gray-400 block mb-1.5">Username</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="admin"
                    autoComplete="username"
                    disabled={loading || attempts >= 5}
                    className="w-full bg-gray-800 border border-gray-700 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500 transition-colors disabled:opacity-50"
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label className="text-xs text-gray-400 block mb-1.5">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                  <input
                    type={showPw ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    autoComplete="current-password"
                    disabled={loading || attempts >= 5}
                    className="w-full bg-gray-800 border border-gray-700 rounded-xl pl-10 pr-10 py-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500 transition-colors disabled:opacity-50"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw((s) => !s)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                    tabIndex={-1}
                  >
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Error */}
              {error && (
                <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded-xl px-3 py-2.5 text-sm text-red-400">
                  <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                  {error}
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={loading || attempts >= 5}
                className="w-full flex items-center justify-center gap-2 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all shadow-lg shadow-cyan-500/20"
              >
                {loading ? <><Loader2 className="w-4 h-4 animate-spin" /> Signing in…</> : 'Sign In'}
              </button>
            </form>
          </div>

          {/* Footer */}
          <div className="px-8 py-4 bg-gray-950/50 border-t border-gray-800 text-center">
            <p className="text-xs text-gray-600">Session expires after 1 hour of inactivity</p>
          </div>
        </div>
      </div>
    </div>
  );
}
