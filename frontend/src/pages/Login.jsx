import React, { useState } from 'react';
import { auth } from '../services/auth';
import { Shield, KeyRound, Mail, ArrowRight, UserCheck, AlertCircle, Lock, RotateCcw } from 'lucide-react';

export default function Login({ onLoginSuccess, navigateToRegister, navigateToAdminRegister }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  // OTP challenge state (after valid credentials)
  const [challenge, setChallenge] = useState(null);
  const [otp, setOtp] = useState('');
  const [verifying, setVerifying] = useState(false);

  const handleSubmit = async (e) => {
    e?.preventDefault();
    setError(null);
    setLoading(true);

    try {
      // Phase 1: validate email+password, get OTP challenge.
      const challenge = await auth.login(email, password);
      setChallenge(challenge);
      setOtp('');
    } catch (err) {
      setError('Unable to sign in. Please check your email and password and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e) => {
    e?.preventDefault();
    setError(null);
    setVerifying(true);

    try {
      // Phase 2: verify the emailed code and establish the session.
      const user = await auth.verifyLoginOtp(challenge.challenge_token, otp.trim());
      onLoginSuccess(user);
    } catch (err) {
      setError('Invalid or expired verification code. Please try again.');
    } finally {
      setVerifying(false);
    }
  };

  const handleBackToLogin = () => {
    setChallenge(null);
    setOtp('');
    setError(null);
  };

  const handleQuickDemo = (role) => {
    if (role === 'admin') {
      setEmail('admin@proctor.edu');
      setPassword('Admin@123');
    } else {
      setEmail('student@proctor.edu');
      setPassword('Student@123');
    }
    setChallenge(null);
    setOtp('');
    setError(null);
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem',
      backgroundColor: 'var(--bg-primary)',
      backgroundImage: 'radial-gradient(ellipse at 50% 10%, rgba(59, 130, 246, 0.12), transparent 70%)'
    }}>
      <div className="glass-card" style={{ maxWidth: '440px', width: '100%', padding: '2.25rem' }}>
        {/* Logo & Header */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{
            display: 'inline-flex',
            padding: '0.75rem',
            borderRadius: '12px',
            backgroundColor: 'rgba(59, 130, 246, 0.15)',
            color: 'var(--accent-blue)',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            marginBottom: '1rem'
          }}>
            <Shield size={32} />
          </div>
          <h2 style={{ fontSize: '1.6rem', marginBottom: '0.35rem' }}>Smart Examination Proctor</h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            AI-Powered Computer Vision Proctoring Platform
          </p>
        </div>

        {error && (
          <div style={{
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            padding: '0.75rem',
            borderRadius: '8px',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            marginBottom: '1.25rem'
          }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {challenge ? (
          /* -------- Stage 2: OTP verification -------- */
          <form onSubmit={handleVerifyOtp}>
            <div style={{
              textAlign: 'center',
              marginBottom: '1.25rem',
              padding: '0.9rem',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              borderRadius: '8px',
              border: '1px solid rgba(59, 130, 246, 0.25)'
            }}>
              <Lock size={18} style={{ color: 'var(--accent-blue)', marginBottom: '0.4rem' }} />
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: 0 }}>
                A verification code has been sent to <strong style={{ color: 'var(--text-primary)' }}>{challenge.email}</strong>.
                Enter it below to complete sign-in.
              </p>
            </div>

            <div className="form-group">
              <label className="form-label">Verification Code</label>
              <input
                type="text"
                required
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
                className="form-input"
                placeholder="Enter 6-digit code"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                style={{ textAlign: 'center', letterSpacing: '0.4rem', fontSize: '1.25rem', fontWeight: 600 }}
              />
            </div>

            <button
              type="submit"
              disabled={verifying}
              className="btn btn-primary"
              style={{ width: '100%', marginTop: '0.5rem', padding: '0.8rem' }}
            >
              {verifying ? 'Verifying...' : 'Verify & Sign In'} <ArrowRight size={16} />
            </button>

            <button
              type="button"
              onClick={handleBackToLogin}
              className="btn btn-secondary btn-sm"
              style={{ width: '100%', marginTop: '0.75rem' }}
            >
              <RotateCcw size={13} /> Back to sign in
            </button>
          </form>
        ) : (
          /* -------- Stage 1: email + password -------- */
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Institutional Email</label>
              <div style={{ position: 'relative' }}>
                <input
                  type="email"
                  required
                  className="form-input"
                  placeholder="name@proctor.edu"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
                <Mail size={16} style={{ position: 'absolute', left: '0.9rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <div style={{ position: 'relative' }}>
                <input
                  type="password"
                  required
                  autoComplete="current-password"
                  className="form-input"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
                <KeyRound size={16} style={{ position: 'absolute', left: '0.9rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
              style={{ width: '100%', marginTop: '0.5rem', padding: '0.8rem' }}
            >
              {loading ? 'Authenticating...' : 'Sign In to Portal'} <ArrowRight size={16} />
            </button>
          </form>
        )}

        {/* 1-Click Demo Credentials — only in development/demo mode */}
        {!challenge && import.meta.env.VITE_DEMO_ENABLED === 'true' && (
          <div style={{ marginTop: '1.5rem', paddingTop: '1.25rem', borderTop: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center', marginBottom: '0.6rem' }}>
              QUICK VIVA DEMO CREDENTIALS
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              <button
                type="button"
                onClick={() => handleQuickDemo('admin')}
                className="btn btn-secondary btn-sm"
                style={{ fontSize: '0.75rem' }}
              >
                <UserCheck size={13} color="#f59e0b" /> Chief Proctor
              </button>
              <button
                type="button"
                onClick={() => handleQuickDemo('student')}
                className="btn btn-secondary btn-sm"
                style={{ fontSize: '0.75rem' }}
              >
                <UserCheck size={13} color="#3b82f6" /> Student Candidate
              </button>
            </div>
          </div>
        )}

        {/* Register Links */}
        {!challenge && (
          <>
            <div style={{ textAlign: 'center', marginTop: '1.25rem', fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
              New student candidate?{' '}
              <button
                onClick={navigateToRegister}
                style={{ background: 'none', border: 'none', color: 'var(--accent-blue)', cursor: 'pointer', fontWeight: 600 }}
              >
                Register Profile
              </button>
            </div>
            <div style={{ textAlign: 'center', marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Administrator?{' '}
              <button
                onClick={navigateToAdminRegister}
                style={{ background: 'none', border: 'none', color: '#f59e0b', cursor: 'pointer', fontWeight: 600, fontSize: '0.75rem' }}
              >
                Admin Registration
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}