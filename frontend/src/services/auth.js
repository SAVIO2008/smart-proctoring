import { api } from './api';

export const auth = {
  getUser() {
    const raw = localStorage.getItem('proctor_user');
    try {
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  },

  setUser(user) {
    if (user) {
      localStorage.setItem('proctor_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('proctor_user');
    }
  },

  isAuthenticated() {
    return !!api.getToken() && !!this.getUser();
  },

  isAdmin() {
    const user = this.getUser();
    return user?.role === 'admin';
  },

  isProfessor() {
    const user = this.getUser();
    return user?.role === 'professor';
  },

  isAdminOrProfessor() {
    const user = this.getUser();
    return user?.role === 'admin' || user?.role === 'professor';
  },

  async login(email, password) {
    // Phase 1: credential validation returns an OTP challenge (no JWT yet).
    const challenge = await api.post('/auth/login', { email, password });
    return challenge;
  },

  async verifyLoginOtp(challengeToken, otp) {
    // Phase 2: verify the emailed OTP and establish the authenticated session.
    const res = await api.post('/auth/login/verify', { challenge_token: challengeToken, otp });
    api.setToken(res.access_token);
    this.setUser(res.user);
    return res.user;
  },

  async register(data) {
    const res = await api.post('/auth/register', data);
    api.setToken(res.access_token);
    this.setUser(res.user);
    return res.user;
  },

  setSession(res) {
    api.setToken(res.access_token);
    this.setUser(res.user);
  },

  async fetchCurrentProfile() {
    const user = await api.get('/auth/me');
    this.setUser(user);
    return user;
  },

  async updateProfile(data) {
    const res = await api.put('/auth/me', data);
    if (res.access_token) {
      api.setToken(res.access_token);
    }
    if (res.user) {
      this.setUser(res.user);
    }
    return res;
  },

  logout() {
    // Best-effort server-side session revocation (the JWT's jti is invalidated).
    // Even if the network call fails, we clear local state so the user is logged out.
    try {
      api.post('/auth/logout', {}).catch(() => {});
    } catch (_) {
      // ignore
    }
    api.setToken(null);
    this.setUser(null);
    window.location.href = '/login';
  },

  async deleteAccount() {
    // Verify token exists before making the request.
    // Use distinct messages so we can tell whether the failure is
    // client-side (token missing) or server-side (backend rejected).
    const token = api.getToken();
    if (!token) {
      console.warn('[deleteAccount] tokenPresent=false — no JWT in storage');
      throw new Error('No active session. Please sign in again.');
    }
    console.warn('[deleteAccount] tokenPresent=true, sending DELETE /auth/me');
    const res = await api.delete('/auth/me');
    api.setToken(null);
    this.setUser(null);
    window.location.href = '/login';
    return res;
  }
};
