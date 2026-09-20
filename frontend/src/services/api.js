// API Client with automatic JWT Token Injection
// Uses VITE_API_BASE_URL in production (statically replaced at build time),
// falls back to '/api' for development (Vite proxy) or same-origin deployments.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

class ApiClient {
  constructor() {
    this.token = localStorage.getItem('proctor_auth_token') || null;
  }

  setToken(token) {
    this.token = token;
    if (token) {
      localStorage.setItem('proctor_auth_token', token);
    } else {
      localStorage.removeItem('proctor_auth_token');
    }
  }

  getToken() {
    return this.token || localStorage.getItem('proctor_auth_token');
  }

  async request(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      // Auto-redirect on 401 for most endpoints, but let specific callers
      // (login, OTP verify, account delete) handle their own auth errors.
      const _isAuthEndpoint = endpoint === '/auth/login'
        || endpoint === '/auth/login/verify'
        || endpoint === '/auth/me';

      if (response.status === 401 && !_isAuthEndpoint) {
        // If unauthorized on a protected endpoint, clear token and redirect.
        this.setToken(null);
        if (!window.location.pathname.includes('/login') && !window.location.pathname.includes('/register')) {
          window.location.href = '/login';
          // Stop processing — the redirect handles the UX.
          return {};
        }
      }

      // Safely read text to prevent "Unexpected end of JSON input" on empty responses
      const text = await response.text();
      let data = null;

      if (text && text.trim().length > 0) {
        try {
          data = JSON.parse(text);
        } catch (parseErr) {
          data = { message: text };
        }
      } else {
        data = {};
      }

      if (!response.ok) {
        throw new Error(data.detail || data.message || `API request failed with status ${response.status}`);
      }
      return data;
    } catch (err) {
      console.error(`API Error [${endpoint}]:`, err);
      throw err;
    }
  }

  get(endpoint) {
    return this.request(endpoint, { method: 'GET' });
  }

  post(endpoint, body) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  put(endpoint, body) {
    return this.request(endpoint, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }

  delete(endpoint) {
    return this.request(endpoint, { method: 'DELETE' });
  }
}

export const api = new ApiClient();