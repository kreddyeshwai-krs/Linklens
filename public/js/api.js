import { API_BASE } from './config.js';

const TOKEN_KEY = 'linklens_session_token';

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export async function apiRequest(endpoint, options = {}) {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  const token = getStoredToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  const contentType = res.headers.get('content-type') || '';
  let data = null;
  if (contentType.includes('application/json')) {
    data = await res.json();
  } else {
    data = await res.text();
  }

  if (!res.ok) {
    const errorMsg = data?.error?.message || (typeof data === 'string' ? data : 'API Request failed');
    const err = new Error(errorMsg);
    err.status = res.status;
    err.code = data?.error?.code || 'REQUEST_FAILED';
    err.details = data?.error?.details || null;

    // Handle token expiration or unauthenticated state
    if (res.status === 401 && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/signup')) {
      setStoredToken(null);
      if (!window.location.pathname.endsWith('login.html') && !window.location.pathname.endsWith('signup.html')) {
        window.location.href = '/login.html';
      }
    }

    throw err;
  }

  return data;
}

