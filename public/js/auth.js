import { apiRequest, getStoredToken, setStoredToken } from './api.js';

let currentUser = null;

export async function getCurrentUser(forceRefresh = false) {
  if (currentUser && !forceRefresh) return currentUser;

  const token = getStoredToken();
  if (!token) return null;

  try {
    const res = await apiRequest('/auth/me');
    currentUser = res.user;
    return currentUser;
  } catch (err) {
    currentUser = null;
    return null;
  }
}

export async function login(email, password) {
  const res = await apiRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  setStoredToken(res.token);
  currentUser = res.user;
  return res.user;
}

export async function signup(email, password, displayName) {
  const res = await apiRequest('/auth/signup', {
    method: 'POST',
    body: JSON.stringify({ email, password, displayName }),
  });
  setStoredToken(res.token);
  currentUser = res.user;
  return res.user;
}

export function logout() {
  setStoredToken(null);
  currentUser = null;
  window.location.href = '/login.html';
}

export async function requireAuthPage() {
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = '/login.html';
    return null;
  }
  return user;
}

export async function requireAdminPage() {
  const user = await requireAuthPage();
  if (!user) return null;
  if (user.role !== 'admin') {
    window.location.href = '/dashboard.html';
    return null;
  }
  return user;
}

