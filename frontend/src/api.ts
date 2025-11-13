import axios from 'axios';
import { getToken } from './token';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE ?? 'http://localhost:8080',
  withCredentials: false
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers = config.headers ?? ({} as import('axios').AxiosRequestHeaders);
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export function registerUser(payload) {
  return api.post('/api/register', payload).then((r) => r.data);
}

export function requestLogin(payload) {
  return api.post('/api/login/request', payload).then((r) => r.data);
}

export function pollLoginStatus(loginId) {
  return api.get('/api/login/status', { params: { login_id: loginId } }).then((r) => r.data);
}

export function fetchProfile() {
  return api.get('/api/me').then((r) => r.data);
}

export function startDeviceLink(payload: { email: string }) {
  return api.post('/api/device/link/start', payload).then((r) => r.data);
}
