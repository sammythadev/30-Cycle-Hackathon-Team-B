import axios, { AxiosHeaders } from 'axios';
import { useAuthStore } from '../auth/store';

// Use Next rewrite proxy in dev so cookies are same-origin and httpOnly cookies are sent/received correctly.
const api = axios.create({
  baseURL: '/api-proxy',
  withCredentials: true,
});

const shouldLogApi =
  process.env.NODE_ENV !== 'production' && process.env.NEXT_PUBLIC_API_LOGGING !== 'false';

type RequestMetadata = { requestId: string; startedAt: number };
type ConfigWithMetadata<T> = T & { metadata?: RequestMetadata };

const generateRequestId = () => {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const highResTime = typeof performance !== 'undefined' ? performance.now().toFixed(3) : Date.now();
  return `req_${Date.now()}_${highResTime}_${Math.random().toString(36).slice(2, 10)}`;
};

// Keep a lightweight interceptor for tenant header only. Do NOT add Authorization headers —
// auth is based on httpOnly cookies set by the backend.
api.interceptors.request.use((config) => {
  const requestId = generateRequestId();
  const startedAt = Date.now();
  const metadata = { requestId, startedAt };
  (config as ConfigWithMetadata<typeof config>).metadata = metadata;

  const { currentTenant } = useAuthStore.getState();
  if (currentTenant) {
    const headers = AxiosHeaders.from(config.headers);
    headers.set('X-Tenant-ID', currentTenant.id);
    config.headers = headers;
  }

  if (shouldLogApi) {
    const method = (config.method || 'get').toUpperCase();
    console.info('[api][request]', {
      requestId,
      method,
      url: config.url,
      baseURL: config.baseURL,
      hasTenantHeader: Boolean(currentTenant),
    });
  }

  return config;
});

let isRefreshing = false;
let failedQueue: Array<{ resolve: (val: unknown) => void; reject: (err: unknown) => void }> = [];

const processQueue = (error: unknown, value: unknown = null) => {
  failedQueue.forEach((p) => (error ? p.reject(error) : p.resolve(value)));
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => {
    const metadata = (response.config as ConfigWithMetadata<typeof response.config>).metadata;

    if (shouldLogApi) {
      console.info('[api][response]', {
        requestId: metadata?.requestId,
        method: (response.config.method || 'get').toUpperCase(),
        url: response.config.url,
        status: response.status,
        durationMs: metadata ? Date.now() - metadata.startedAt : undefined,
      });
    }

    return response;
  },
  async (error) => {
    const originalRequest = error.config || {};
    const metadata = (originalRequest as ConfigWithMetadata<typeof originalRequest>).metadata;
    const skipRedirect = originalRequest.headers?.['X-Skip-Auth-Redirect'] === 'true';

    if (shouldLogApi) {
      console.error('[api][error]', {
        requestId: metadata?.requestId,
        method: (originalRequest.method || 'get').toUpperCase(),
        url: originalRequest.url,
        status: error.response?.status,
        durationMs: metadata ? Date.now() - metadata.startedAt : undefined,
        message: error.message,
      });
    }

    if (error.response?.status === 401 && !originalRequest._retry && !originalRequest.url?.includes('/auth/')) {
      if (skipRedirect) return Promise.reject(error);

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(() => api(originalRequest));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Ask backend to rotate refresh token (backend will read ciap_refresh cookie)
        await axios.post('/api-proxy/auth/refresh', {}, { withCredentials: true });

        // Obtain current user/session info
        const verifyResp = await api.get('/auth/verify', { withCredentials: true });
        const user = verifyResp.data;
        useAuthStore.getState().setAuth(user);

        processQueue(null, null);
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        useAuthStore.getState().logout();
        if (typeof window !== 'undefined') window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  },
);

export default api;
