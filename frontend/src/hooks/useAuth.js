import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';

export function useAuth() {
  const [token, setToken] = useState(() => localStorage.getItem('token'));
  const [user, setUser] = useState(() => {
    try {
      const stored = localStorage.getItem('user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const handleStorage = (e) => {
      if (e.key === 'token') setToken(e.newValue);
      if (e.key === 'user') {
        try {
          setUser(e.newValue ? JSON.parse(e.newValue) : null);
        } catch {
          setUser(null);
        }
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, []);

  const login = useCallback(async (credentials) => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.login(credentials);
      if (data.access_token) {
        localStorage.setItem('token', data.access_token);
        setToken(data.access_token);
        const userData = { username: credentials.username };
        localStorage.setItem('user', JSON.stringify(userData));
        setUser(userData);
        return true;
      }
      throw new Error('Invalid response from server');
    } catch (err) {
      setError(err.message);
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const register = useCallback(async (data) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await api.register(data);
      if (response.access_token) {
        localStorage.setItem('token', response.access_token);
        setToken(response.access_token);
        const userData = { username: data.username };
        localStorage.setItem('user', JSON.stringify(userData));
        setUser(userData);
        return true;
      }
      throw new Error('Invalid response from server');
    } catch (err) {
      setError(err.message);
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser(null);
    window.location.hash = '#/';
    window.location.reload();
  }, []);

  return { user, token, login, register, logout, isLoading, error };
}
