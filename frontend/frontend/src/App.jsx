import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Home from './pages/Home';
import About from './pages/About';
import Hotels from './pages/Hotels';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Admin from './pages/Admin';
import Contact from './pages/Contact';
import './App.css';
const API_URL = 'http://localhost:5000';
const App = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    checkAuth();
  }, []);
  const checkAuth = async () => {
    try {
      const res = await fetch(`${API_URL}/me`, {
        credentials: 'include'
      });

      if (res.ok) {
        const data = await res.json();
        setUser(data);
      }
    } catch (err) {
      console.log('Not logged in');
    } finally {
      setLoading(false);
    }
  };
  const login = (userData) => {
    setUser(userData);
  };
  const logout = async () => {
    try {
      await fetch(`${API_URL}/logout`, {
        method: 'POST',
        credentials: 'include'
      });
    } catch (err) {
      console.error('Logout error:', err);
    }
    setUser(null);
  };
  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-spinner"></div>
        <p>WORLD TOURISM

        </p>
      </div>
    );
  }
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home user={user} logout={logout} />} />
        <Route path="/about" element={<About user={user} logout={logout} />} />
        <Route path="/hotels" element={<Hotels user={user} logout={logout} />} />
        <Route path="/contact" element={<Contact user={user} logout={logout} />} />
        <Route path="/login" element={!user ? <Login login={login} /> : <Navigate to="/dashboard" />} />
        <Route path="/register" element={!user ? <Register login={login} /> : <Navigate to="/dashboard" />} />
        <Route path="/dashboard/*" element={user ? <Dashboard user={user} logout={logout} /> : <Navigate to="/login" />} />
        <Route path="/admin" element={user?.role === 'admin' ? <Admin user={user} logout={logout} /> : <Navigate to="/" />} />
      </Routes>
    </Router>
  );
};
export default App;