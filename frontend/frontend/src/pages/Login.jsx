import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';

const API_URL = 'http://localhost:5000';

const Login = ({ login }) => {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(formData)
      });

      const data = await response.json();

      if (data.success) {
        login(data.user);
        navigate('/dashboard');
      } else {
        setError(data.message || 'Login failed');
      }
    } catch (err) {
      setError('Server error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    // For demo - in production use Google OAuth
    window.open(`${API_URL}/auth/google`, '_self');
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <div className="auth-visual">
          <div className="auth-image"></div>
          <div className="auth-overlay">
            <h2>Welcome Back</h2>
            <p>Sign in to continue your journey</p>
          </div>
        </div>

        <div className="auth-form-wrapper">
          <form onSubmit={handleSubmit} className="auth-form">
            <h2>Sign In</h2>

            {error && <div className="error-message">{error}</div>}

            <div className="form-group">
              <label>Email</label>
              <input
                type="email"
                required
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                required
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              />
            </div>

            <button type="submit" className="btn-primary full-width" disabled={loading}>
              {loading ? 'Signing in...' : 'Sign In'}
              <ArrowRight size={20} />
            </button>

            <div className="auth-divider">
              <span>or continue with</span>
            </div>

            <button type="button" className="btn-google" onClick={handleGoogleLogin}>
              <img src="https://www.svgrepo.com/show/475656/google-color.svg" alt="Google" />
              Google
            </button>

            <p className="auth-switch">
              Don't have an account?
              <Link to="/register">Create one</Link>
            </p>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;