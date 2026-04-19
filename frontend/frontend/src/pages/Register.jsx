import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';

const API_URL = 'http://localhost:5000';

const Register = ({ login }) => {
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    password: '',
    birthday: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(formData)
      });

      const data = await response.json();

      if (!data.error) {
        // Auto login after register
        const loginRes = await fetch(`${API_URL}/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            email: formData.email,
            password: formData.password
          })
        });

        const loginData = await loginRes.json();
        if (loginData.success) {
          login(loginData.user);
          navigate('/dashboard');
        }
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <div className="auth-visual">
          <div className="auth-image"></div>
          <div className="auth-overlay">
            <h2>Join Us</h2>
            <p>Start your adventure today</p>
          </div>
        </div>

        <div className="auth-form-wrapper">
          <form onSubmit={handleSubmit} className="auth-form">
            <h2>Create Account</h2>

            {error && <div className="error-message">{error}</div>}

            <div className="form-group">
              <label>Full Name</label>
              <input
                type="text"
                required
                value={formData.fullName}
                onChange={(e) => setFormData({ ...formData, fullName: e.target.value })}
              />
            </div>

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

            <div className="form-group">
              <label>Birthday</label>
              <input
                type="date"
                value={formData.birthday}
                onChange={(e) => setFormData({ ...formData, birthday: e.target.value })}
              />
            </div>

            <button type="submit" className="btn-primary full-width" disabled={loading}>
              {loading ? 'Creating...' : 'Create Account'}
              <ArrowRight size={20} />
            </button>

            <p className="auth-switch">
              Already have an account?
              <Link to="/login">Sign in</Link>
            </p>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Register;