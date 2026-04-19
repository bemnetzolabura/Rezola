import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Compass, Menu, X, User, LogOut } from 'lucide-react';
const Navbar = ({ user, logout, isSidebar = false }) => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const navigate = useNavigate();
  const handleLogout = () => {
    logout();
    navigate('/');
  };

  if (isSidebar) {
    return (
      <aside className="sidebar">
        <div className="sidebar-brand">
          <Compass size={32} />
          <span>WORLD TOURISM</span>
        </div>
        <nav className="sidebar-nav">
          <Link to="/dashboard" className="sidebar-link">Dashboard</Link>
          <Link to="/dashboard/bookings" className="sidebar-link">My Bookings</Link>
          <Link to="/dashboard/favorites" className="sidebar-link">Favorites</Link>
          <Link to="/dashboard/profile" className="sidebar-link">Profile</Link>
          {user?.role === 'admin' && (
            <Link to="/admin" className="sidebar-link">Admin Panel</Link>
          )}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-user">
            <div className="user-avatar">
              <User size={20} />
            </div>
            <span>{user?.fullName}</span>
          </div>
          <button className="sidebar-logout" onClick={handleLogout}>
            <LogOut size={18} />
            Logout
          </button>
        </div>
      </aside>
    );
  }
  return (
    <nav className="navbar">
      <Link to="/" className="nav-brand">
        <Compass size={28} />
        <span>WORLD TOURISM</span>
      </Link>
      <div className={`nav-links ${isMenuOpen ? 'open' : ''}`}>
        <Link to="/">Home</Link>
        <Link to="/about">About</Link>
        <Link to="/hotels">Hotels & Maps</Link>
        <Link to="/contact">Get in Touch</Link>
      </div>
      <div className="nav-actions">
        {user ? (
          <div className="user-menu">
            <Link to="/dashboard" className="user-avatar">
              <User size={20} />
            </Link>
            <button className="logout-btn" onClick={handleLogout}>
              <LogOut size={18} />
            </button>
          </div>
        ) : (
          <Link to="/login" className="login-btn">Sign In</Link>
        )}
        <button className="menu-toggle" onClick={() => setIsMenuOpen(!isMenuOpen)}>
          {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </div>
    </nav>
  );
};
export default Navbar;