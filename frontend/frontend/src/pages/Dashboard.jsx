import React, { useState, useEffect } from 'react';
import { Routes, Route, Navigate, Link } from 'react-router-dom';
import { LayoutDashboard, Calendar, Heart, User, ArrowRight } from 'lucide-react';
import Navbar from '../components/Navbar';

const API_URL = 'http://localhost:5000';

const Dashboard = ({ user, logout }) => {
  const [bookings, setBookings] = useState([]);
  const [favorites, setFavorites] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      // Fetch bookings
      const bookingsRes = await fetch(`${API_URL}/bookings`, {
        credentials: 'include'
      });
      if (bookingsRes.ok) {
        const bookingsData = await bookingsRes.json();
        setBookings(bookingsData);
      }

      // Fetch favorites
      const favRes = await fetch(`${API_URL}/favorites`, {
        credentials: 'include'
      });
      if (favRes.ok) {
        const favData = await favRes.json();
        setFavorites(favData);
      }
    } catch (err) {
      console.error('Error fetching data:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="dashboard-layout">
        <Navbar user={user} logout={logout} isSidebar={true} />
        <div className="dashboard-content">
          <div className="loading-screen">
            <div className="loading-spinner"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-layout">
      <Navbar user={user} logout={logout} isSidebar={true} />

      <div className="dashboard-content">
        <Routes>
          <Route path="/" element={<DashboardHome user={user} bookings={bookings} favorites={favorites} />} />
          <Route path="/bookings" element={<BookingsPage bookings={bookings} />} />
          <Route path="/favorites" element={<FavoritesPage favorites={favorites} setFavorites={setFavorites} />} />
          <Route path="/profile" element={<ProfilePage user={user} />} />
          <Route path="*" element={<Navigate to="/dashboard" />} />
        </Routes>
      </div>
    </div>
  );
};

const DashboardHome = ({ user, bookings, favorites }) => (
  <div className="dashboard-page">
    <div className="dashboard-welcome">
      <h1>Welcome back, {user?.fullName}</h1>
      <p>Here's what's happening with your trips</p>
    </div>

    <div className="dashboard-stats">
      <div className="stat-card">
        <Calendar size={32} />
        <div>
          <h3>{bookings.length}</h3>
          <p>Active Bookings</p>
        </div>
      </div>
      <div className="stat-card">
        <Heart size={32} />
        <div>
          <h3>{favorites.length}</h3>
          <p>Saved Places</p>
        </div>
      </div>
      <div className="stat-card">
        <User size={32} />
        <div>
          <h3>Member</h3>
          <p>Since 2024</p>
        </div>
      </div>
    </div>

    <div className="dashboard-sections">
      <div className="dash-section">
        <div className="section-header-row">
          <h2>Recent Bookings</h2>
          <Link to="/dashboard/bookings">View All <ArrowRight size={16} /></Link>
        </div>
        {bookings.length === 0 ? (
          <div className="empty-state">
            <Calendar size={48} />
            <p>No bookings yet</p>
            <Link to="/hotels" className="btn-secondary">Browse Hotels</Link>
          </div>
        ) : (
          <div className="mini-list">
            {bookings.slice(0, 3).map(booking => (
              <div key={booking.id} className="mini-item">
                <img src={booking.destinations?.image} alt="" />
                <div>
                  <h4>{booking.destinations?.name}</h4>
                  <p>{booking.check_in}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="dash-section">
        <div className="section-header-row">
          <h2>Recent Favorites</h2>
          <Link to="/dashboard/favorites">View All <ArrowRight size={16} /></Link>
        </div>
        {favorites.length === 0 ? (
          <div className="empty-state">
            <Heart size={48} />
            <p>No favorites yet</p>
            <Link to="/hotels" className="btn-secondary">Explore</Link>
          </div>
        ) : (
          <div className="mini-grid">
            {favorites.slice(0, 4).map(item => (
              <div key={item.id} className="mini-card">
                <img src={item.destinations?.image} alt={item.destinations?.name} />
                <span>{item.destinations?.name}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  </div>
);

const BookingsPage = ({ bookings }) => (
  <div className="dashboard-page">
    <h1>My Bookings</h1>
    {bookings.length === 0 ? (
      <div className="empty-state large">
        <Calendar size={64} />
        <p>No bookings yet</p>
        <Link to="/hotels" className="btn-primary">Find Hotels</Link>
      </div>
    ) : (
      <div className="bookings-list">
        {bookings.map(booking => (
          <div key={booking.id} className="booking-card-large">
            <img src={booking.destinations?.image} alt="" />
            <div className="booking-info-large">
              <h3>{booking.destinations?.name}</h3>
              <p>{booking.destinations?.country}</p>
              <span className="status-badge confirmed">{booking.status}</span>
              <p className="booking-date">Check-in: {booking.check_in}</p>
            </div>
          </div>
        ))}
      </div>
    )}
  </div>
);

const FavoritesPage = ({ favorites, setFavorites }) => {
  const removeFavorite = async (destinationId) => {
    try {
      await fetch(`${API_URL}/favorites/${destinationId}`, {
        method: 'DELETE',
        credentials: 'include'
      });
      setFavorites(prev => prev.filter(f => f.destination_id !== destinationId));
    } catch (err) {
      console.error('Error removing favorite:', err);
    }
  };

  return (
    <div className="dashboard-page">
      <h1>My Favorites</h1>
      {favorites.length === 0 ? (
        <div className="empty-state large">
          <Heart size={64} />
          <p>No favorites yet</p>
          <Link to="/hotels" className="btn-primary">Discover Places</Link>
        </div>
      ) : (
        <div className="favorites-grid-large">
          {favorites.map(item => (
            <div key={item.id} className="favorite-card-large">
              <img src={item.destinations?.image} alt={item.destinations?.name} />
              <div className="favorite-info">
                <h3>{item.destinations?.name}</h3>
                <p>{item.destinations?.country}</p>
                <button
                  className="remove-btn"
                  onClick={() => removeFavorite(item.destination_id)}
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const ProfilePage = ({ user }) => (
  <div className="dashboard-page">
    <h1>My Profile</h1>
    <div className="profile-card">
      <div className="profile-avatar">
        <User size={64} />
      </div>
      <div className="profile-info">
        <h2>{user?.fullName}</h2>
        <p>{user?.email}</p>
        <span className="role-badge">{user?.role}</span>
      </div>
    </div>
  </div>
);

export default Dashboard;