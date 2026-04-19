import React, { useState, useEffect } from 'react';
import { Plus, Edit, Trash2 } from 'lucide-react';
import Navbar from '../components/Navbar';

const API_URL = 'http://localhost:5000';

const Admin = ({ user, logout }) => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await fetch(`${API_URL}/admin/users`, {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      }
    } catch (err) {
      console.error('Error fetching users:', err);
    } finally {
      setLoading(false);
    }
  };

  const stats = {
    totalUsers: users.length,
    totalBookings: 156,
    revenue: 89432
  };

  if (loading) {
    return (
      <div className="admin-layout">
        <Navbar user={user} logout={logout} isSidebar={true} />
        <div className="admin-content">
          <div className="loading-screen">
            <div className="loading-spinner"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-layout">
      <Navbar user={user} logout={logout} isSidebar={true} />

      <div className="admin-content">
        <div className="admin-header">
          <h1>Admin Dashboard</h1>
          <button className="btn-primary">
            <Plus size={20} />
            Add Destination
          </button>
        </div>

        <div className="admin-stats">
          <div className="admin-stat-card">
            <h4>Total Users</h4>
            <span className="stat-value">{stats.totalUsers}</span>
          </div>
          <div className="admin-stat-card">
            <h4>Total Bookings</h4>
            <span className="stat-value">{stats.totalBookings}</span>
          </div>
          <div className="admin-stat-card">
            <h4>Revenue</h4>
            <span className="stat-value">${stats.revenue.toLocaleString()}</span>
          </div>
        </div>

        <div className="admin-table-container">
          <h2>All Users</h2>
          <table className="admin-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Provider</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td>{u.id}</td>
                  <td>{u.full_name}</td>
                  <td>{u.email}</td>
                  <td>
                    <span className={`role-pill ${u.role}`}>{u.role}</span>
                  </td>
                  <td>{u.provider}</td>
                  <td>
                    <button className="action-btn edit">
                      <Edit size={16} />
                    </button>
                    <button className="action-btn delete">
                      <Trash2 size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Admin;