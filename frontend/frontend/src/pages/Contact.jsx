import React, { useState } from 'react';
import { Send } from 'lucide-react';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

const API_URL = 'http://localhost:5000';

const Contact = ({ user, logout }) => {
    const [formData, setFormData] = useState({ name: '', email: '', message: '' });
    const [sent, setSent] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            await fetch(`${API_URL}/contact`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });
            setSent(true);
            setFormData({ name: '', email: '', message: '' });
        } catch (err) {
            console.error('Error sending message:', err);
        }
    };

    return (
        <div className="contact-page">
            <Navbar user={user} logout={logout} />

            <div className="contact-header">
                <h1>Get in Touch</h1>
                <p>We'd love to hear from you</p>
            </div>

            <div className="contact-content">
                <div className="contact-form">
                    {sent ? (
                        <div className="empty-state">
                            <h3>Message Sent!</h3>
                            <p>We'll get back to you soon.</p>
                            <button className="btn-secondary" onClick={() => setSent(false)}>Send Another</button>
                        </div>
                    ) : (
                        <form onSubmit={handleSubmit}>
                            <div className="form-group">
                                <label>Name</label>
                                <input
                                    type="text"
                                    required
                                    value={formData.name}
                                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
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
                                <label>Message</label>
                                <textarea
                                    rows="5"
                                    required
                                    value={formData.message}
                                    onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                                ></textarea>
                            </div>
                            <button type="submit" className="btn-primary full-width">
                                <Send size={20} />
                                Send Message
                            </button>
                        </form>
                    )}
                </div>
            </div>

            <Footer />
        </div>
    );
};

export default Contact;