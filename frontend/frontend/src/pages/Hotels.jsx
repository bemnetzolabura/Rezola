import React, { useState } from 'react';
import { Star, MapPin, Phone, Globe } from 'lucide-react';
import { Link } from 'react-router-dom';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

const HOTELS = [
  {
    id: 1,
    name: "Grand Plaza Hotel",
    location: "Paris, France",
    rating: 5,
    price: 350,
    image: "https://images.unsplash.com/photo-1566073771259-6a8506099945?w=800",
    coords: { lat: 48.8566, lng: 2.3522 },
    phone: "+33 1 23 45 67 89",
    website: "grandplaza.com"
  },
  {
    id: 2,
    name: "Ocean View Resort",
    location: "Maldives",
    rating: 5,
    price: 890,
    image: "https://images.unsplash.com/photo-1582719508461-905c673771fd?w=800",
    coords: { lat: 3.2028, lng: 73.2207 },
    phone: "+960 123 4567",
    website: "oceanview.mv"
  },
  {
    id: 3,
    name: "Mountain Lodge",
    location: "Swiss Alps",
    rating: 4,
    price: 280,
    image: "https://images.unsplash.com/photo-1551882547-ff40c63fe5fa?w=800",
    coords: { lat: 46.8182, lng: 8.2275 },
    phone: "+41 44 123 45 67",
    website: "mountainlodge.ch"
  },
  {
    id: 4,
    name: "Desert Oasis",
    location: "Dubai, UAE",
    rating: 5,
    price: 450,
    image: "https://images.unsplash.com/photo-1582719508461-905c673771fd?w=800",
    coords: { lat: 25.2048, lng: 55.2708 },
    phone: "+971 4 123 4567",
    website: "desertoasis.ae"
  },
  {
    id: 5,
    name: "Tropical Paradise",
    location: "Bali, Indonesia",
    rating: 4,
    price: 180,
    image: "https://images.unsplash.com/photo-1571896349842-33c89424de2d?w=800",
    coords: { lat: -8.4095, lng: 115.1889 },
    phone: "+62 361 123 456",
    website: "tropicalbali.com"
  },
  {
    id: 6,
    name: "City Center Inn",
    location: "Tokyo, Japan",
    rating: 3,
    price: 120,
    image: "https://images.unsplash.com/photo-1542314831-068cd1dbfeeb?w=800",
    coords: { lat: 35.6762, lng: 139.6503 },
    phone: "+81 3 1234 5678",
    website: "citycentertokyo.jp"
  }
];

const Hotels = ({ user, logout }) => {
  const [filter, setFilter] = useState('all');

  const filteredHotels = filter === 'all'
    ? HOTELS
    : HOTELS.filter(h => h.rating === parseInt(filter));

  return (
    <div className="hotels-page">
      <Navbar user={user} logout={logout} />

      <div className="hotels-header">
        <h1>Hotels & Maps</h1>
        <p>Find the perfect stay with real-time location</p>

        <div className="filter-bar">
          <button className={filter === 'all' ? 'active' : ''} onClick={() => setFilter('all')}>All</button>
          <button className={filter === '5' ? 'active' : ''} onClick={() => setFilter('5')}>5 Star</button>
          <button className={filter === '4' ? 'active' : ''} onClick={() => setFilter('4')}>4 Star</button>
          <button className={filter === '3' ? 'active' : ''} onClick={() => setFilter('3')}>3 Star</button>
        </div>
      </div>

      <div className="hotels-grid">
        {filteredHotels.map(hotel => (
          <div key={hotel.id} className="hotel-card">
            <div className="hotel-image">
              <img src={hotel.image} alt={hotel.name} />
              <div className="hotel-rating">
                {[...Array(hotel.rating)].map((_, i) => (
                  <Star key={i} size={14} fill="#ffd700" />
                ))}
              </div>
            </div>

            <div className="hotel-info">
              <h3>{hotel.name}</h3>
              <p className="hotel-location">
                <MapPin size={16} />
                {hotel.location}
              </p>

              <div className="map-container">
                <iframe
                  src={`https://www.openstreetmap.org/export/embed.html?bbox=${hotel.coords.lng - 0.01}%2C${hotel.coords.lat - 0.01}%2C${hotel.coords.lng + 0.01}%2C${hotel.coords.lat + 0.01}&layer=mapnik&marker=${hotel.coords.lat}%2C${hotel.coords.lng}`}
                  width="100%"
                  height="100%"
                  style={{ border: 0 }}
                  allowFullScreen=""
                  loading="lazy"
                  title={hotel.name}
                />
              </div>

              <div className="hotel-contact">
                <a href={`tel:${hotel.phone}`}>
                  <Phone size={16} />
                  {hotel.phone}
                </a>
                <a href={`https://${hotel.website}`} target="_blank" rel="noopener noreferrer">
                  <Globe size={16} />
                  {hotel.website}
                </a>
              </div>

              <div className="hotel-footer">
                <span className="hotel-price">${hotel.price}<small>/night</small></span>
                {user ? (
                  <Link to="/dashboard/bookings" className="btn-primary">Book Now</Link>
                ) : (
                  <Link to="/login" className="btn-primary">Book Now</Link>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      <Footer />
    </div>
  );
};

export default Hotels;