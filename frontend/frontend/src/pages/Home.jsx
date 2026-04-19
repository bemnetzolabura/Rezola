import React, { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';
import VideoBackground from '../components/VideoBackground';
import HorizontalScroll from '../components/HorizontalScroll';
const Home = ({ user, logout }) => {
  const heroRef = useRef(null);
  useEffect(() => {
    gsap.fromTo('.hero-title',
      { y: 100, opacity: 0 },
      { y: 0, opacity: 1, duration: 1.2, ease: 'power4.out', delay: 0.2 }
    );
    gsap.fromTo('.hero-subtitle',
      { y: 50, opacity: 0 },
      { y: 0, opacity: 1, duration: 1, ease: 'power3.out', delay: 0.5 }
    );
    gsap.fromTo('.hero-cta',
      { y: 30, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.8, ease: 'power2.out', delay: 0.8 }
    );
  }, []);
  return (
    <div className="home-page">
      <Navbar user={user} logout={logout} />
      <section ref={heroRef} className="hero">
        <VideoBackground />
        <div className="hero-content">
          <h1 className="hero-title">Welcome</h1>
          <p className="hero-subtitle">
            Discover breathtaking destinations and create unforgettable memories
          </p>
          <div className="hero-cta">
            <Link to="/hotels" className="btn-primary">
              Explore Hotels
              <ArrowRight size={20} />
            </Link>
            <Link to="/about" className="btn-secondary">
              Learn More
            </Link>
          </div>
        </div>
      </section>
      <HorizontalScroll user={user} />
      <Footer />
    </div>
  );
};
export default Home;