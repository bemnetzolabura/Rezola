import React, { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

gsap.registerPlugin(ScrollTrigger);

const About = ({ user, logout }) => {
  const sectionRef = useRef(null);

  useEffect(() => {
    const section = sectionRef.current;
    const images = section.querySelectorAll('.about-image');
    const texts = section.querySelectorAll('.about-text');

    images.forEach((img, i) => {
      gsap.fromTo(img,
        { x: i % 2 === 0 ? -100 : 100, opacity: 0 },
        {
          x: 0,
          opacity: 1,
          duration: 1,
          scrollTrigger: {
            trigger: img,
            start: 'top 80%',
            toggleActions: 'play none none reverse'
          }
        }
      );
    });

    texts.forEach((text, i) => {
      gsap.fromTo(text,
        { x: i % 2 === 0 ? 100 : -100, opacity: 0 },
        {
          x: 0,
          opacity: 1,
          duration: 1,
          scrollTrigger: {
            trigger: text,
            start: 'top 80%',
            toggleActions: 'play none none reverse'
          }
        }
      );
    });

    return () => {
      ScrollTrigger.getAll().forEach(trigger => trigger.kill());
    };
  }, []);

  return (
    <div className="about-page">
      <Navbar user={user} logout={logout} />

      <div className="about-header">
        <h1>About Us</h1>
        <p>Our story and mission</p>
      </div>

      <div ref={sectionRef} className="about-content">
        <div className="about-row">
          <div className="about-image">
            <img src="https://images.unsplash.com/photo-1469854523086-cc02fe5d8800?w=800" alt="Travel" />
          </div>
          <div className="about-text">
            <h2>Our Story</h2>
            <p>Founded in 2020, WORLD TOURISM began with a simple mission: to make travel accessible, enjoyable, and unforgettable for everyone. We believe that exploring new places opens minds and creates lasting memories.</p>
          </div>
        </div>

        <div className="about-row reverse">
          <div className="about-text">
            <h2>Our Mission</h2>
            <p>We curate the finest destinations and experiences, ensuring every journey is unique. From luxury resorts to hidden gems, we help you discover the world on your terms.</p>
          </div>
          <div className="about-image">
            <img src="https://images.unsplash.com/photo-1501785888041-af3ef285b470?w=800" alt="Mission" />
          </div>
        </div>

        <div className="about-row">
          <div className="about-image">
            <img src="https://images.unsplash.com/photo-1522202176988-66273c2fd55f?w=800" alt="Team" />
          </div>
          <div className="about-text">
            <h2>Why Choose Us</h2>
            <p>With over 500+ destinations, 24/7 support, and exclusive deals, we're your trusted partner in adventure. Our team of travel experts ensures every detail is perfect.</p>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  );
};

export default About;