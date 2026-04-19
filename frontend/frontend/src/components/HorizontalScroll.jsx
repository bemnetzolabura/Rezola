import React, { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Heart, MapPin, Star, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

gsap.registerPlugin(ScrollTrigger);

const DESTINATIONS = [
    {
        id: 1,
        name: "Santorini",
        country: "Greece",
        price: 1299,
        rating: 4.9,
        image: "https://images.unsplash.com/photo-1613395877344-13d4c280d288?w=800",
        description: "White-washed buildings, blue domes, and stunning sunsets over the Aegean Sea.",
        duration: "7 days",
        category: "Beach"
    },
    {
        id: 2,
        name: "Kyoto",
        country: "Japan",
        price: 1899,
        rating: 4.8,
        image: "https://images.unsplash.com/photo-1493976040374-85c8e12f0c0e?w=800",
        description: "Ancient temples, traditional tea houses, and beautiful cherry blossoms.",
        duration: "10 days",
        category: "Culture"
    },
    {
        id: 3,
        name: "Machu Picchu",
        country: "Peru",
        price: 1599,
        rating: 4.9,
        image: "https://images.unsplash.com/photo-1587595431973-160d0d94add1?w=800",
        description: "Mysterious Incan citadel set high in the Andes Mountains.",
        duration: "8 days",
        category: "Adventure"
    },
    {
        id: 4,
        name: "Maldives",
        country: "Maldives",
        price: 2499,
        rating: 5.0,
        image: "https://images.unsplash.com/photo-1514282401047-d79a71a590e8?w=800",
        description: "Crystal clear waters, overwater bungalows, and pristine beaches.",
        duration: "6 days",
        category: "Luxury"
    },
    {
        id: 5,
        name: "Iceland",
        country: "Iceland",
        price: 1799,
        rating: 4.7,
        image: "https://images.unsplash.com/photo-1476610182048-b716b8518aae?w=800",
        description: "Northern lights, geothermal springs, and dramatic landscapes.",
        duration: "9 days",
        category: "Adventure"
    },
    {
        id: 6,
        name: "Paris",
        country: "France",
        price: 1399,
        rating: 4.6,
        image: "https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=800",
        description: "The city of love, art, and world-class cuisine.",
        duration: "5 days",
        category: "City"
    }
];

const HorizontalScroll = ({ user }) => {
    const sectionRef = useRef(null);
    const containerRef = useRef(null);
    const navigate = useNavigate();

    useEffect(() => {
        const section = sectionRef.current;
        const container = containerRef.current;

        if (!section || !container) return;

        const scrollWidth = container.scrollWidth - window.innerWidth;

        gsap.to(container, {
            x: -scrollWidth,
            ease: 'none',
            scrollTrigger: {
                trigger: section,
                start: 'top top',
                end: () => `+=${scrollWidth}`,
                pin: true,
                scrub: 1,
                anticipatePin: 1,
                invalidateOnRefresh: true
            }
        });

        return () => {
            ScrollTrigger.getAll().forEach(trigger => trigger.kill());
        };
    }, []);

    const handleBook = (dest) => {
        if (!user) {
            navigate('/login');
            return;
        }
        navigate('/hotels');
    };

    return (
        <section ref={sectionRef} className="horizontal-section">
            <div className="horizontal-header">
                <h2>Popular Destinations</h2>
                <p>Scroll to explore our handpicked locations</p>
            </div>

            <div ref={containerRef} className="horizontal-scroll-container">
                {DESTINATIONS.map((dest) => (
                    <div key={dest.id} className="destination-card">
                        <div className="card-image">
                            <img src={dest.image} alt={dest.name} />
                            <div className="card-badge">{dest.category}</div>
                        </div>

                        <div className="card-content">
                            <div className="card-header">
                                <div>
                                    <h3>{dest.name}</h3>
                                    <span className="location">
                                        <MapPin size={14} />
                                        {dest.country}
                                    </span>
                                </div>
                                <div className="rating">
                                    <Star size={14} fill="#ffd700" />
                                    {dest.rating}
                                </div>
                            </div>

                            <p className="card-description">{dest.description}</p>

                            <div className="card-footer">
                                <div className="price">
                                    <span className="amount">${dest.price}</span>
                                    <span className="period">/person</span>
                                </div>
                                <button className="book-btn" onClick={() => handleBook(dest)}>
                                    Book Now
                                </button>
                            </div>
                        </div>
                    </div>
                ))}

                <div className="scroll-end-card" onClick={() => navigate('/hotels')}>
                    <h3>View All Destinations</h3>
                    <ArrowRight size={40} />
                </div>
            </div>
        </section>
    );
};

export default HorizontalScroll;