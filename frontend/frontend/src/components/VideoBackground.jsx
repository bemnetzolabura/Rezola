import React from 'react';

const VideoBackground = () => {
    return (
        <div className="video-background">
            <video autoPlay loop muted playsInline>
                <source src="https://assets.mixkit.co/videos/preview/mixkit-aerial-view-of-a-beach-with-waves-1089-large.mp4" type="video/mp4" />
            </video>
            <div className="video-overlay"></div>
        </div>
    );
};

export default VideoBackground;