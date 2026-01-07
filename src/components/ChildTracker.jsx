import { useState, useEffect } from "react";
import "./ChildTracker.css";

const API = "http://localhost:5000";

export default function ChildTracker() {
  const [childPhone, setChildPhone] = useState("");
  const [isTracking, setIsTracking] = useState(false);
  const [coords, setCoords] = useState(null);
  const [error, setError] = useState("");
  const [lastUpdate, setLastUpdate] = useState(null);

  useEffect(() => {
    let watchId = null;

    if (isTracking && childPhone) {
      if (!navigator.geolocation) {
        setError("Geolocation not supported");
        return;
      }

      watchId = navigator.geolocation.watchPosition(
        async (position) => {
          const lat = position.coords.latitude;
          const lng = position.coords.longitude;
          
          setCoords({ latitude: lat, longitude: lng });
          setLastUpdate(new Date().toLocaleTimeString());

          const address = await getAddress(lat, lng);

          try {
            await fetch(API + "/update-location", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                childPhone,
                latitude: lat,
                longitude: lng,
                address
              })
            });
            setError("");
          } catch (err) {
            console.error("Failed to update:", err);
          }
        },
        (err) => {
          setError("GPS error");
        },
        {
          enableHighAccuracy: true,
          timeout: 5000,
          maximumAge: 0
        }
      );
    }

    return () => {
      if (watchId) {
        navigator.geolocation.clearWatch(watchId);
      }
    };
  }, [isTracking, childPhone]);

  const getAddress = async (lat, lng) => {
    try {
      const url = "https://nominatim.openstreetmap.org/reverse?format=json&lat=" + lat + "&lon=" + lng;
      const response = await fetch(url);
      const data = await response.json();
      return data.display_name || "Address unavailable";
    } catch (err) {
      return "Address unavailable";
    }
  };

  const startTracking = () => {
    const phoneRegex = /^\+[1-9]\d{9,14}$/;
    if (!childPhone || !phoneRegex.test(childPhone)) {
      setError("Enter valid phone with country code");
      return;
    }
    setIsTracking(true);
    setError("");
  };

  const stopTracking = () => {
    setIsTracking(false);
    setCoords(null);
  };

  return (
    <div className="child-tracker-container">
      <div className="child-tracker-box">
        <div className="tracker-header">
          <div className="tracker-icon">📍</div>
          <h1>Child GPS Tracker</h1>
          <p>Enable GPS tracking for location updates</p>
        </div>

        {!isTracking ? (
          <div className="tracker-form">
            <label>Child Phone Number</label>
            <input
              type="text"
              placeholder="+91**********"
              value={childPhone}
              onChange={(e) => setChildPhone(e.target.value)}
            />

            {error && <div className="tracker-error">{error}</div>}

            <button onClick={startTracking} className="btn-start">
              Start GPS Tracking
            </button>

            <div className="tracker-info">
              <strong>How it works</strong>
              <ul>
                <li>Enter child phone number</li>
                <li>Allow browser GPS access</li>
                <li>Automatic position updates</li>
                <li>Parents can track from dashboard</li>
              </ul>
            </div>
          </div>
        ) : (
          <div className="tracking-active">
            <div className="tracking-status">
              <div className="pulse-dot"></div>
              <strong>Tracking Active</strong>
            </div>

            <div className="tracking-details">
              <div><strong>Phone</strong> {childPhone}</div>
              {coords && (
                <>
                  <div><strong>Latitude</strong> {coords.latitude.toFixed(6)}</div>
                  <div><strong>Longitude</strong> {coords.longitude.toFixed(6)}</div>
                  <div><strong>Last Update</strong> {lastUpdate}</div>
                </>
              )}
            </div>

            {error && <div className="tracker-error">{error}</div>}

            <button onClick={stopTracking} className="btn-stop">
              Stop Tracking
            </button>

            <div className="tracker-warning">
              Keep this page open for continuous tracking
            </div>
          </div>
        )}
      </div>
    </div>
  );
}