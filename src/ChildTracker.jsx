import { useEffect, useState } from "react";
import "./ChildTracker.css";

const API = "http://localhost:5001";

export default function ChildTracker({ token, onLogout }) {
  const [children, setChildren] = useState([]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [selectedChild, setSelectedChild] = useState(null);
  const [loading, setLoading] = useState(false);
  const [mapInstance, setMapInstance] = useState(null);
  const [markerInstance, setMarkerInstance] = useState(null);
  const [circleInstance, setCircleInstance] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(null);

  // Helper function for API calls with authentication
  const apiCall = async (endpoint, options = {}) => {
    const headers = {
      "Content-Type": "application/json",
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers
    };

    try {
      const response = await fetch(`${API}${endpoint}`, {
        ...options,
        headers
      });

      const data = await response.json();

      // Handle 401 (token expired or invalid)
      if (response.status === 401) {
        setError("Session expired. Please login again.");
        setTimeout(() => {
          if (onLogout) onLogout();
        }, 2000);
        throw new Error("Unauthorized");
      }

      if (!response.ok) {
        throw new Error(data.error || "Request failed");
      }

      return data;
    } catch (err) {
      if (err.message === "Unauthorized") {
        throw err;
      }
      throw new Error(err.message || "Network error");
    }
  };

  // Load Google Maps
  useEffect(() => {
    if (window.google && window.google.maps) {
      initMap();
      return;
    }

    const script = document.createElement("script");
    script.src = `https://maps.googleapis.com/maps/api/js?key=${process.env.REACT_APP_GOOGLE_MAPS_KEY || "YOUR_API_KEY"}&callback=initGoogleMap`;
    script.async = true;
    script.defer = true;

    window.initGoogleMap = () => initMap();
    document.head.appendChild(script);

    return () => {
      if (document.head.contains(script)) {
        document.head.removeChild(script);
      }
      delete window.initGoogleMap;
    };
  }, []);

  // Initialize map
  const initMap = () => {
    if (!window.google || !window.google.maps) return;
    const mapElement = document.getElementById("tracking-map");
    if (!mapElement) return;

    const map = new window.google.maps.Map(mapElement, {
      zoom: 13,
      center: { lat: 28.6139, lng: 77.209 }, // Delhi, India
      mapTypeControl: true,
      streetViewControl: true,
      fullscreenControl: true,
      zoomControl: true,
      styles: [
        {
          featureType: "poi",
          elementType: "labels",
          stylers: [{ visibility: "off" }]
        }
      ]
    });

    setMapInstance(map);
  };

  // Fetch children
  const fetchChildren = async () => {
    if (!token) return;

    setLoading(true);
    setError("");

    try {
      const data = await apiCall("/my-children");
      setChildren(data.children || []);
      setMessage(data.children?.length > 0 
        ? `✅ Loaded ${data.children.length} ${data.children.length === 1 ? "child" : "children"}` 
        : ""
      );
    } catch (err) {
      if (err.message !== "Unauthorized") {
        setError(err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  // Load children on mount
  useEffect(() => {
    fetchChildren();
  }, [token]);

  // Auto-refresh functionality
  useEffect(() => {
    if (autoRefresh && selectedChild) {
      const interval = setInterval(() => {
        getLocation(selectedChild.childPhone, selectedChild.childName, true);
      }, 30000); // Refresh every 30 seconds

      setRefreshInterval(interval);

      return () => clearInterval(interval);
    } else if (refreshInterval) {
      clearInterval(refreshInterval);
      setRefreshInterval(null);
    }
  }, [autoRefresh, selectedChild]);

  // Update map with location
  const updateMapLocation = (location) => {
    if (!mapInstance || !window.google) return;

    const position = {
      lat: parseFloat(location.latitude),
      lng: parseFloat(location.longitude)
    };

    // Remove existing marker and circle
    if (markerInstance) markerInstance.setMap(null);
    if (circleInstance) circleInstance.setMap(null);

    // Create marker
    const marker = new window.google.maps.Marker({
      position: position,
      map: mapInstance,
      title: location.childName || "Child Location",
      animation: window.google.maps.Animation.DROP,
      icon: {
        url: "http://maps.google.com/mapfiles/ms/icons/red-dot.png",
        scaledSize: new window.google.maps.Size(50, 50)
      }
    });

    // Create accuracy circle
    const circle = new window.google.maps.Circle({
      map: mapInstance,
      radius: location.accuracy || 50,
      fillColor: "#4285F4",
      fillOpacity: 0.2,
      strokeColor: "#4285F4",
      strokeOpacity: 0.5,
      strokeWeight: 2,
      center: position
    });

    // Info window
    const infoWindow = new window.google.maps.InfoWindow({
      content: `
        <div style="padding: 15px; font-family: Arial, sans-serif; min-width: 200px;">
          <h3 style="margin: 0 0 10px 0; color: #333; font-size: 16px;">📍 ${location.childName || "Child"}</h3>
          <div style="color: #666; font-size: 13px;">
            <p style="margin: 5px 0;"><strong>Coordinates:</strong></p>
            <p style="margin: 5px 0; font-family: monospace;">
              ${parseFloat(location.latitude).toFixed(6)}, ${parseFloat(location.longitude).toFixed(6)}
            </p>
            <p style="margin: 5px 0;"><strong>Accuracy:</strong> ±${Math.round(location.accuracy)}m</p>
            <p style="margin: 5px 0;"><strong>Updated:</strong> ${new Date(location.lastUpdated).toLocaleString()}</p>
          </div>
          <a href="https://www.google.com/maps/dir/?api=1&destination=${location.latitude},${location.longitude}" 
             target="_blank" 
             style="display: inline-block; margin-top: 10px; color: #1976D2; text-decoration: none; font-weight: 600;">
            🚗 Get Directions →
          </a>
        </div>
      `
    });

    marker.addListener("click", () => {
      infoWindow.open(mapInstance, marker);
    });

    // Center map and open info window
    mapInstance.setCenter(position);
    mapInstance.setZoom(16);
    infoWindow.open(mapInstance, marker);

    setMarkerInstance(marker);
    setCircleInstance(circle);
  };

  // Get child location
  const getLocation = async (childPhone, childName, isAutoRefresh = false) => {
    if (!isAutoRefresh) {
      setMessage("📡 Fetching latest location...");
      setLoading(true);
    }
    setError("");

    try {
      const data = await apiCall("/track-location", {
        method: "POST",
        body: JSON.stringify({ childPhone })
      });

      const locationData = {
        ...data.location,
        childName: childName || data.childName
      };

      setSelectedChild({ childPhone, childName });
      updateMapLocation(locationData);
      
      setMessage(isAutoRefresh 
        ? `🔄 Auto-refreshed at ${new Date().toLocaleTimeString()}` 
        : "✅ Location loaded successfully!"
      );
    } catch (err) {
      if (err.message !== "Unauthorized") {
        setError(err.message || "Location not available. Child may not have shared location yet.");
        setSelectedChild(null);
      }
    } finally {
      if (!isAutoRefresh) {
        setLoading(false);
      }
    }
  };

  // Remove child
  const handleRemoveChild = async (childPhone, childName) => {
    if (!confirm(`Are you sure you want to remove ${childName}?`)) {
      return;
    }

    setLoading(true);
    setError("");

    try {
      await apiCall(`/remove-child/${encodeURIComponent(childPhone)}`, {
        method: "DELETE"
      });

      setMessage(`✅ ${childName} removed successfully`);
      
      // Clear selection if it was the removed child
      if (selectedChild?.childPhone === childPhone) {
        setSelectedChild(null);
        setAutoRefresh(false);
        if (markerInstance) markerInstance.setMap(null);
        if (circleInstance) circleInstance.setMap(null);
      }

      // Reload children
      await fetchChildren();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading && children.length === 0) {
    return (
      <div className="child-tracker-container">
        <div className="child-tracker-box">
          <div className="tracker-header">
            <div className="tracker-icon">⏳</div>
            <h1>Loading...</h1>
            <p>Fetching your children's information</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="tracker-main-container">
      {/* Header */}
      <div className="tracker-header-bar">
        <div className="tracker-header-content">
          <div>
            <h1 className="tracker-main-title">📍 Child Location Tracker</h1>
            <p className="tracker-main-subtitle">
              Real-time GPS tracking with secure authentication
            </p>
          </div>
          {onLogout && (
            <button onClick={onLogout} className="logout-btn">
              🚪 Logout
            </button>
          )}
        </div>
      </div>

      {/* Messages */}
      {message && (
        <div className={`alert ${message.includes("✅") || message.includes("🔄") ? "alert-success" : "alert-info"}`}>
          {(message.includes("✅") || message.includes("🔄")) && <div className="pulse-dot"></div>}
          <div>{message}</div>
        </div>
      )}

      {error && (
        <div className="alert alert-error">
          ❌ {error}
        </div>
      )}

      {/* Main Content Grid */}
      <div className="tracker-grid">
        {/* Left Panel - Children List */}
        <div className="tracker-panel">
          <div className="panel-header">
            <h2 className="panel-title">
              👶 Your Children ({children.length})
            </h2>
            <button
              onClick={fetchChildren}
              className="refresh-btn"
              disabled={loading}
              title="Refresh list"
            >
              🔄
            </button>
          </div>

          <div className="children-scroll">
            {children.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">👶</div>
                <p className="empty-text">No children registered</p>
                <p className="empty-subtext">
                  Register a child from the home page to start tracking
                </p>
              </div>
            ) : (
              children.map((child, idx) => (
                <div
                  key={idx}
                  className={`child-card ${
                    selectedChild?.childPhone === child.childPhone ? "child-card-selected" : ""
                  }`}
                >
                  <div className="child-card-header">
                    <div className="child-avatar">
                      {child.childName.charAt(0).toUpperCase()}
                    </div>
                    <div className="child-details">
                      <h3 className="child-name">{child.childName}</h3>
                      <p className="child-phone">{child.childPhone}</p>
                      <p className="child-registered">
                        📅 {new Date(child.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                  </div>

                  <div className="child-card-actions">
                    <button
                      onClick={() => getLocation(child.childPhone, child.childName)}
                      className="btn-track"
                      disabled={loading}
                    >
                      📍 Track Now
                    </button>
                    <button
                      onClick={() => handleRemoveChild(child.childPhone, child.childName)}
                      className="btn-remove"
                      disabled={loading}
                      title="Remove child"
                    >
                      🗑️
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Panel - Map */}
        <div className="tracker-panel">
          <div className="panel-header">
            <h2 className="panel-title">🗺️ Live Location Map</h2>
            {selectedChild && (
              <div className="map-controls">
                <label className="auto-refresh-toggle">
                  <input
                    type="checkbox"
                    checked={autoRefresh}
                    onChange={(e) => setAutoRefresh(e.target.checked)}
                  />
                  <span>🔄 Auto-refresh (30s)</span>
                </label>
              </div>
            )}
          </div>

          {selectedChild && (
            <div className="location-info-bar">
              <div className="location-info-item">
                <span className="info-label">Child:</span>
                <span className="info-value">{selectedChild.childName}</span>
              </div>
              <div className="location-info-item">
                <span className="info-label">Status:</span>
                <span className="info-value">
                  {autoRefresh ? "🟢 Auto-refreshing" : "⚪ Manual"}
                </span>
              </div>
            </div>
          )}

          <div id="tracking-map" className="map-container"></div>

          {selectedChild && (
            <div className="map-actions">
              <button
                onClick={() => getLocation(selectedChild.childPhone, selectedChild.childName)}
                className="btn-refresh"
                disabled={loading}
              >
                🔄 Refresh Location
              </button>
              <button
                onClick={() => {
                  setSelectedChild(null);
                  setAutoRefresh(false);
                  if (markerInstance) markerInstance.setMap(null);
                  if (circleInstance) circleInstance.setMap(null);
                }}
                className="btn-clear"
              >
                ✕ Clear Selection
              </button>
            </div>
          )}

          {!selectedChild && (
            <div className="map-placeholder">
              <div className="placeholder-icon">🗺️</div>
              <p className="placeholder-text">Select a child to view their location</p>
              <p className="placeholder-subtext">
                Click "Track Now" on any child to see their real-time location on the map
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Privacy Notice */}
      <div className="privacy-notice">
        <div className="privacy-icon">🔒</div>
        <div>
          <strong>Privacy & Security:</strong> All location data is encrypted with AES-256. 
          Child must actively share location for tracking to work. Location history is stored securely and 
          only accessible to authorized parents.
        </div>
      </div>
    </div>
  );
}