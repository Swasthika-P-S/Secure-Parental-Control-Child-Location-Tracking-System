import { useEffect, useState } from "react";

const API = "http://localhost:5000";

export default function ChildTracker({ parentPhone }) {
  const [children, setChildren] = useState([]);
  const [message, setMessage] = useState("");
  const [location, setLocation] = useState(null);
  const [loading, setLoading] = useState(false);

  // FETCH CHILDREN FROM DB
  useEffect(() => {
    if (!parentPhone) return;
    
    setLoading(true);
    fetch(`${API}/my-children`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ parentPhone })
    })
      .then(res => res.json())
      .then(data => {
        setChildren(data.children || []);
        setLoading(false);
      })
      .catch(() => {
        setMessage("Failed to load children");
        setLoading(false);
      });
  }, [parentPhone]);

  // STEP 1: REQUEST TRACKING (OTP) + OPEN CHILD PAGE
  const track = async (childPhone) => {
    setMessage("Requesting child consent...");
    setLocation(null);

    try {
      const res = await fetch(`${API}/request-child-track`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          parentPhone,
          childPhone
        })
      });

      const data = await res.json();

      if (!res.ok) {
        setMessage(data.error || "Failed to request tracking");
        return;
      }

      // Open child page in new tab
      window.open("/child-gps.html", "_blank");

      setMessage("OTP sent to console. Waiting for child to share location...");
    } catch (err) {
      setMessage("Failed to request tracking. Please try again.");
    }
  };

  // STEP 2: FETCH LOCATION AFTER CHILD SHARES
  const getLocation = async (childPhone) => {
    setMessage("Fetching latest location...");
    setLocation(null);

    try {
      const res = await fetch(`${API}/track-location`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          parentPhone,
          childPhone
        })
      });

      if (!res.ok) {
        const data = await res.json();
        setMessage(data.error || "Location not available. Ask child to share location.");
        return;
      }

      const data = await res.json();
      setLocation(data);
      setMessage("Location received successfully ✅");
    } catch (err) {
      setMessage("Failed to fetch location. Please try again.");
    }
  };

  if (loading) {
    return <div style={{ padding: 30 }}>Loading children...</div>;
  }

  return (
    <div style={{ padding: 30, fontFamily: "system-ui, sans-serif" }}>
      <h2 style={{ color: "#16a34a" }}>Track Children Location</h2>

      {children.length === 0 ? (
        <p style={{ color: "#666" }}>No children registered yet.</p>
      ) : (
        children.map((c, idx) => (
          <div
            key={idx}
            style={{
              border: "2px solid #16a34a",
              padding: 20,
              borderRadius: 12,
              marginBottom: 15,
              backgroundColor: "#f0fdf4"
            }}
          >
            <h3 style={{ margin: "0 0 8px 0" }}>{c.childName}</h3>
            <p style={{ color: "#666", margin: "0 0 15px 0" }}>{c.childPhone}</p>

            <button
              onClick={() => track(c.childPhone)}
              style={{
                background: "#16a34a",
                color: "white",
                padding: "10px 18px",
                marginRight: 10,
                border: "none",
                borderRadius: 6,
                cursor: "pointer",
                fontWeight: "600"
              }}
            >
              📍 Request Track
            </button>

            <button
              onClick={() => getLocation(c.childPhone)}
              style={{
                background: "#2563eb",
                color: "white",
                padding: "10px 18px",
                border: "none",
                borderRadius: 6,
                cursor: "pointer",
                fontWeight: "600"
              }}
            >
              🗺️ Get Location
            </button>
          </div>
        ))
      )}

      {message && (
        <div style={{ 
          padding: 15, 
          marginTop: 20, 
          borderRadius: 8,
          background: message.includes("✅") ? "#dcfce7" : "#fee2e2",
          color: message.includes("✅") ? "#166534" : "#991b1b",
          fontWeight: "500"
        }}>
          {message}
        </div>
      )}

      {location && (
        <div style={{ 
          marginTop: 20, 
          padding: 20,
          border: "2px solid #2563eb",
          borderRadius: 12,
          backgroundColor: "#eff6ff"
        }}>
          <h3 style={{ marginTop: 0, color: "#1e40af" }}>
            📍 {location.childName}'s Location
          </h3>
          <p><strong>Latitude:</strong> {location.latitude}</p>
          <p><strong>Longitude:</strong> {location.longitude}</p>
          {location.accuracy && (
            <p><strong>Accuracy:</strong> ±{location.accuracy.toFixed(0)}m</p>
          )}
          <p><strong>Last Updated:</strong> {new Date(location.lastUpdated).toLocaleString()}</p>
          
          <a
            href={`https://www.google.com/maps?q=${location.latitude},${location.longitude}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: "inline-block",
              marginTop: 10,
              padding: "10px 18px",
              background: "#16a34a",
              color: "white",
              textDecoration: "none",
              borderRadius: 6,
              fontWeight: "600"
            }}
          >
            🗺️ Open in Google Maps
          </a>
        </div>
      )}
    </div>
  );
}