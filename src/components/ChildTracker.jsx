import { useEffect, useState } from "react";

const API = "http://localhost:5000";

export default function ChildTracker({ parentUsername }) {
  const [children, setChildren] = useState([]);
  const [message, setMessage] = useState("");
  const [location, setLocation] = useState(null);

  // FETCH CHILDREN FROM DB
  useEffect(() => {
    fetch(`${API}/parent/${parentUsername}/children`)
      .then(res => res.json())
      .then(setChildren)
      .catch(() => setMessage("Failed to load children"));
  }, [parentUsername]);

  // STEP 1: REQUEST TRACKING (OTP) + OPEN CHILD PAGE
  const track = async (phone) => {
    setMessage("Requesting child consent...");

    await fetch(`${API}/request-child-track`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        parentUsername,
        childPhone: phone
      })
    });

    // IMPORTANT: open via Vite server
    window.open("/child-gps.html", "_blank");

    setMessage("OTP sent. Waiting for child to share location...");
  };

  // STEP 2: FETCH LOCATION AFTER CHILD SHARES
  const getLocation = async (phone) => {
    setMessage("Fetching latest location...");

    const res = await fetch(
      `${API}/parent/${parentUsername}/child/${phone}/location`
    );

    if (!res.ok) {
      setMessage("Location not available. Ask child to share location.");
      return;
    }

    const data = await res.json();
    setLocation(data);
    setMessage("Location received successfully ✅");
  };

  return (
    <div style={{ padding: 30 }}>
      <h2>Track Location</h2>

      {children.map(c => (
        <div
          key={c._id}
          style={{
            border: "1px solid #16a34a",
            padding: 20,
            borderRadius: 12,
            marginBottom: 15
          }}
        >
          <b>{c.childName}</b>
          <p>{c.childPhone}</p>

          <button
            onClick={() => track(c.childPhone)}
            style={{
              background: "#16a34a",
              color: "white",
              padding: "8px 14px",
              marginRight: 10,
              border: "none",
              borderRadius: 6,
              cursor: "pointer"
            }}
          >
            Track
          </button>

          <button
            onClick={() => getLocation(c.childPhone)}
            style={{
              background: "#2563eb",
              color: "white",
              padding: "8px 14px",
              border: "none",
              borderRadius: 6,
              cursor: "pointer"
            }}
          >
            Get Location
          </button>
        </div>
      ))}

      {message && <p style={{ color: "red" }}>{message}</p>}

      {location && (
        <div style={{ marginTop: 20 }}>
          <h4>Last Known Location</h4>
          <p>Latitude: {location.latitude}</p>
          <p>Longitude: {location.longitude}</p>
          <p>
            Time: {new Date(location.createdAt).toLocaleString()}
          </p>
        </div>
      )}
    </div>
  );
}
