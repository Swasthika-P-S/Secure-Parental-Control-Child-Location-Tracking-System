import { useState, useEffect } from "react";
import "./home.css";

const API = "http://localhost:5001";

export default function Home({ userPhone, token, onLogout }) {
  const [view, setView] = useState("main"); // main, register, track
  const [childPhone, setChildPhone] = useState("");
  const [childName, setChildName] = useState("");
  const [otp, setOtp] = useState("");
  const [children, setChildren] = useState([]);
  const [selectedChild, setSelectedChild] = useState(null);
  const [location, setLocation] = useState(null);
  const [locationHistory, setLocationHistory] = useState([]);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(1); // 1: form, 2: otp
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "light");
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  // Load children when component mounts or token changes
  useEffect(() => {
    if (token) {
      loadChildren();
    }
  }, [token]);

  const features = [
    {
      id: 1,
      icon: "📍",
      title: "Real-Time Tracking",
      description: "Secure GPS-based location tracking with encrypted storage.",
    },
    {
      id: 2,
      icon: "🔐",
      title: "JWT Authentication",
      description: "Token-based authentication with secure session management.",
    },
    {
      id: 3,
      icon: "🔒",
      title: "Access Control",
      description: "Role-based access for Parent, Child, and Admin.",
    },
    {
      id: 4,
      icon: "🛡️",
      title: "Data Security",
      description: "AES-256 encryption, SHA-256 hashing, and secure key management.",
    }
  ];

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
      throw new Error(err.message || "Network error. Please check if server is running.");
    }
  };

  // Load children
  const loadChildren = async () => {
    if (!token) return;

    try {
      const data = await apiCall("/my-children");
      setChildren(data.children || []);
    } catch (err) {
      if (err.message !== "Unauthorized") {
        console.error("Failed to load children:", err);
      }
    }
  };

  // Register child - send OTP
  const handleRegisterChild = async () => {
    const phoneRegex = /^\+?[1-9]\d{9,14}$/;
    
    // Validation
    if (!childPhone || !childName) {
      setError("All fields are required");
      return;
    }
    
    if (!phoneRegex.test(childPhone.replace(/[\s-]/g, ""))) {
      setError("Invalid phone format. Use +[country][number] (e.g., +1234567890)");
      return;
    }

    if (childName.trim().length < 2) {
      setError("Child name must be at least 2 characters");
      return;
    }
    
    if (childPhone === userPhone) {
      setError("Child phone cannot be the same as parent phone");
      return;
    }
    
    setLoading(true);
    setError("");
    setMessage("");
    
    try {
      const data = await apiCall("/register-child", {
        method: "POST",
        body: JSON.stringify({
          childPhone: childPhone.trim(),
          childName: childName.trim()
        })
      });

      setMessage(data.message || "OTP sent to your phone for verification");
      setStep(2);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Verify OTP and complete registration
  const handleVerifyOTP = async () => {
    if (!otp || otp.length !== 6) {
      setError("Please enter a valid 6-digit OTP");
      return;
    }
    
    setLoading(true);
    setError("");
    
    try {
      const data = await apiCall("/verify-parent", {
        method: "POST",
        body: JSON.stringify({ otp })
      });

      setMessage("✅ " + data.message);
      
      // Reload children list
      await loadChildren();
      
      setTimeout(() => {
        resetForm();
        setView("track");
      }, 1500);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Track child location
  const handleTrackLocation = async (child) => {
    setLoading(true);
    setError("");
    setMessage("");
    setSelectedChild(child);
    setShowHistory(false);
    
    try {
      const data = await apiCall("/track-location", {
        method: "POST",
        body: JSON.stringify({ childPhone: child.childPhone })
      });

      setLocation(data.location);
      setMessage("✅ Location loaded successfully");
    } catch (err) {
      setError(err.message);
      setLocation(null);
    } finally {
      setLoading(false);
    }
  };

  // Load location history
  const handleLoadHistory = async (child) => {
    if (!child) return;
    
    setLoading(true);
    setError("");
    setMessage("");
    
    try {
      const data = await apiCall(`/location-history/${encodeURIComponent(child.childPhone)}?limit=20`);
      
      setLocationHistory(data.locations || []);
      setShowHistory(true);
      setMessage(`✅ Loaded ${data.locations?.length || 0} location records`);
    } catch (err) {
      setError(err.message);
      setLocationHistory([]);
    } finally {
      setLoading(false);
    }
  };

  // Remove child
  const handleRemoveChild = async (childPhone) => {
    if (!confirm("Are you sure you want to remove this child?")) {
      return;
    }

    setLoading(true);
    setError("");

    try {
      await apiCall(`/remove-child/${encodeURIComponent(childPhone)}`, {
        method: "DELETE"
      });

      setMessage("✅ Child removed successfully");
      
      // Clear selection if it was the removed child
      if (selectedChild?.childPhone === childPhone) {
        setSelectedChild(null);
        setLocation(null);
        setLocationHistory([]);
      }

      // Reload children list
      await loadChildren();
      
      setTimeout(() => setMessage(""), 3000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setChildPhone("");
    setChildName("");
    setOtp("");
    setStep(1);
    setError("");
    setMessage("");
  };

  const handleViewChange = (newView) => {
    setView(newView);
    setError("");
    setMessage("");
    setLocation(null);
    setSelectedChild(null);
    setShowHistory(false);
    setLocationHistory([]);
  };

  return (
    <div className="home-container">
      {/* Navigation Bar */}
      <div className="top-nav-bar">
        <div className="nav-brand">
          <span className="nav-icon">🔒</span>
          Child Tracker
        </div>
        <div className="nav-links">
          <button className="nav-link active" onClick={() => handleViewChange("main")}>
            🏠 Home
          </button>
        </div>
        <div className="nav-actions">
          <div className="user-info-nav">
            <span className="user-icon-nav">👤</span>
            <span className="user-phone-nav">{userPhone}</span>
            <span className="user-role-badge">PARENT</span>
          </div>
          {onLogout && (
            <button className="nav-logout" onClick={onLogout}>
              🚪 Logout
            </button>
          )}
          <button className="theme-toggle-nav" onClick={() => setTheme(theme === "light" ? "dark" : "light")}>
            {theme === "light" ? "🌙" : "☀️"}
          </button>
        </div>
      </div>

      <div className="animated-bg">
        <div className="circle circle-1"></div>
        <div className="circle circle-2"></div>
        <div className="circle circle-3"></div>
      </div>

      <section className="hero-section">
        <div className="hero-content">
          <h1 className="hero-title">
            Secure Parental Control & 
            <span className="gradient-text"> Child Location Tracking</span>
          </h1>
          <p className="hero-subtitle">
            Track your child's real-time location securely using JWT authentication, encryption, and access control.
          </p>

          {view === "main" && (
            <div className="tracking-container">
              <div className="tracking-card">
                <div className="tracking-icon">🔍</div>
                <h2 className="tracking-title">Welcome Back!</h2>
                <p className="tracking-subtitle">
                  Manage your children and track their locations securely
                </p>

                {error && <div className="tracking-error">{error}</div>}
                {message && <div className="tracking-success">{message}</div>}
                
                <div className="action-buttons">
                  <button onClick={() => handleViewChange("track")} className="tracking-btn">
                    📍 Track Children
                  </button>
                  <button onClick={() => handleViewChange("register")} className="tracking-btn-secondary">
                    ➕ Register New Child
                  </button>
                </div>

                <div className="stats-mini">
                  <div className="stat-mini">
                    <div className="stat-mini-value">{children.length}</div>
                    <div className="stat-mini-label">Registered Children</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {view === "register" && (
            <div className="tracking-container">
              <div className="tracking-card">
                <div className="tracking-icon">👨‍👩‍👧</div>
                <h2 className="tracking-title">Register Child</h2>
                <p className="tracking-subtitle">
                  Link your child's phone number for location tracking
                </p>

                {step === 1 && (
                  <div className="tracking-form">
                    <div className="input-group">
                      <label>Child's Name <span className="required">*</span></label>
                      <input
                        type="text"
                        placeholder="Enter child's name"
                        value={childName}
                        onChange={(e) => {
                          setChildName(e.target.value);
                          setError("");
                        }}
                        className="tracking-input"
                        disabled={loading}
                        maxLength={50}
                      />
                    </div>
                    <div className="input-group">
                      <label>Child's Phone Number <span className="required">*</span></label>
                      <input
                        type="text"
                        placeholder="+1234567890"
                        value={childPhone}
                        onChange={(e) => {
                          setChildPhone(e.target.value);
                          setError("");
                        }}
                        className="tracking-input"
                        disabled={loading}
                      />
                      <small className="input-hint">Format: +[country code][number]</small>
                    </div>
                    {error && <div className="tracking-error">{error}</div>}
                    {message && <div className="tracking-success">{message}</div>}
                    
                    <div className="action-buttons">
                      <button 
                        onClick={handleRegisterChild} 
                        className="tracking-btn" 
                        disabled={loading || !childName.trim() || !childPhone.trim()}
                      >
                        {loading ? "⏳ Sending..." : "📤 Send OTP"}
                      </button>
                      <button 
                        onClick={() => handleViewChange("main")} 
                        className="tracking-btn-secondary"
                        disabled={loading}
                      >
                        ← Back
                      </button>
                    </div>
                    <p className="tracking-note">
                      <span className="note-icon">ℹ️</span>
                      OTP will be sent to your phone ({userPhone}) for verification
                    </p>
                  </div>
                )}

                {step === 2 && (
                  <div className="tracking-form">
                    <div className="verification-info">
                      <span className="info-icon">📱</span>
                      <div>
                        <p className="verification-text">Verification code sent!</p>
                        <p className="verification-subtext">Check your phone: {userPhone}</p>
                      </div>
                    </div>
                    <div className="input-group">
                      <label>Enter 6-Digit OTP <span className="required">*</span></label>
                      <input
                        type="text"
                        placeholder="000000"
                        value={otp}
                        onChange={(e) => {
                          const val = e.target.value.replace(/\D/g, "").slice(0, 6);
                          setOtp(val);
                          setError("");
                        }}
                        className="tracking-input otp-input"
                        maxLength={6}
                        disabled={loading}
                        autoFocus
                      />
                    </div>
                    {error && <div className="tracking-error">{error}</div>}
                    {message && <div className="tracking-success">{message}</div>}
                    
                    <div className="action-buttons">
                      <button 
                        onClick={handleVerifyOTP} 
                        className="tracking-btn" 
                        disabled={loading || otp.length !== 6}
                      >
                        {loading ? "⏳ Verifying..." : "✅ Verify & Register"}
                      </button>
                      <button 
                        onClick={() => { handleViewChange("main"); resetForm(); }} 
                        className="tracking-btn-secondary"
                        disabled={loading}
                      >
                        ✕ Cancel
                      </button>
                    </div>
                    <p className="tracking-note">
                      <span className="note-icon">⏱️</span>
                      OTP expires in 5 minutes
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {view === "track" && (
            <div className="tracking-container tracking-container-wide">
              <div className="tracking-card">
                <div className="tracking-icon">📍</div>
                <h2 className="tracking-title">Track Children</h2>
                <p className="tracking-subtitle">
                  Select a child to view their location
                </p>

                {error && <div className="tracking-error">{error}</div>}
                {message && <div className="tracking-success">{message}</div>}

                {children.length === 0 ? (
                  <div className="no-children">
                    <div className="no-children-icon">👶</div>
                    <p className="no-children-text">No children registered yet</p>
                    <button onClick={() => handleViewChange("register")} className="tracking-btn">
                      ➕ Register Your First Child
                    </button>
                  </div>
                ) : (
                  <div className="children-list">
                    {children.map((child, index) => (
                      <div 
                        key={index} 
                        className={`child-item ${selectedChild?.childPhone === child.childPhone ? "child-item-selected" : ""}`}
                      >
                        <div className="child-info">
                          <h4 className="child-name">{child.childName}</h4>
                          <p className="child-phone">{child.childPhone}</p>
                          <p className="child-date">
                            Registered: {new Date(child.createdAt).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="child-actions">
                          <button 
                            onClick={() => handleTrackLocation(child)} 
                            className="track-btn-small" 
                            disabled={loading}
                          >
                            {loading && selectedChild?.childPhone === child.childPhone ? "⏳" : "📍"} Track
                          </button>
                          <button 
                            onClick={() => handleLoadHistory(child)} 
                            className="track-btn-small track-btn-secondary" 
                            disabled={loading}
                          >
                            📊 History
                          </button>
                          <button 
                            onClick={() => handleRemoveChild(child.childPhone)} 
                            className="track-btn-small track-btn-danger" 
                            disabled={loading}
                          >
                            🗑️
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {location && selectedChild && !showHistory && (
                  <div className="location-display">
                    <div className="location-header">
                      <div className="location-icon">📍</div>
                      <h4 className="location-title">{selectedChild.childName}'s Location</h4>
                    </div>
                    <div className="location-details">
                      <div className="location-row">
                        <span className="location-label">Latitude:</span>
                        <span className="location-value">{location.latitude?.toFixed(6)}</span>
                      </div>
                      <div className="location-row">
                        <span className="location-label">Longitude:</span>
                        <span className="location-value">{location.longitude?.toFixed(6)}</span>
                      </div>
                      <div className="location-row">
                        <span className="location-label">Accuracy:</span>
                        <span className="location-value">±{Math.round(location.accuracy || 0)}m</span>
                      </div>
                      <div className="location-row">
                        <span className="location-label">Updated:</span>
                        <span className="location-value">
                          {new Date(location.lastUpdated).toLocaleString()}
                        </span>
                      </div>
                    </div>
                    <button 
                      onClick={() => window.open(
                        `https://www.google.com/maps?q=${location.latitude},${location.longitude}`,
                        "_blank"
                      )}
                      className="maps-btn"
                    >
                      🗺️ View on Google Maps
                    </button>
                  </div>
                )}

                {showHistory && locationHistory.length > 0 && (
                  <div className="location-history">
                    <div className="history-header">
                      <h4>📊 Location History ({locationHistory.length} records)</h4>
                      <button 
                        onClick={() => setShowHistory(false)} 
                        className="close-history-btn"
                      >
                        ✕
                      </button>
                    </div>
                    <div className="history-list">
                      {locationHistory.map((loc, idx) => (
                        <div key={idx} className="history-item">
                          <div className="history-time">
                            {new Date(loc.timestamp).toLocaleString()}
                          </div>
                          <div className="history-coords">
                            {loc.latitude?.toFixed(5)}, {loc.longitude?.toFixed(5)}
                            <span className="history-accuracy">±{Math.round(loc.accuracy || 0)}m</span>
                          </div>
                          <button
                            onClick={() => window.open(
                              `https://www.google.com/maps?q=${loc.latitude},${loc.longitude}`,
                              "_blank"
                            )}
                            className="history-map-btn"
                          >
                            🗺️
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="action-buttons">
                  <button 
                    onClick={() => handleViewChange("register")} 
                    className="tracking-btn-secondary"
                  >
                    ➕ Register Another Child
                  </button>
                  <button 
                    onClick={() => handleViewChange("main")} 
                    className="tracking-btn-secondary"
                  >
                    ← Back to Home
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      <section className="features-section">
        <h2 className="section-title">Key Features</h2>
        <div className="features-grid">
          {features.map((feature) => (
            <div key={feature.id} className="feature-card">
              <div className="feature-icon">{feature.icon}</div>
              <h3 className="feature-title">{feature.title}</h3>
              <p className="feature-description">{feature.description}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="stats-section">
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-number">99.9%</div>
            <div className="stat-label">Uptime</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">AES-256</div>
            <div className="stat-label">Encryption</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">&lt;500ms</div>
            <div className="stat-label">Response Time</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">JWT</div>
            <div className="stat-label">Auth Tokens</div>
          </div>
        </div>
      </section>

      <section className="security-section">
        <div className="security-content">
          <div className="security-text">
            <h2>Enterprise-Grade Security</h2>
            <ul className="security-list">
              <li>
                <span className="check-icon">✓</span>
                <span>End-to-end AES-256 encryption for location data</span>
              </li>
              <li>
                <span className="check-icon">✓</span>
                <span>JWT-based authentication with 7-day expiry</span>
              </li>
              <li>
                <span className="check-icon">✓</span>
                <span>Multi-factor authentication with OTP</span>
              </li>
              <li>
                <span className="check-icon">✓</span>
                <span>Role-based access control (RBAC)</span>
              </li>
              <li>
                <span className="check-icon">✓</span>
                <span>Rate limiting and DDoS protection</span>
              </li>
            </ul>
          </div>
          <div className="security-visual">
            <div className="shield-container">
              <div className="shield">🛡️</div>
              <div className="shield-ring ring-1"></div>
              <div className="shield-ring ring-2"></div>
              <div className="shield-ring ring-3"></div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}