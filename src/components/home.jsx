import { useState, useEffect } from "react";
import "./home.css";

const API = "http://localhost:5000";

export default function Home({ userPhone, onNavigate }) {
  const [view, setView] = useState("main"); // main, register, track
  const [parentPhone, setParentPhone] = useState(userPhone || "");
  const [childPhone, setChildPhone] = useState("");
  const [childName, setChildName] = useState("");
  const [otp, setOtp] = useState("");
  const [children, setChildren] = useState([]);
  const [selectedChild, setSelectedChild] = useState(null);
  const [location, setLocation] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(1); // 1: form, 2: otp
  const [theme, setTheme] = useState("light");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  // Auto-populate parent phone and load children when userPhone is available
  useEffect(() => {
    if (userPhone) {
      setParentPhone(userPhone);
      loadChildren(userPhone);
    }
  }, [userPhone]);

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
      title: "Strong Authentication",
      description: "Password + OTP based login following NIST standards.",
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
      description: "AES encryption, SHA-256 hashing, and Base64 encoding.",
    }
  ];

  // Register child - send OTP
  const handleRegisterChild = async () => {
    const phoneRegex = /^\+[1-9]\d{9,14}$/;
    
    if (!parentPhone || !childPhone || !childName) {
      setError("All fields are required");
      return;
    }
    
    if (!phoneRegex.test(parentPhone.replace(/[\s-]/g, '')) || !phoneRegex.test(childPhone.replace(/[\s-]/g, ''))) {
      setError("Invalid phone format. Use +[country][number]");
      return;
    }
    
    setLoading(true);
    setError("");
    
    try {
      const res = await fetch(`${API}/register-child`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ parentPhone, childPhone, childName })
      });

      const data = await res.json();
      
      if (!res.ok) {
        setError(data.error);
        return;
      }

      setMessage(data.message);
      setStep(2);
    } catch (err) {
      setError("Network error. Please check if server is running.");
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
      const res = await fetch(`${API}/verify-parent`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ parentPhone, otp })
      });

      const data = await res.json();
      
      if (!res.ok) {
        setError(data.error);
        return;
      }

      setMessage("✅ " + data.message);
      setTimeout(() => {
        resetForm();
        setView("track");
      }, 1500);
    } catch (err) {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  // Load parent's children
  const loadChildren = async (phone) => {
    if (!phone) return;
    
    try {
      const res = await fetch(`${API}/my-children`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ parentPhone: phone })
      });

      const data = await res.json();
      
      if (res.ok) {
        setChildren(data.children);
      }
    } catch (err) {
      console.error("Failed to load children:", err);
    }
  };

  // Track child location
  const handleTrackLocation = async (child) => {
    setLoading(true);
    setError("");
    setSelectedChild(child);
    
    try {
      const res = await fetch(`${API}/track-location`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          parentPhone,
          childPhone: child.childPhone
        })
      });

      const data = await res.json();
      
      if (!res.ok) {
        setError(data.error);
        setLocation(null);
        return;
      }

      setLocation(data);
    } catch (err) {
      setError("Network error. Please try again.");
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

  const handleViewTrack = () => {
    const phoneRegex = /^\+[1-9]\d{9,14}$/;
    
    if (!parentPhone) {
      setError("Please enter your phone number");
      return;
    }
    
    if (!phoneRegex.test(parentPhone.replace(/[\s-]/g, ''))) {
      setError("Invalid phone format");
      return;
    }
    
    setError("");
    setView("track");
    loadChildren(parentPhone);
  };

  return (
    <div className="home-container">
      {/* Theme Toggle */}
      <div className="theme-toggle" onClick={() => setTheme(theme === "light" ? "dark" : "light")}>
        {theme === "light" ? "🌙 Dark" : "☀️ Light"}
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
            Track your child's real-time location securely using strong authentication, encryption, and access control.
          </p>

          {view === "main" && (
            <div className="tracking-container">
              <div className="tracking-card">
                <div className="tracking-icon">🔍</div>
                <h2 className="tracking-title">Track Your Child</h2>
                <p className="tracking-subtitle">
                  Enter your phone number to register a child or track existing children
                </p>

                <div className="tracking-form">
                  <div className="input-group">
                    <label>Your Phone Number (Parent)</label>
                    <input
                      type="text"
                      placeholder="+91**********"
                      value={parentPhone}
                      onChange={(e) => {
                        setParentPhone(e.target.value);
                        setError("");
                      }}
                      className="tracking-input"
                      disabled={userPhone ? true : false}
                    />
                  </div>
                  {error && <div className="tracking-error">{error}</div>}
                  
                  <div className="action-buttons">
                    <button onClick={handleViewTrack} className="tracking-btn">
                      View My Children
                    </button>
                    <button 
                      onClick={() => {
                        if (parentPhone) {
                          setView("register");
                          setError("");
                        } else {
                          setError("Please enter your phone number first");
                        }
                      }}
                      className="tracking-btn-secondary"
                    >
                      Register New Child
                    </button>
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
                  One-time setup to link your child's phone number
                </p>

                {step === 1 && (
                  <div className="tracking-form">
                    <div className="input-group">
                      <label>Child's Name</label>
                      <input
                        type="text"
                        placeholder="Enter child's name"
                        value={childName}
                        onChange={(e) => setChildName(e.target.value)}
                        className="tracking-input"
                        disabled={loading}
                      />
                    </div>
                    <div className="input-group">
                      <label>Child's Phone Number</label>
                      <input
                        type="text"
                        placeholder="+91**********"
                        value={childPhone}
                        onChange={(e) => setChildPhone(e.target.value)}
                        className="tracking-input"
                        disabled={loading}
                      />
                    </div>
                    {error && <div className="tracking-error">{error}</div>}
                    {message && <div className="tracking-success">{message}</div>}
                    
                    <div className="action-buttons">
                      <button onClick={handleRegisterChild} className="tracking-btn" disabled={loading}>
                        {loading ? "Sending OTP..." : "Send Verification OTP"}
                      </button>
                      <button onClick={() => { setView("main"); resetForm(); }} className="tracking-btn-secondary">
                        ← Back
                      </button>
                    </div>
                    <p className="tracking-note">
                      OTP will be sent to your phone ({parentPhone}) for verification
                    </p>
                  </div>
                )}

                {step === 2 && (
                  <div className="tracking-form">
                    <div className="verification-info">
                      <span className="info-icon">📱</span>
                      <p>Verification code sent to your phone</p>
                    </div>
                    <div className="input-group">
                      <label>Enter 6-Digit OTP</label>
                      <input
                        type="text"
                        placeholder="000000"
                        value={otp}
                        onChange={(e) => {
                          const val = e.target.value.replace(/\D/g, '').slice(0, 6);
                          setOtp(val);
                          setError("");
                        }}
                        className="tracking-input otp-input"
                        maxLength={6}
                        disabled={loading}
                      />
                    </div>
                    {error && <div className="tracking-error">{error}</div>}
                    {message && <div className="tracking-success">{message}</div>}
                    
                    <div className="action-buttons">
                      <button onClick={handleVerifyOTP} className="tracking-btn" disabled={loading || otp.length !== 6}>
                        {loading ? "Verifying..." : "Verify & Register"}
                      </button>
                      <button onClick={() => { setView("main"); resetForm(); }} className="tracking-btn-secondary">
                        ← Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {view === "track" && (
            <div className="tracking-container">
              <div className="tracking-card">
                <div className="tracking-icon">📍</div>
                <h2 className="tracking-title">Track Location</h2>
                <p className="tracking-subtitle">
                  Select a child to view their real-time location
                </p>

                {children.length === 0 ? (
                  <div className="no-children">
                    <p>No children registered yet</p>
                    <button onClick={() => setView("register")} className="tracking-btn">
                      Register Your First Child
                    </button>
                  </div>
                ) : (
                  <div className="children-list">
                    {children.map((child, index) => (
                      <div key={index} className="child-item">
                        <div className="child-info">
                          <h4>{child.childName}</h4>
                          <p>{child.childPhone}</p>
                        </div>
                        <button onClick={() => handleTrackLocation(child)} className="track-btn-small" disabled={loading}>
                          {loading && selectedChild?.childPhone === child.childPhone ? "Loading..." : "Track"}
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {location && (
                  <div className="location-display">
                    <div className="location-icon">📍</div>
                    <div className="location-details">
                      <h4>{selectedChild?.childName}'s Location</h4>
                      <p className="location-address">{location.address || "Address not available"}</p>
                      <p className="location-coords">
                        Lat: {location.latitude}, Long: {location.longitude}
                      </p>
                      <p className="location-time">
                        Updated: {new Date(location.lastUpdated).toLocaleString()}
                      </p>
                    </div>
                  </div>
                )}

                {error && <div className="tracking-error">{error}</div>}

                <div className="action-buttons">
                  {location && (
                    <button 
                      onClick={() => window.open(`https://www.google.com/maps?q=${location.latitude},${location.longitude}`, '_blank')}
                      className="tracking-btn"
                    >
                      View on Google Maps
                    </button>
                  )}
                  <button onClick={() => setView("register")} className="tracking-btn-secondary">
                    Register Another Child
                  </button>
                  <button onClick={() => { setView("main"); setLocation(null); setSelectedChild(null); }} className="tracking-btn-secondary">
                    ← Back
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
            <div className="stat-number">256-bit</div>
            <div className="stat-label">Encryption</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">&lt;1s</div>
            <div className="stat-label">Response Time</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">24/7</div>
            <div className="stat-label">Monitoring</div>
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
                <span>End-to-end encryption for all data</span>
              </li>
              <li>
                <span className="check-icon">✓</span>
                <span>Multi-factor authentication (MFA)</span>
              </li>
              <li>
                <span className="check-icon">✓</span>
                <span>NIST compliant password policies</span>
              </li>
              <li>
                <span className="check-icon">✓</span>
                <span>Role-based access control (RBAC)</span>
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