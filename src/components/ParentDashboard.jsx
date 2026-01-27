import { useState, useEffect } from 'react';
import './ParentDashboard.css';

const API = 'http://localhost:5001';

export default function ParentDashboard({ user, token, onLogout }) {
  const [children, setChildren] = useState([]);
  const [selectedChild, setSelectedChild] = useState(null);
  const [location, setLocation] = useState(null);
  const [locationHistory, setLocationHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showRegisterForm, setShowRegisterForm] = useState(false);
  const [newChild, setNewChild] = useState({ name: '', phone: '' });
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [otpDisplay, setOtpDisplay] = useState(null); // New state for OTP display

  // Load children on mount
  useEffect(() => {
    loadChildren();
  }, []);

  // Auto-refresh location
  useEffect(() => {
    let interval;
    if (autoRefresh && selectedChild) {
      interval = setInterval(() => {
        trackChildLocation(selectedChild, false);
      }, 10000); // Refresh every 10 seconds
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh, selectedChild]);

  const apiCall = async (endpoint, options = {}) => {
    try {
      const response = await fetch(`${API}${endpoint}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
          ...options.headers
        }
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Request failed');
      }

      return data;
    } catch (err) {
      throw new Error(err.message);
    }
  };

  const loadChildren = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await apiCall('/my-children');
      setChildren(data.children || []);
      if (data.children?.length === 0) {
        setShowRegisterForm(true);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const trackChildLocation = async (child, showMessages = true) => {
    if (showMessages) setLoading(true);
    setError('');
    
    try {
      const data = await apiCall('/track-location', {
        method: 'POST',
        body: JSON.stringify({ childPhone: child.childPhone })
      });

      setLocation(data.location);
      setSelectedChild(child);
      
      if (showMessages) {
        setSuccess(`✅ Tracking ${child.childName}'s location`);
        setTimeout(() => setSuccess(''), 3000);
      }
    } catch (err) {
      if (err.message.includes('No location data')) {
        setError(`${child.childName} hasn't shared location yet. They need to use the child GPS page first.`);
      } else {
        setError(err.message);
      }
    } finally {
      if (showMessages) setLoading(false);
    }
  };

  const loadLocationHistory = async (child) => {
    setLoading(true);
    setError('');
    
    try {
      const data = await apiCall(`/location-history/${child.childPhone}?limit=50`);
      setLocationHistory(data.locations || []);
      setSelectedChild(child);
      setSuccess(`✅ Loaded ${data.locations?.length || 0} location points`);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const registerChild = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setOtpDisplay(null); // Clear previous OTP
    
    try {
      // This will send OTP to parent's phone
      const data = await apiCall('/register-child', {
        method: 'POST',
        body: JSON.stringify({
          childPhone: newChild.phone.trim(),
          childName: newChild.name.trim()
        })
      });

      // Display OTP in console with clear formatting
      if (data.otp) {
        console.clear(); // Clear console for better visibility
        console.log('='.repeat(60));
        console.log('🔐 OTP FOR VERIFICATION');
        console.log('='.repeat(60));
        console.log('');
        console.log('  OTP CODE:      ', data.otp);
        console.log('  Child Name:    ', newChild.name.trim());
        console.log('  Child Phone:   ', newChild.phone.trim());
        console.log('  Parent Phone:  ', user.phone || user.username);
        console.log('  Generated at:  ', new Date().toLocaleString());
        console.log('');
        console.log('='.repeat(60));
        console.log('⚠️  Share this OTP with your child to verify');
        console.log('='.repeat(60));

        // Store OTP for UI display
        setOtpDisplay({
          otp: data.otp,
          childName: newChild.name.trim(),
          childPhone: newChild.phone.trim(),
          timestamp: new Date().toLocaleString()
        });
      }

      setSuccess(`✅ Child registered! Check the OTP display below.`);
      
      // Don't close form immediately - keep it open to show OTP
      // await loadChildren();
      // setShowRegisterForm(false);
      // setNewChild({ name: '', phone: '' });
      
      // Keep success message visible longer
      setTimeout(() => setSuccess(''), 10000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const closeOtpDisplay = () => {
    setOtpDisplay(null);
    setShowRegisterForm(false);
    setNewChild({ name: '', phone: '' });
    loadChildren();
  };

  const removeChild = async (childPhone) => {
    if (!confirm('Are you sure you want to remove this child from tracking?')) {
      return;
    }

    setLoading(true);
    setError('');
    
    try {
      await apiCall(`/remove-child/${childPhone}`, { method: 'DELETE' });
      setSuccess('✅ Child removed');
      setTimeout(() => setSuccess(''), 3000);
      await loadChildren();
      if (selectedChild?.childPhone === childPhone) {
        setSelectedChild(null);
        setLocation(null);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const openInGoogleMaps = () => {
    if (location) {
      window.open(`https://www.google.com/maps?q=${location.latitude},${location.longitude}`, '_blank');
    }
  };

  return (
    <div className="dashboard">
      {/* Header */}
      <div className="dashboard-header">
        <div className="header-left">
          <h1>🏠 Parent Dashboard</h1>
          <p>Welcome back, {user.username}!</p>
        </div>
        <div className="header-right">
          <span className="user-badge">👤 {user.role}</span>
          <button onClick={onLogout} className="btn btn-logout">🚪 Logout</button>
        </div>
      </div>

      <div className="dashboard-content">
        {/* Left Sidebar - Children List */}
        <div className="sidebar">
          <div className="sidebar-header">
            <h2>📱 Registered Children</h2>
            <button 
              onClick={() => setShowRegisterForm(!showRegisterForm)} 
              className="btn btn-sm btn-primary"
            >
              {showRegisterForm ? '✕' : '+ Add Child'}
            </button>
          </div>

          {/* Register Form */}
          {showRegisterForm && (
            <form onSubmit={registerChild} className="register-form">
              <h3>Register New Child</h3>
              
              {/* OTP Display */}
              {otpDisplay && (
                <div className="otp-display-box">
                  <div className="otp-header">
                    <h4>🔐 OTP Generated</h4>
                    <button 
                      type="button" 
                      onClick={closeOtpDisplay} 
                      className="otp-close"
                    >
                      ✕
                    </button>
                  </div>
                  <div className="otp-content">
                    <div className="otp-code-large">{otpDisplay.otp}</div>
                    <div className="otp-details">
                      <p><strong>Child:</strong> {otpDisplay.childName}</p>
                      <p><strong>Phone:</strong> {otpDisplay.childPhone}</p>
                      <p><strong>Generated:</strong> {otpDisplay.timestamp}</p>
                    </div>
                    <div className="otp-instructions">
                      <p>⚠️ Share this OTP with your child</p>
                      <p>✅ Also check the browser console (F12) for details</p>
                    </div>
                  </div>
                  <button 
                    type="button" 
                    onClick={closeOtpDisplay} 
                    className="btn btn-success btn-block"
                  >
                    ✓ Done - Close Registration
                  </button>
                </div>
              )}

              {/* Registration Form Fields */}
              {!otpDisplay && (
                <>
                  <div className="form-group">
                    <label>Child's Name:</label>
                    <input
                      type="text"
                      value={newChild.name}
                      onChange={(e) => setNewChild({...newChild, name: e.target.value})}
                      placeholder="Enter child's name"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>Child's Phone:</label>
                    <input
                      type="tel"
                      value={newChild.phone}
                      onChange={(e) => setNewChild({...newChild, phone: e.target.value})}
                      placeholder="+919876543210"
                      required
                    />
                  </div>
                  <button type="submit" className="btn btn-primary" disabled={loading}>
                    {loading ? '⏳ Registering...' : '✓ Register Child'}
                  </button>
                </>
              )}
            </form>
          )}

          {/* Children List */}
          <div className="children-list">
            {loading && children.length === 0 ? (
              <div className="loading">Loading children...</div>
            ) : children.length === 0 ? (
              <div className="empty-state">
                <p>👶 No children registered yet</p>
                <p style={{fontSize: '14px', color: '#666', marginTop: '8px'}}>
                  Click "Add Child" to register your first child
                </p>
              </div>
            ) : (
              children.map((child) => (
                <div 
                  key={child._id} 
                  className={`child-card ${selectedChild?.childPhone === child.childPhone ? 'selected' : ''}`}
                >
                  <div className="child-info">
                    <h3>{child.childName}</h3>
                    <p className="phone">📞 {child.childPhone}</p>
                    <p className="registered">Registered: {new Date(child.createdAt).toLocaleDateString()}</p>
                  </div>
                  <div className="child-actions">
                    <button 
                      onClick={() => trackChildLocation(child)} 
                      className="btn btn-sm btn-success"
                      disabled={loading}
                    >
                      📍 Track
                    </button>
                    <button 
                      onClick={() => loadLocationHistory(child)} 
                      className="btn btn-sm btn-info"
                      disabled={loading}
                    >
                      📊 History
                    </button>
                    <button 
                      onClick={() => removeChild(child.childPhone)} 
                      className="btn btn-sm btn-danger"
                      disabled={loading}
                    >
                      🗑️
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Main Content - Map and Location */}
        <div className="main-content">
          {error && (
            <div className="alert alert-error">
              {error}
              <button onClick={() => setError('')} className="alert-close">✕</button>
            </div>
          )}
          
          {success && (
            <div className="alert alert-success">
              {success}
              <button onClick={() => setSuccess('')} className="alert-close">✕</button>
            </div>
          )}

          {!selectedChild && !location ? (
            <div className="empty-main">
              <div className="empty-icon">📍</div>
              <h2>No Location Selected</h2>
              <p>Select a child from the sidebar and click "Track" to view their location</p>
              <div className="instruction-box">
                <h3>📋 How to use:</h3>
                <ol>
                  <li>Register your child using the "Add Child" button</li>
                  <li>Copy the OTP displayed after registration</li>
                  <li>Child opens the GPS sharing page (child-gps.html)</li>
                  <li>Child enters the OTP to verify and start sharing location</li>
                  <li>Click "Track" to view their real-time location</li>
                </ol>
                <div className="note-box">
                  <p><strong>📝 Note:</strong> OTP will be displayed in the registration form and in the browser console (press F12 to open)</p>
                </div>
              </div>
            </div>
          ) : (
            <>
              {/* Location Info */}
              {location && (
                <div className="location-section">
                  <div className="section-header">
                    <h2>📍 {selectedChild.childName}'s Location</h2>
                    <div className="header-actions">
                      <label className="auto-refresh">
                        <input
                          type="checkbox"
                          checked={autoRefresh}
                          onChange={(e) => setAutoRefresh(e.target.checked)}
                        />
                        🔄 Auto-refresh (10s)
                      </label>
                      <button onClick={openInGoogleMaps} className="btn btn-sm btn-primary">
                        🗺️ Open in Google Maps
                      </button>
                      <button onClick={() => trackChildLocation(selectedChild)} className="btn btn-sm btn-success">
                        🔄 Refresh
                      </button>
                    </div>
                  </div>

                  <div className="location-grid">
                    <div className="location-card">
                      <div className="card-header">Coordinates</div>
                      <div className="card-body">
                        <div className="coord-row">
                          <span className="label">Latitude:</span>
                          <span className="value">{location.latitude?.toFixed(6)}</span>
                        </div>
                        <div className="coord-row">
                          <span className="label">Longitude:</span>
                          <span className="value">{location.longitude?.toFixed(6)}</span>
                        </div>
                        <div className="coord-row">
                          <span className="label">Accuracy:</span>
                          <span className="value">{location.accuracy?.toFixed(0)}m</span>
                        </div>
                      </div>
                    </div>

                    <div className="location-card">
                      <div className="card-header">Timestamp</div>
                      <div className="card-body">
                        <div className="coord-row">
                          <span className="label">Last Updated:</span>
                          <span className="value">{new Date(location.lastUpdated).toLocaleString()}</span>
                        </div>
                        <div className="coord-row">
                          <span className="label">Time Ago:</span>
                          <span className="value">{getTimeAgo(location.lastUpdated)}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Map */}
                  <div className="map-container">
                    <iframe
                      width="100%"
                      height="450"
                      frameBorder="0"
                      style={{ border: 0, borderRadius: '10px' }}
                      src={`https://www.google.com/maps/embed/v1/place?key=YOUR_GOOGLE_MAPS_API_KEY&q=${location.latitude},${location.longitude}&zoom=15`}
                      allowFullScreen
                      title="Child Location Map"
                    />
                    <div className="map-overlay">
                      <p>⚠️ Replace YOUR_GOOGLE_MAPS_API_KEY with your actual Google Maps API key</p>
                      <p>Or use the "Open in Google Maps" button above</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Location History */}
              {locationHistory.length > 0 && (
                <div className="history-section">
                  <h2>📊 Location History ({locationHistory.length} points)</h2>
                  <div className="history-list">
                    {locationHistory.map((loc, index) => (
                      <div key={index} className="history-item">
                        <div className="history-time">
                          {new Date(loc.timestamp).toLocaleString()}
                        </div>
                        <div className="history-coords">
                          {loc.latitude.toFixed(6)}, {loc.longitude.toFixed(6)}
                        </div>
                        <div className="history-accuracy">
                          ±{loc.accuracy?.toFixed(0)}m
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// Helper function to get time ago
function getTimeAgo(timestamp) {
  const now = new Date();
  const then = new Date(timestamp);
  const seconds = Math.floor((now - then) / 1000);

  if (seconds < 60) return `${seconds} seconds ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
  return `${Math.floor(seconds / 86400)} days ago`;
}