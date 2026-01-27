import { useState, useEffect } from "react";
import Auth from "./Auth";
import Home from "./home";
import ChildTracker from "./ChildTracker";
import "./App.css";

const API = "http://localhost:5001";

export default function App() {
  const [token, setToken] = useState(null);
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [currentView, setCurrentView] = useState("home"); // 'home' or 'tracker'

  // Check for existing session on mount
  useEffect(() => {
    const storedToken = localStorage.getItem("authToken");
    const storedUser = localStorage.getItem("user");

    if (storedToken && storedUser) {
      verifyToken(storedToken, JSON.parse(storedUser));
    } else {
      setLoading(false);
    }
  }, []);

  // Verify token validity
  const verifyToken = async (token, userData) => {
    try {
      const response = await fetch(`${API}/profile`, {
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });

      if (response.ok) {
        setToken(token);
        setUser(userData);
        setIsAuthenticated(true);
      } else {
        // Token is invalid, clear storage
        localStorage.removeItem("authToken");
        localStorage.removeItem("user");
      }
    } catch (err) {
      console.error("Token verification failed:", err);
      localStorage.removeItem("authToken");
      localStorage.removeItem("user");
    } finally {
      setLoading(false);
    }
  };

  // Handle login
  const handleLogin = (newToken, userData) => {
    setToken(newToken);
    setUser(userData);
    setIsAuthenticated(true);

    // Persist to localStorage
    localStorage.setItem("authToken", newToken);
    localStorage.setItem("user", JSON.stringify(userData));
  };

  // Handle logout
  const handleLogout = () => {
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
    setCurrentView("home");

    // Clear localStorage
    localStorage.removeItem("authToken");
    localStorage.removeItem("user");
  };

  // Loading screen
  if (loading) {
    return (
      <div style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"
      }}>
        <div style={{
          background: "white",
          padding: "40px",
          borderRadius: "20px",
          textAlign: "center",
          boxShadow: "0 20px 60px rgba(0,0,0,0.3)"
        }}>
          <div style={{ fontSize: "48px", marginBottom: "16px" }}>⏳</div>
          <h2 style={{ margin: "0 0 8px 0", color: "#1a202c" }}>Loading...</h2>
          <p style={{ margin: 0, color: "#718096", fontSize: "14px" }}>
            Please wait
          </p>
        </div>
      </div>
    );
  }

  // Not authenticated - show auth screen
  if (!isAuthenticated) {
    return <Auth onLogin={handleLogin} />;
  }

  // Authenticated - show main app
  // NO NAVIGATION BAR HERE - Let each component handle its own navigation
  return (
    <div className="app-container">
      {/* Main Content - No wrapper navigation */}
      {currentView === "home" && (
        <Home
          userPhone={user?.phone}
          userName={user?.username}
          userRole={user?.role}
          token={token}
          onNavigate={() => setCurrentView("tracker")}
          onLogout={handleLogout}
        />
      )}
      {currentView === "tracker" && (
        <ChildTracker
          token={token}
          userName={user?.username}
          userRole={user?.role}
          onLogout={handleLogout}
          onNavigateHome={() => setCurrentView("home")}
        />
      )}
    </div>
  );
}