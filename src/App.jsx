import { useEffect, useState } from "react";
import Home from "./components/home";
import ChildTracker from "./components/ChildTracker";
import "./App.css";

const API = "http://localhost:5000";


export default function App() {
  const [page, setPage] = useState("login");
  const [form, setForm] = useState({
    username: "",
    password: "",
    phone: ""
  });
  const [otp, setOtp] = useState("");
  const [hint, setHint] = useState("");
  const [phone, setPhone] = useState("");
  const [theme, setTheme] = useState("light");
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [showModal, setShowModal] = useState(false);
  const [modalContent, setModalContent] = useState({ type: "", text: "" });
  const [userPhone, setUserPhone] = useState("");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const showPopup = (type, text, callback) => {
    setModalContent({ type, text, callback });
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    if (modalContent.callback) {
      modalContent.callback();
    }
  };

  const handle = e => {
    const { name, value } = e.target;
    setForm({ ...form, [name]: value });
    if (errors[name]) {
      setErrors({ ...errors, [name]: "" });
    }
  };

  const validateSignup = () => {
    const newErrors = {};

    if (!form.username || form.username.trim().length < 3) {
      newErrors.username = "Username must be at least 3 characters";
    } else if (!/^[a-zA-Z0-9_]+$/.test(form.username)) {
      newErrors.username = "Username can only contain letters, numbers, and underscores";
    }

    if (!form.password || form.password.length < 8 || !/[A-Z]/.test(form.password) || !/[a-z]/.test(form.password) || !/[0-9]/.test(form.password) || !/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;'`~]/.test(form.password)) {
      newErrors.password = "Password must be 8+ characters with uppercase, lowercase, number, and special character";
    }

    if (!form.phone) {
      newErrors.phone = "Phone number is required";
    } else {
      const cleaned = form.phone.replace(/[\s-]/g, '');
      if (!/^\+[1-9]\d{9,14}$/.test(cleaned)) {
        newErrors.phone = "Phone must start with + and country code (e.g., +911234567890)";
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const validateLogin = () => {
    const newErrors = {};

    if (!form.username || form.username.trim().length === 0) {
      newErrors.username = "Username is required";
    }

    if (!form.password || form.password.length === 0) {
      newErrors.password = "Password is required";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const signup = async () => {
    if (!validateSignup()) return;

    setLoading(true);
    try {
      const res = await fetch(`${API}/signup/send-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form)
      });

      const data = await res.json();
      
      if (!res.ok) {
        showPopup("error", data.error || "Signup failed");
        return;
      }

      setPhone(data.phone);
      setHint(data.phoneHint);
      showPopup("success", data.message);
      setPage("signup-otp");
    } catch (err) {
      console.error("Signup error:", err);
      showPopup("error", "Network error. Please check if the server is running.");
    } finally {
      setLoading(false);
    }
  };

  const verifySignupOTP = async () => {
    if (!otp || otp.length !== 6) {
      showPopup("error", "Please enter a valid 6-digit OTP");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API}/signup/verify-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone, otp })
      });

      const data = await res.json();

      if (!res.ok) {
        showPopup("error", data.error || "Invalid OTP");
        return;
      }

      showPopup("success", data.message, () => {
        setForm({ username: "", password: "", phone: "" });
        setOtp("");
        setPage("login");
      });
    } catch (err) {
      console.error("Verification error:", err);
      showPopup("error", "Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const login = async () => {
    if (!validateLogin()) return;

    setLoading(true);
    try {
      const res = await fetch(`${API}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: form.username,
          password: form.password
        })
      });

      const data = await res.json();
      
      if (!res.ok) {
        showPopup("error", data.error || "Login failed");
        return;
      }

      setPhone(data.phone);
      setHint(data.phoneHint);
      setUserPhone(data.phone);
      showPopup("success", data.message);
      setPage("login-otp");
    } catch (err) {
      console.error("Login error:", err);
      showPopup("error", "Network error. Please check if the server is running.");
    } finally {
      setLoading(false);
    }
  };

  const verifyLoginOTP = async () => {
    if (!otp || otp.length !== 6) {
      showPopup("error", "Please enter a valid 6-digit OTP");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API}/verify-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone, otp })
      });

      const data = await res.json();

      if (!res.ok) {
        showPopup("error", data.error || "Invalid OTP");
        return;
      }

      showPopup("success", "Login successful!", () => {
        setPage("home");
      });
    } catch (err) {
      console.error("Verification error:", err);
      showPopup("error", "Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e, action) => {
    if (e.key === "Enter" && !loading) {
      action();
    }
  };

  return (
    <>
      {page !== "home" && page !== "child-tracker" && (
        <div className="theme-toggle" onClick={() =>
          setTheme(theme === "light" ? "dark" : "light")
        }>
          {theme === "light" ? "🌙 Dark" : "☀️ Light"}
        </div>
      )}

      {showModal && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <div className={`modal-icon ${modalContent.type}`}>
              {modalContent.type === "success" ? "✓" : "✕"}
            </div>
            <h3 className="modal-title">
              {modalContent.type === "success" ? "Success" : "Error"}
            </h3>
            <p className="modal-message">{modalContent.text}</p>
            <button className="modal-button" onClick={closeModal}>
              OK
            </button>
          </div>
        </div>
      )}

      {page === "child-tracker" ? (
        <ChildTracker />
      ) : page === "home" ? (
        <Home userPhone={userPhone} onNavigate={setPage} />
      ) : (
        <div className="auth-wrapper">
          <div className="box">

            {page === "signup" && (
              <>
                <h2>Create Account</h2>
                <div>
                  <input 
                    name="username" 
                    placeholder="Username" 
                    value={form.username}
                    onChange={handle}
                    onKeyPress={(e) => handleKeyPress(e, signup)}
                    disabled={loading}
                  />
                  {errors.username && <div className="error">{errors.username}</div>}
                </div>
                <div>
                  <input 
                    type="password" 
                    name="password" 
                    placeholder="Password (min 8 chars, A-z, 0-9, !@#...)" 
                    value={form.password}
                    onChange={handle}
                    onKeyPress={(e) => handleKeyPress(e, signup)}
                    disabled={loading}
                  />
                  {errors.password && <div className="error">{errors.password}</div>}
                </div>
                <div>
                  <input 
                    name="phone" 
                    placeholder="+91**********" 
                    value={form.phone}
                    onChange={handle}
                    onKeyPress={(e) => handleKeyPress(e, signup)}
                    disabled={loading}
                  />
                  {errors.phone && <div className="error">{errors.phone}</div>}
                </div>
                <button onClick={signup} disabled={loading}>
                  {loading ? "Sending OTP..." : "Continue"}
                </button>
                <div className="auth-footer">
                  <span>Already have an account?</span>
                  <span className="signup-link" onClick={() => {
                    setPage("login");
                    setErrors({});
                    setForm({ username: "", password: "", phone: "" });
                  }}>Login</span>
                </div>
              </>
            )}

            {page === "signup-otp" && (
              <>
                <h2>Verify Phone Number</h2>
                <div className="otp-hint">
                  Enter the OTP sent to ***{hint}
                  <br />
                </div>
                <input 
                  placeholder="Enter 6-digit OTP" 
                  value={otp}
                  onChange={e => {
                    const val = e.target.value.replace(/\D/g, '').slice(0, 6);
                    setOtp(val);
                  }}
                  onKeyPress={(e) => handleKeyPress(e, verifySignupOTP)}
                  maxLength={6}
                  disabled={loading}
                />
                <button onClick={verifySignupOTP} disabled={loading || otp.length !== 6}>
                  {loading ? "Verifying..." : "Verify & Create Account"}
                </button>
                <div className="auth-footer">
                  <span className="signup-link" onClick={() => {
                    setPage("signup");
                    setOtp("");
                  }}>Back to Signup</span>
                </div>
              </>
            )}

            {page === "login" && (
              <>
                <h2>Welcome Back</h2>
                <div>
                  <input 
                    name="username" 
                    placeholder="Username" 
                    value={form.username}
                    onChange={handle}
                    onKeyPress={(e) => handleKeyPress(e, login)}
                    disabled={loading}
                  />
                  {errors.username && <div className="error">{errors.username}</div>}
                </div>
                <div>
                  <input 
                    type="password" 
                    name="password" 
                    placeholder="Password" 
                    value={form.password}
                    onChange={handle}
                    onKeyPress={(e) => handleKeyPress(e, login)}
                    disabled={loading}
                  />
                  {errors.password && <div className="error">{errors.password}</div>}
                </div>
                <button onClick={login} disabled={loading}>
                  {loading ? "Logging in..." : "Login"}
                </button>
                <div className="auth-footer">
                  <span>New user?</span>
                  <span className="signup-link" onClick={() => {
                    setPage("signup");
                    setErrors({});
                    setForm({ username: "", password: "", phone: "" });
                  }}>Create account</span>
                </div>
              </>
            )}

            {page === "login-otp" && (
              <>
                <h2>OTP Verification</h2>
                <div className="otp-hint">
                  Enter the OTP sent to ***{hint}
                  <br />
                </div>
                <input 
                  placeholder="Enter 6-digit OTP" 
                  value={otp}
                  onChange={e => {
                    const val = e.target.value.replace(/\D/g, '').slice(0, 6);
                    setOtp(val);
                  }}
                  onKeyPress={(e) => handleKeyPress(e, verifyLoginOTP)}
                  maxLength={6}
                  disabled={loading}
                />
                <button onClick={verifyLoginOTP} disabled={loading || otp.length !== 6}>
                  {loading ? "Verifying..." : "Verify"}
                </button>
                <div className="auth-footer">
                  <span className="signup-link" onClick={() => {
                    setPage("login");
                    setOtp("");
                  }}>Back to Login</span>
                </div>
              </>
            )}

          </div>
        </div>
      )}
    </>
  );
}