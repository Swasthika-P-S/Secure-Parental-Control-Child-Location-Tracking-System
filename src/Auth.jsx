import { useState } from "react";
import "./Auth.css";

const API = "http://localhost:5001";

export default function Auth({ onLogin }) {
  const [mode, setMode] = useState("login"); // 'login', 'signup', or 'forgot'
  const [step, setStep] = useState(1); // 1: credentials, 2: OTP
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [phone, setPhone] = useState("");
  const [otp, setOtp] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [phoneHint, setPhoneHint] = useState("");
  const [serverPhone, setServerPhone] = useState("");

  // Validation helpers
  const validateUsername = (value) => {
    if (value.length < 3) return "Username must be at least 3 characters";
    if (!/^[a-zA-Z0-9_]+$/.test(value)) return "Username can only contain letters, numbers, and underscores";
    return null;
  };

  const validatePassword = (value) => {
    if (value.length < 8) return "Password must be at least 8 characters";
    if (!/[A-Z]/.test(value)) return "Password must contain an uppercase letter";
    if (!/[a-z]/.test(value)) return "Password must contain a lowercase letter";
    if (!/[0-9]/.test(value)) return "Password must contain a number";
    return null;
  };

  const validatePhone = (value) => {
    // Remove spaces and dashes for validation
    const cleaned = value.replace(/[\s-]/g, "");
    const phoneRegex = /^\+?[1-9]\d{9,14}$/;
    if (!phoneRegex.test(cleaned)) {
      return "Invalid phone format. Use +[country][number]";
    }
    return null;
  };

  // Normalize phone number - remove spaces and dashes, ensure + prefix
  const normalizePhone = (phoneStr) => {
    let normalized = phoneStr.trim().replace(/[\s-]/g, "");
    // Add + if missing and doesn't start with +
    if (!normalized.startsWith('+') && /^\d/.test(normalized)) {
      normalized = '+' + normalized;
    }
    console.log('🔧 Phone normalized:', phoneStr, '→', normalized);
    return normalized;
  };

  // API call helper with enhanced debugging
  const apiCall = async (endpoint, body) => {
    try {
      console.log('📤 API Request:', {
        endpoint: `${API}${endpoint}`,
        body: body
      });

      const response = await fetch(`${API}${endpoint}`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      });

      console.log('📥 Response Status:', response.status);

      const textResponse = await response.text();
      console.log('📥 Raw Response:', textResponse);

      let data;
      try {
        data = JSON.parse(textResponse);
      } catch (parseError) {
        console.error('❌ JSON Parse Error:', parseError);
        throw new Error('Server returned invalid response');
      }

      console.log('📥 Parsed Response:', data);

      if (!response.ok) {
        throw new Error(data.error || data.message || `Request failed with status ${response.status}`);
      }

      if (data.success === false) {
        throw new Error(data.error || 'Request failed');
      }

      return data;
    } catch (err) {
      console.error('❌ API Error:', err);
      
      if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
        throw new Error('Cannot connect to server. Please ensure the server is running on port 5001.');
      }
      
      throw err;
    }
  };

  // Signup - Send OTP
  const handleSignupSendOTP = async () => {
    setError("");
    setMessage("");

    console.log('🚀 Starting signup OTP send...');

    // Validation
    const usernameError = validateUsername(username);
    if (usernameError) {
      setError(usernameError);
      return;
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      setError(passwordError);
      return;
    }

    const phoneError = validatePhone(phone);
    if (phoneError) {
      setError(phoneError);
      return;
    }

    setLoading(true);

    try {
      const normalizedPhone = normalizePhone(phone);
      
      console.log('📞 Sending signup OTP with:', {
        username: username.trim(),
        phone: normalizedPhone
      });

      const data = await apiCall("/signup/send-otp", {
        username: username.trim(),
        password,
        phone: normalizedPhone
      });

      console.log('✅ Signup OTP sent successfully:', data);

      // Store phone from server response (this is the authoritative phone number)
      if (data.phone) {
        setServerPhone(data.phone);
        console.log('💾 Stored server phone:', data.phone);
      }

      setPhoneHint(data.phoneHint || phone.slice(-4));
      setMessage(data.message || "✅ OTP sent to your phone!");
      setStep(2);
    } catch (err) {
      console.error('❌ Signup OTP send failed:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Signup - Verify OTP
  const handleSignupVerifyOTP = async () => {
    if (otp.length !== 6) {
      setError("Please enter a valid 6-digit OTP");
      return;
    }

    setLoading(true);
    setError("");

    try {
      // IMPORTANT: Use serverPhone (from server response) if available
      const phoneToUse = serverPhone || normalizePhone(phone);
      
      console.log('🔐 Verifying signup OTP:', {
        phone: phoneToUse,
        otp: otp.trim(),
        serverPhone: serverPhone,
        inputPhone: phone
      });

      const data = await apiCall("/signup/verify-otp", {
        phone: phoneToUse,
        otp: otp.trim()
      });

      console.log('✅ Signup verification successful:', data);

      setMessage(data.message || "✅ Account created successfully! Logging you in...");
      
      setTimeout(() => {
        if (data.token && data.user) {
          onLogin(data.token, data.user);
        } else {
          setError("Login failed: Invalid response from server");
        }
      }, 1500);
    } catch (err) {
      console.error('❌ Signup verification failed:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Login - Send OTP
  const handleLoginSendOTP = async () => {
    setError("");
    setMessage("");

    console.log('🚀 Starting login OTP send...');

    if (!username.trim() || !password) {
      setError("Username and password are required");
      return;
    }

    setLoading(true);

    try {
      console.log('📞 Sending login OTP for:', username.trim());

      const data = await apiCall("/login", {
        username: username.trim(),
        password
      });

      console.log('✅ Login OTP sent successfully:', data);

      // Store phone from server response
      if (data.phone) {
        setServerPhone(data.phone);
        setPhone(data.phone); // Update phone state too
        console.log('💾 Stored server phone:', data.phone);
      }

      setPhoneHint(data.phoneHint || "****");
      setMessage(data.message || "✅ OTP sent to your phone!");
      setStep(2);
    } catch (err) {
      console.error('❌ Login OTP send failed:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Login - Verify OTP
  const handleLoginVerifyOTP = async () => {
    if (otp.length !== 6) {
      setError("Please enter a valid 6-digit OTP");
      return;
    }

    setLoading(true);
    setError("");

    try {
      // Use serverPhone from the login response
      const phoneToUse = serverPhone || normalizePhone(phone);
      
      if (!phoneToUse) {
        throw new Error("Phone number not available. Please go back and try again.");
      }

      console.log('🔐 Verifying login OTP:', {
        phone: phoneToUse,
        otp: otp.trim(),
        serverPhone: serverPhone
      });

      const data = await apiCall("/login/verify-otp", {
        phone: phoneToUse,
        otp: otp.trim()
      });

      console.log('✅ Login verification successful:', data);

      setMessage(data.message || "✅ Login successful!");
      
      setTimeout(() => {
        if (data.token && data.user) {
          onLogin(data.token, data.user);
        } else {
          setError("Login failed: Invalid response from server");
        }
      }, 500);
    } catch (err) {
      console.error('❌ Login verification failed:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Forgot Password - Send OTP
  const handleForgotSendOTP = async () => {
    setError("");
    setMessage("");

    console.log('🚀 Starting forgot password OTP send...');

    if (!username.trim()) {
      setError("Username is required");
      return;
    }

    setLoading(true);

    try {
      console.log('📞 Sending forgot password OTP for:', username.trim());

      const data = await apiCall("/forgot-password/send-otp", {
        username: username.trim()
      });

      console.log('✅ Forgot password OTP sent successfully:', data);

      // Store phone from server response
      if (data.phone) {
        setServerPhone(data.phone);
        setPhone(data.phone);
        console.log('💾 Stored server phone:', data.phone);
      }

      setPhoneHint(data.phoneHint || "****");
      setMessage(data.message || "✅ OTP sent to your phone!");
      setStep(2);
    } catch (err) {
      console.error('❌ Forgot password OTP send failed:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Forgot Password - Verify OTP and Reset
  const handleForgotVerifyOTP = async () => {
    if (otp.length !== 6) {
      setError("Please enter a valid 6-digit OTP");
      return;
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      setError(passwordError);
      return;
    }

    setLoading(true);
    setError("");

    try {
      const phoneToUse = serverPhone || normalizePhone(phone);
      
      if (!phoneToUse) {
        throw new Error("Phone number not available. Please go back and try again.");
      }

      console.log('🔐 Verifying forgot password OTP:', {
        phone: phoneToUse,
        otp: otp.trim(),
        hasNewPassword: !!password
      });

      const data = await apiCall("/forgot-password/verify-otp", {
        phone: phoneToUse,
        otp: otp.trim(),
        newPassword: password
      });

      console.log('✅ Password reset successful:', data);

      setMessage(data.message || "✅ Password reset successful! Redirecting to login...");
      
      setTimeout(() => {
        // Reset to login mode
        setMode("login");
        setStep(1);
        setUsername("");
        setPassword("");
        setPhone("");
        setOtp("");
        setError("");
        setMessage("");
        setPhoneHint("");
        setServerPhone("");
      }, 1500);
    } catch (err) {
      console.error('❌ Password reset failed:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Resend OTP
  const handleResendOTP = async () => {
    setLoading(true);
    setError("");
    setMessage("");

    try {
      let endpoint;
      if (mode === "signup") {
        endpoint = "/signup/resend-otp";
      } else if (mode === "forgot") {
        endpoint = "/forgot-password/resend-otp";
      } else {
        endpoint = "/login/resend-otp";
      }

      const phoneToUse = serverPhone || normalizePhone(phone);
      
      if (!phoneToUse) {
        throw new Error("Phone number not available. Please go back and try again.");
      }

      console.log('🔄 Resending OTP:', {
        endpoint,
        phone: phoneToUse,
        mode
      });

      const data = await apiCall(endpoint, { phone: phoneToUse });
      
      console.log('✅ OTP resent successfully');
      setMessage(data.message || "✅ OTP resent successfully!");
      setTimeout(() => setMessage(""), 3000);
    } catch (err) {
      console.error('❌ Resend OTP failed:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Switch mode
  const switchMode = () => {
    console.log('🔄 Switching mode from', mode, 'to', mode === "login" ? "signup" : "login");
    setMode(mode === "login" ? "signup" : "login");
    setStep(1);
    setUsername("");
    setPassword("");
    setPhone("");
    setOtp("");
    setError("");
    setMessage("");
    setPhoneHint("");
    setServerPhone("");
    setShowPassword(false);
  };

  // Go back
  const goBack = () => {
    console.log('⬅️ Going back to step 1');
    setStep(1);
    setOtp("");
    setError("");
    setMessage("");
  };

  // Get current form handler
  const getFormSubmitHandler = () => {
    if (mode === "login") return handleLoginSendOTP;
    if (mode === "signup") return handleSignupSendOTP;
    if (mode === "forgot") return handleForgotSendOTP;
  };

  // Get verify handler
  const getVerifyHandler = () => {
    if (mode === "login") return handleLoginVerifyOTP;
    if (mode === "signup") return handleSignupVerifyOTP;
    if (mode === "forgot") return handleForgotVerifyOTP;
  };

  return (
    <div className="auth-container">
      <div className="auth-animated-bg">
        <div className="auth-circle auth-circle-1"></div>
        <div className="auth-circle auth-circle-2"></div>
        <div className="auth-circle auth-circle-3"></div>
      </div>

      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-logo">🔐</div>
          <h1 className="auth-title">
            {mode === "login" && "Welcome Back"}
            {mode === "signup" && "Create Account"}
            {mode === "forgot" && "Reset Password"}
          </h1>
          <p className="auth-subtitle">
            {mode === "login" && "Secure child location tracking with JWT authentication"}
            {mode === "signup" && "Join our secure parental control platform"}
            {mode === "forgot" && "We'll send you a code to reset your password"}
          </p>
        </div>

        {/* Step 1: Credentials */}
        {step === 1 && (
          <form className="auth-form" onSubmit={(e) => {
            e.preventDefault();
            getFormSubmitHandler()();
          }}>
            {mode === "login" && (
              <div style={{ textAlign: "right", marginBottom: "10px" }}>
                <button
                  type="button"
                  className="auth-link"
                  onClick={() => {
                    setMode("forgot");
                    setStep(1);
                    setPassword("");
                    setOtp("");
                    setError("");
                    setMessage("");
                  }}
                  disabled={loading}
                >
                  Forgot password?
                </button>
              </div>
            )}

            <div className="input-group">
              <label className="input-label">
                Username <span className="required">*</span>
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  setError("");
                }}
                placeholder="Enter your username"
                className="auth-input"
                disabled={loading}
                autoComplete="username"
                required
              />
              {mode === "signup" && username && validateUsername(username) && (
                <small className="input-error-hint">{validateUsername(username)}</small>
              )}
            </div>

            {mode !== "forgot" && (
              <div className="input-group">
                <label className="input-label">
                  Password <span className="required">*</span>
                </label>
                <div className="password-input-wrapper">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      setError("");
                    }}
                    placeholder="Enter your password"
                    className="auth-input"
                    disabled={loading}
                    autoComplete={mode === "login" ? "current-password" : "new-password"}
                    required
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                    tabIndex={-1}
                  >
                    {showPassword ? "👁️" : "👁️‍🗨️"}
                  </button>
                </div>
                {mode === "signup" && password && validatePassword(password) && (
                  <small className="input-error-hint">{validatePassword(password)}</small>
                )}
              </div>
            )}

            {mode === "signup" && (
              <div className="input-group">
                <label className="input-label">
                  Phone Number <span className="required">*</span>
                </label>
                <input
                  type="tel"
                  value={phone}
                  onChange={(e) => {
                    setPhone(e.target.value);
                    setError("");
                  }}
                  placeholder="+1234567890"
                  className="auth-input"
                  disabled={loading}
                  autoComplete="tel"
                  required
                />
                <small className="input-hint">Format: +[country code][number]</small>
                {phone && validatePhone(phone) && (
                  <small className="input-error-hint">{validatePhone(phone)}</small>
                )}
              </div>
            )}

            {mode === "signup" && (
              <div className="password-requirements">
                <p className="requirements-title">Password must contain:</p>
                <ul className="requirements-list">
                  <li className={password.length >= 8 ? "requirement-met" : ""}>
                    {password.length >= 8 ? "✓" : "○"} At least 8 characters
                  </li>
                  <li className={/[A-Z]/.test(password) ? "requirement-met" : ""}>
                    {/[A-Z]/.test(password) ? "✓" : "○"} One uppercase letter
                  </li>
                  <li className={/[a-z]/.test(password) ? "requirement-met" : ""}>
                    {/[a-z]/.test(password) ? "✓" : "○"} One lowercase letter
                  </li>
                  <li className={/[0-9]/.test(password) ? "requirement-met" : ""}>
                    {/[0-9]/.test(password) ? "✓" : "○"} One number
                  </li>
                </ul>
              </div>
            )}

            {error && <div className="auth-error">{error}</div>}
            {message && <div className="auth-success">{message}</div>}

            <button
              type="submit"
              className="auth-btn auth-btn-primary"
              disabled={loading || (mode === "signup" && (
                validateUsername(username) || validatePassword(password) || validatePhone(phone)
              ))}
            >
              {loading ? "⏳ Please wait..." : (
                mode === "login" ? "Continue to OTP" : 
                mode === "signup" ? "Send OTP" : 
                "Send Reset Code"
              )}
            </button>

            <div className="auth-divider">
              <span>or</span>
            </div>

            {mode === "forgot" ? (
              <button
                type="button"
                className="auth-btn auth-btn-secondary"
                onClick={() => {
                  setMode("login");
                  setStep(1);
                  setUsername("");
                  setPassword("");
                  setPhone("");
                  setOtp("");
                  setError("");
                  setMessage("");
                }}
                disabled={loading}
              >
                ← Back to Login
              </button>
            ) : (
              <button
                type="button"
                className="auth-btn auth-btn-secondary"
                onClick={switchMode}
                disabled={loading}
              >
                {mode === "login" ? "Create new account" : "Already have an account? Login"}
              </button>
            )}
          </form>
        )}

        {/* Step 2: OTP Verification */}
        {step === 2 && (
          <div className="auth-form">
            <div className="otp-info">
              <div className="otp-icon">📱</div>
              <p className="otp-text">Verification code sent!</p>
              <p className="otp-subtext">
                Check your phone ending in <strong>***{phoneHint}</strong>
              </p>
              {serverPhone && (
                <p className="otp-debug" style={{fontSize: '0.8em', color: '#666', marginTop: '8px'}}>
                  Using phone: {serverPhone}
                </p>
              )}
            </div>

            {mode === "forgot" && (
              <div className="input-group">
                <label className="input-label">
                  New Password <span className="required">*</span>
                </label>
                <div className="password-input-wrapper">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      setError("");
                    }}
                    placeholder="Enter your new password"
                    className="auth-input"
                    disabled={loading}
                    autoComplete="new-password"
                    required
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                    tabIndex={-1}
                  >
                    {showPassword ? "👁️" : "👁️‍🗨️"}
                  </button>
                </div>
                {password && validatePassword(password) && (
                  <small className="input-error-hint">{validatePassword(password)}</small>
                )}
                <div className="password-requirements" style={{marginTop: '10px'}}>
                  <p className="requirements-title">Password must contain:</p>
                  <ul className="requirements-list">
                    <li className={password.length >= 8 ? "requirement-met" : ""}>
                      {password.length >= 8 ? "✓" : "○"} At least 8 characters
                    </li>
                    <li className={/[A-Z]/.test(password) ? "requirement-met" : ""}>
                      {/[A-Z]/.test(password) ? "✓" : "○"} One uppercase letter
                    </li>
                    <li className={/[a-z]/.test(password) ? "requirement-met" : ""}>
                      {/[a-z]/.test(password) ? "✓" : "○"} One lowercase letter
                    </li>
                    <li className={/[0-9]/.test(password) ? "requirement-met" : ""}>
                      {/[0-9]/.test(password) ? "✓" : "○"} One number
                    </li>
                  </ul>
                </div>
              </div>
            )}

            <div className="input-group">
              <label className="input-label">
                Enter 6-Digit OTP <span className="required">*</span>
              </label>
              <input
                type="text"
                value={otp}
                onChange={(e) => {
                  const val = e.target.value.replace(/\D/g, "").slice(0, 6);
                  setOtp(val);
                  setError("");
                }}
                placeholder="000000"
                className="auth-input otp-input"
                maxLength={6}
                disabled={loading}
                autoFocus
                autoComplete="one-time-code"
              />
              <small className="input-hint">
                OTP expires in 5 minutes. Check your server console for the OTP during development.
              </small>
            </div>

            {error && <div className="auth-error">{error}</div>}
            {message && <div className="auth-success">{message}</div>}

            <button
              onClick={getVerifyHandler()}
              className="auth-btn auth-btn-primary"
              disabled={loading || otp.length !== 6 || (mode === "forgot" && validatePassword(password))}
            >
              {loading ? "⏳ Verifying..." : (
                mode === "forgot" ? "✓ Reset Password" : "✓ Verify & Continue"
              )}
            </button>

            <button
              onClick={handleResendOTP}
              className="auth-btn auth-btn-tertiary"
              disabled={loading}
            >
              🔄 Resend OTP
            </button>

            <button
              onClick={goBack}
              className="auth-btn auth-btn-secondary"
              disabled={loading}
            >
              ← Back
            </button>
          </div>
        )}
      </div>
    </div>
  );
}