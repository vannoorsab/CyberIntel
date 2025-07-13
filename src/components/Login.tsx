import React, { useState, useEffect } from 'react';
import { Shield, Eye, EyeOff, LogIn, UserPlus, Zap, ArrowLeft } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

interface LoginProps {
  onToggleAuth: () => void;
}

const Login: React.FC<LoginProps> = ({ onToggleAuth }) => {
  const { login } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [scanLines, setScanLines] = useState<number[]>([]);

  // Generate random scan lines for cyberpunk effect
  useEffect(() => {
    const lines = [];
    for (let i = 0; i < 10; i++) {
      lines.push(Math.floor(Math.random() * 100));
    }
    setScanLines(lines);

    const interval = setInterval(() => {
      const newLines = [];
      for (let i = 0; i < 10; i++) {
        newLines.push(Math.floor(Math.random() * 100));
      }
      setScanLines(newLines);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    if (!formData.email || !formData.password) {
      setError('All fields are required');
      setIsLoading(false);
      return;
    }

    try {
      const success = await login(formData.email, formData.password);
      if (!success) {
        setError('Invalid email or password');
      }
    } catch (err) {
      setError('Login failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="min-h-screen bg-cyber-darker flex items-center justify-center p-4 relative overflow-hidden">
      {/* Back to Home Button */}
      <button
        className="absolute top-6 left-6 flex items-center text-cyber-primary hover:text-cyber-accent font-medium transition-colors z-20"
        type="button"
        onClick={() => {
          window.location.pathname = '/';
        }}
      >
        <ArrowLeft className="w-5 h-5 mr-1" />
        Back to Home
      </button>
      {/* Cyberpunk background effects */}
      <div className="absolute inset-0 cyber-grid"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(0,255,65,0.1),transparent)]"></div>
      <div className="hex-grid"></div>
      <div className="data-stream"></div>
      
      {/* Scan lines */}
      {scanLines.map((top, i) => (
        <div 
          key={i}
          className="absolute left-0 w-full h-px bg-cyber-primary/20"
          style={{ 
            top: `${top}%`,
            animation: `scan-line ${2 + Math.random() * 4}s linear infinite`,
            animationDelay: `${Math.random() * 2}s`
          }}
        ></div>
      ))}
      
      <div className="w-full max-w-md relative">
        <div className="cyber-card p-8 border-cyber-primary/30">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="flex justify-center mb-4">
              <div className="relative">
                <Shield className="w-16 h-16 text-cyber-primary" />
                <div className="absolute inset-0 animate-cyber-pulse">
                  <Shield className="w-16 h-16 text-cyber-primary/30" />
                </div>
                <div className="absolute -inset-4 bg-cyber-primary/10 rounded-full blur-xl"></div>
              </div>
            </div>
            <h1 className="text-3xl font-bold text-cyber-primary mb-2 font-cyber">
              CYBERINTEL
            </h1>
            <p className="text-gray-400 font-cyber-alt">SECURE AUTHENTICATION PORTAL</p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="bg-cyber-danger/10 border border-cyber-danger/20 rounded-lg p-3 text-cyber-danger text-sm">
                {error}
              </div>
            )}

            <div className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2 font-cyber">
                  EMAIL ADDRESS
                </label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  className="w-full px-4 py-3 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                  placeholder="Enter your email"
                  required
                />
              </div>

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-2 font-cyber">
                  PASSWORD
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    id="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    className="w-full px-4 py-3 pr-12 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                    placeholder="Enter your password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-cyber-primary transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="cyber-button w-full py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center justify-center space-x-2"
            >
              {isLoading ? (
                <>
                  <div className="cyber-loading" />
                  <span className="font-cyber">AUTHENTICATING...</span>
                </>
              ) : (
                <>
                  <LogIn className="w-5 h-5" />
                  <span className="font-cyber">LOGIN</span>
                </>
              )}
            </button>
          </form>

          {/* Footer */}
          <div className="mt-8 text-center">
            <p className="text-gray-400">
              Don't have an account?{' '}
              <button
                onClick={onToggleAuth}
                className="text-cyber-primary hover:text-cyber-primary/80 font-medium inline-flex items-center space-x-1 transition-colors"
              >
                <UserPlus className="w-4 h-4" />
                <span className="font-cyber">SIGN UP</span>
              </button>
            </p>
          </div>
        </div>

       
      </div>
    </div>
  );
};

export default Login;