
import React, { useState, useEffect } from 'react';
import { Shield, Eye, EyeOff, LogIn, Zap, UserCheck, Terminal, Cpu, Server, Database, HardDrive, Wifi, ArrowLeft } from 'lucide-react';
import { useOfficerAuth } from '../contexts/OfficerAuthContext';

interface OfficerLoginProps {
  onLoginSuccess: () => void;
}

const OfficerLogin: React.FC<OfficerLoginProps> = ({ onLoginSuccess }) => {
  const { login } = useOfficerAuth();
  const [formData, setFormData] = useState({
    officerId: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [scanLines, setScanLines] = useState<number[]>([]);
  const [terminalText, setTerminalText] = useState('');
  const [terminalCursor, setTerminalCursor] = useState(true);
  const [floatingIcons, setFloatingIcons] = useState<{icon: any, x: number, y: number, size: number, speed: number}[]>([]);

  // Generate random scan lines for cyberpunk effect
  useEffect(() => {
    const lines = [];
    for (let i = 0; i < 15; i++) {
      lines.push(Math.floor(Math.random() * 100));
    }
    setScanLines(lines);

    const interval = setInterval(() => {
      const newLines = [];
      for (let i = 0; i < 15; i++) {
        newLines.push(Math.floor(Math.random() * 100));
      }
      setScanLines(newLines);
    }, 3000);

    // Generate floating icons
    const icons = [Terminal, Cpu, Server, Database, HardDrive, Wifi];
    const floatingElements = [];
    
    for (let i = 0; i < 12; i++) {
      floatingElements.push({
        icon: icons[Math.floor(Math.random() * icons.length)],
        x: Math.random() * 100,
        y: Math.random() * 100,
        size: 20 + Math.random() * 30,
        speed: 10 + Math.random() * 20
      });
    }
    
    setFloatingIcons(floatingElements);

    return () => clearInterval(interval);
  }, []);

  // Terminal text animation
  useEffect(() => {
    const messages = [
      "INITIALIZING SECURE CONNECTION...",
      "ESTABLISHING ENCRYPTED CHANNEL...",
      "VERIFYING SECURITY PROTOCOLS...",
      "LOADING AUTHENTICATION MODULE...",
      "READY FOR OFFICER CREDENTIALS..."
    ];
    
    let currentMessageIndex = 0;
    let currentCharIndex = 0;
    let isDeleting = false;
    let typingSpeed = 80;
    
    const typeTerminalText = () => {
      const currentMessage = messages[currentMessageIndex];
      
      if (isDeleting) {
        setTerminalText(currentMessage.substring(0, currentCharIndex - 1));
        currentCharIndex--;
        typingSpeed = 30;
        
        if (currentCharIndex === 0) {
          isDeleting = false;
          currentMessageIndex = (currentMessageIndex + 1) % messages.length;
          typingSpeed = 500; // Pause before typing next message
        }
      } else {
        setTerminalText(currentMessage.substring(0, currentCharIndex + 1));
        currentCharIndex++;
        typingSpeed = 80;
        
        if (currentCharIndex === currentMessage.length) {
          isDeleting = true;
          typingSpeed = 2000; // Pause before deleting
        }
      }
    };
    
    const typingInterval = setInterval(typeTerminalText, typingSpeed);
    const cursorInterval = setInterval(() => setTerminalCursor(prev => !prev), 500);
    
    return () => {
      clearInterval(typingInterval);
      clearInterval(cursorInterval);
    };
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    if (!formData.officerId || !formData.password) {
      setError('All fields are required');
      setIsLoading(false);
      return;
    }

    try {
      console.log('Attempting login with:', formData.officerId);
      const success = await login(formData.officerId, formData.password);
      console.log('Login result:', success);
      
      if (success) {
        console.log('Login successful, calling onLoginSuccess');
        setTimeout(() => {
          onLoginSuccess();
        }, 100);
      } else {
        setError('Invalid Officer ID or password. Please check your credentials.');
      }
    } catch (err) {
      console.error('Login error:', err);
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

  const handleDemoLogin = (officerId: string, password: string) => {
    setFormData({ officerId, password });
    setError('');
  };

  return (
    <div className="min-h-screen bg-cyber-darker relative overflow-hidden">
      {/* Back to Home Button */}
      <button
        className="absolute top-6 left-6 flex items-center text-cyber-danger hover:text-cyber-warning font-medium transition-colors z-20"
        type="button"
        onClick={() => window.location.href = '/'}
      >
        <ArrowLeft className="w-5 h-5 mr-2" />
        BACK TO HOME
      </button>

      {/* Cyberpunk background effects */}
      <div className="absolute inset-0 cyber-grid opacity-30"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(255,0,64,0.15),transparent)]"></div>
      <div className="hex-grid opacity-20"></div>
      
      {/* Floating icons */}
      {floatingIcons.map((item, index) => (
        <div 
          key={index}
          className="absolute text-cyber-danger/10 pointer-events-none"
          style={{
            left: `${item.x}%`,
            top: `${item.y}%`,
            width: `${item.size}px`,
            height: `${item.size}px`,
            animation: `cyber-float ${item.speed}s ease-in-out infinite alternate`
          }}
        >
          <item.icon size={item.size} />
        </div>
      ))}
      
      {/* Scan lines */}
      {scanLines.map((top, i) => (
        <div 
          key={i}
          className="absolute left-0 w-full h-px bg-cyber-danger/20"
          style={{ 
            top: `${top}%`,
            animation: `scan-line ${2 + Math.random() * 4}s linear infinite`,
            animationDelay: `${Math.random() * 2}s`
          }}
        ></div>
      ))}
      
      <div className="w-full max-w-4xl relative mx-auto flex items-center justify-center min-h-screen p-4">
        <div className="cyber-card p-8 border-cyber-danger/30 w-full max-w-md relative overflow-hidden">
          {/* Animated circuit pattern overlay */}
          <div className="absolute inset-0 pointer-events-none opacity-10">
            <svg width="100%" height="100%" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
              <path d="M10,10 L90,10 L90,90 L10,90 Z" fill="none" stroke="#ff0040" strokeWidth="0.5" />
              <path d="M20,20 L80,20 L80,80 L20,80 Z" fill="none" stroke="#ff0040" strokeWidth="0.5" />
              <path d="M30,30 L70,30 L70,70 L30,70 Z" fill="none" stroke="#ff0040" strokeWidth="0.5" />
              <path d="M10,10 L30,30" fill="none" stroke="#ff0040" strokeWidth="0.5" />
              <path d="M90,10 L70,30" fill="none" stroke="#ff0040" strokeWidth="0.5" />
              <path d="M10,90 L30,70" fill="none" stroke="#ff0040" strokeWidth="0.5" />
              <path d="M90,90 L70,70" fill="none" stroke="#ff0040" strokeWidth="0.5" />
              <circle cx="10" cy="10" r="2" fill="#ff0040" />
              <circle cx="90" cy="10" r="2" fill="#ff0040" />
              <circle cx="10" cy="90" r="2" fill="#ff0040" />
              <circle cx="90" cy="90" r="2" fill="#ff0040" />
            </svg>
          </div>
          
          {/* Header */}
          <div className="text-center mb-8 relative">
            <div className="flex justify-center mb-4">
              <div className="relative">
                <Shield className="w-16 h-16 text-cyber-danger" />
                <div className="absolute inset-0 animate-cyber-pulse">
                  <Shield className="w-16 h-16 text-cyber-danger/30" />
                </div>
                <div className="absolute -inset-4 bg-cyber-danger/10 rounded-full blur-xl"></div>
              </div>
            </div>
            <h1 className="text-3xl font-bold text-cyber-danger mb-2 font-cyber glitch" data-text="OFFICER ACCESS">
              OFFICER ACCESS
            </h1>
            <p className="text-gray-400 font-cyber-alt">SECURE THREATOPS COMMAND CENTER</p>
            <div className="mt-4 bg-cyber-danger/10 border border-cyber-danger/20 rounded-lg p-3">
              <p className="text-cyber-danger text-sm font-medium font-cyber">⚠️ AUTHORIZED PERSONNEL ONLY</p>
              <p className="text-gray-400 text-xs mt-1 font-cyber-alt">CBI • CYBERCRIME • RED TEAM • DIGITAL FORENSICS</p>
            </div>
          </div>

          {/* Terminal effect */}
          <div className="mb-6 bg-black border border-cyber-danger/30 rounded-lg p-4 font-mono text-xs text-cyber-danger">
            <div className="flex items-center space-x-2 mb-2 border-b border-cyber-danger/20 pb-2">
              <Terminal className="w-4 h-4" />
              <span className="font-cyber">SYSTEM TERMINAL</span>
            </div>
            <div className="h-16 overflow-hidden">
              <p className="whitespace-pre-line">
                {terminalText}
                <span className={`inline-block w-2 h-4 bg-cyber-danger ml-1 ${terminalCursor ? 'opacity-100' : 'opacity-0'}`}></span>
              </p>
            </div>
          </div>

          {/* Demo Credentials */}
          <div className="mb-6 bg-black/70 border border-gray-600/50 rounded-lg p-4">
            <h3 className="text-sm font-bold text-cyber-warning mb-3 font-cyber">🔑 DEMO CREDENTIALS:</h3>
            <div className="space-y-2">
              <button
                onClick={() => handleDemoLogin('CBI001', 'secure123')}
                className="w-full text-left px-3 py-2 bg-green-500/10 hover:bg-green-500/20 border border-green-500/30 rounded text-xs text-green-400 transition-colors"
              >
                <span className="font-bold">CBI001</span> / secure123 (Agent Sarah Connor)
              </button>
              <button
                onClick={() => handleDemoLogin('CYBER002', 'redteam456')}
                className="w-full text-left px-3 py-2 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 rounded text-xs text-blue-400 transition-colors"
              >
                <span className="font-bold">CYBER002</span> / redteam456 (Lt. John Matrix)
              </button>
              <button
                onClick={() => handleDemoLogin('SEC003', 'forensic789')}
                className="w-full text-left px-3 py-2 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 rounded text-xs text-purple-400 transition-colors"
              >
                <span className="font-bold">SEC003</span> / forensic789 (Dr. Lisa Chen)
              </button>
              <button
                onClick={() => handleDemoLogin('ADMIN001', 'admin2024')}
                className="w-full text-left px-3 py-2 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 rounded text-xs text-orange-400 transition-colors"
              >
                <span className="font-bold">ADMIN001</span> / admin2024 (Vannoor Sab - vanursab18@gmail.com)
              </button>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6 relative">
            {error && (
              <div className="bg-cyber-danger/10 border border-cyber-danger/20 rounded-lg p-3 text-cyber-danger text-sm">
                {error}
              </div>
            )}

            <div className="space-y-4">
              <div>
                <label htmlFor="officerId" className="block text-sm font-medium text-gray-300 mb-2 font-cyber">
                  OFFICER ID
                </label>
                <div className="relative">
                  <input
                    type="text"
                    id="officerId"
                    name="officerId"
                    value={formData.officerId}
                    onChange={handleChange}
                    className="w-full px-4 py-3 pl-12 bg-black/70 border border-cyber-danger/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-danger/50 focus:border-cyber-danger transition-all duration-200"
                    placeholder="Enter your Officer ID"
                    required
                  />
                  <UserCheck className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-cyber-danger" />
                  
                  {/* Animated border effect */}
                  <div className="absolute inset-0 pointer-events-none">
                    <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyber-danger to-transparent transform -translate-x-full animate-cyber-scan"></div>
                  </div>
                </div>
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
                    className="w-full px-4 py-3 pr-12 bg-black/70 border border-cyber-danger/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-danger/50 focus:border-cyber-danger transition-all duration-200"
                    placeholder="Enter your password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-cyber-danger transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                  
                  {/* Animated border effect */}
                  <div className="absolute inset-0 pointer-events-none">
                    <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyber-danger to-transparent transform -translate-x-full animate-cyber-scan" style={{ animationDelay: '0.5s' }}></div>
                  </div>
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="cyber-button w-full py-3 px-4 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center justify-center space-x-2 border-cyber-danger text-cyber-danger relative overflow-hidden group"
            >
              <div className="absolute inset-0 w-full h-full bg-cyber-danger/0 group-hover:bg-cyber-danger/10 transition-colors duration-300"></div>
              <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyber-danger to-transparent transform -translate-x-full group-hover:translate-x-full transition-transform duration-1000"></div>
              <div className="absolute bottom-0 right-0 w-full h-px bg-gradient-to-r from-cyber-danger to-transparent transform translate-x-full group-hover:-translate-x-full transition-transform duration-1000"></div>
              
              {isLoading ? (
                <>
                  <div className="cyber-loading" />
                  <span className="font-cyber relative z-10">AUTHENTICATING...</span>
                </>
              ) : (
                <>
                  <LogIn className="w-5 h-5 relative z-10" />
                  <span className="font-cyber relative z-10">ACCESS COMMAND CENTER</span>
                </>
              )}
            </button>
          </form>

          {/* Footer */}
          <div className="mt-8 text-center">
            <p className="text-gray-500 text-sm font-cyber-alt">
              🔒 SECURE CONNECTION ESTABLISHED
            </p>
            <p className="text-gray-600 text-xs mt-1 font-cyber-alt">
              ALL ACTIVITIES ARE MONITORED AND LOGGED
            </p>
          </div>
        </div>

       
      </div>
    </div>
  );
};

export default OfficerLogin;