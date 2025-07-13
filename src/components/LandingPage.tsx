import React, { useState, useEffect } from 'react';
import { Shield, User, UserCheck, ArrowRight, Eye, Lock, Zap, Brain, Activity, Database, Cpu, Globe, Server, Network, Wifi, HardDrive, Terminal, Code, Key } from 'lucide-react';

interface LandingPageProps {
  onSelectUserType: (type: 'user' | 'officer') => void;
}

const LandingPage: React.FC<LandingPageProps> = ({ onSelectUserType }) => {
  const [hoveredCard, setHoveredCard] = useState<string | null>(null);
  const [animatedText, setAnimatedText] = useState('');
  const [textIndex, setTextIndex] = useState(0);
  const [showCursor, setShowCursor] = useState(true);
  const [matrixColumns, setMatrixColumns] = useState<{x: number, chars: string[], speed: number}[]>([]);
  const [scanLines, setScanLines] = useState<number[]>([]);

  const securityPhrases = [
    "ADVANCED THREAT DETECTION",
    "REAL-TIME MONITORING",
    "CYBER INTELLIGENCE",
    "SECURE OPERATIONS",
    "THREAT ANALYSIS"
  ];

  // Generate matrix digital rain effect
  useEffect(() => {
    const columns = [];
    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
    
    for (let i = 0; i < 50; i++) {
      const columnChars = [];
      const length = 5 + Math.floor(Math.random() * 15);
      
      for (let j = 0; j < length; j++) {
        columnChars.push(chars[Math.floor(Math.random() * chars.length)]);
      }
      
      columns.push({
        x: Math.random() * 100,
        chars: columnChars,
        speed: 1 + Math.random() * 3
      });
    }
    
    setMatrixColumns(columns);
    
    // Update matrix characters periodically
    const interval = setInterval(() => {
      setMatrixColumns(prev => prev.map(col => ({
        ...col,
        chars: col.chars.map(() => chars[Math.floor(Math.random() * chars.length)])
      })));
    }, 1000);
    
    return () => clearInterval(interval);
  }, []);

  // Generate scan lines
  useEffect(() => {
    const lines = [];
    for (let i = 0; i < 20; i++) {
      lines.push(Math.floor(Math.random() * 100));
    }
    setScanLines(lines);

    const interval = setInterval(() => {
      const newLines = [];
      for (let i = 0; i < 20; i++) {
        newLines.push(Math.floor(Math.random() * 100));
      }
      setScanLines(newLines);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  // Typing animation effect
  useEffect(() => {
    const phrase = securityPhrases[textIndex];
    let currentIndex = 0;
    let typingInterval: NodeJS.Timeout;
    let pauseTimeout: NodeJS.Timeout;

    // Type the current phrase
    const typeText = () => {
      if (currentIndex <= phrase.length) {
        setAnimatedText(phrase.substring(0, currentIndex));
        currentIndex++;
        typingInterval = setTimeout(typeText, 100);
      } else {
        // Pause at the end of the phrase
        pauseTimeout = setTimeout(() => {
          // Erase the phrase
          eraseText();
        }, 2000);
      }
    };

    // Erase the current phrase
    const eraseText = () => {
      if (currentIndex > 0) {
        setAnimatedText(phrase.substring(0, currentIndex - 1));
        currentIndex--;
        typingInterval = setTimeout(eraseText, 50);
      } else {
        // Move to the next phrase
        setTextIndex((prevIndex) => (prevIndex + 1) % securityPhrases.length);
      }
    };

    typeText();

    // Blinking cursor effect
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 500);

    return () => {
      clearTimeout(typingInterval);
      clearTimeout(pauseTimeout);
      clearInterval(cursorInterval);
    };
  }, [textIndex]);

  // Cyber icons for the background
  const cyberIcons = [
    Shield, Lock, Eye, Brain, Activity, Database, Cpu, Globe, Server, Network, Wifi, HardDrive, Terminal, Code, Key
  ];

  return (
    <div className="min-h-screen bg-cyber-darker relative overflow-hidden">
      {/* Matrix Digital Rain */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {matrixColumns.map((column, i) => (
          <div
            key={i}
            className="absolute top-0 text-xs font-mono-cyber text-cyber-primary/20"
            style={{
              left: `${column.x}%`,
              animation: `matrix-fall ${column.speed}s linear infinite`,
              animationDelay: `${Math.random() * 5}s`
            }}
          >
            {column.chars.map((char, j) => (
              <div 
                key={j} 
                style={{ 
                  opacity: j === 0 ? 0.9 : 0.2 + (0.7 * (1 - j / column.chars.length)),
                  textShadow: j === 0 ? '0 0 8px var(--cyber-primary)' : 'none'
                }}
              >
                {char}
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* Animated Background */}
      <div className="absolute inset-0">
<div className="absolute inset-0 cyber-grid opacity-20 pointer-events-none"></div>
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_80%,rgba(0,255,65,0.1),transparent)]"></div>
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_20%,rgba(0,212,255,0.1),transparent)]"></div>
        <div className="hex-grid"></div>
        <div className="data-stream"></div>
      </div>

      {/* Scan lines */}
      {scanLines.map((top, i) => (
        <div 
          key={i}
          className="absolute left-0 w-full h-px bg-cyber-primary/10"
          style={{ 
            top: `${top}%`,
            animation: `scan-line ${2 + Math.random() * 4}s linear infinite`,
            animationDelay: `${Math.random() * 2}s`
          }}
        ></div>
      ))}

      {/* Floating icons */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {cyberIcons.map((Icon, i) => (
          <div
            key={i}
            className="absolute text-cyber-primary/10"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              transform: `scale(${1 + Math.random() * 2}) rotate(${Math.random() * 360}deg)`,
              opacity: 0.1 + Math.random() * 0.2,
              animation: `cyber-float ${3 + Math.random() * 5}s ease-in-out infinite alternate`,
              animationDelay: `${Math.random() * 5}s`
            }}
          >
            <Icon size={30 + Math.random() * 40} />
          </div>
        ))}
      </div>

      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="flex justify-center mb-6">
            <div className="relative">
              <div className="w-24 h-24 rounded-full bg-gradient-to-r from-cyber-primary/20 to-cyber-accent/20 flex items-center justify-center">
                <Shield className="w-16 h-16 text-cyber-primary" />
              </div>
              <div className="absolute inset-0 animate-cyber-pulse">
                <div className="w-24 h-24 rounded-full bg-gradient-to-r from-cyber-primary/10 to-cyber-accent/10 flex items-center justify-center">
                  <Shield className="w-16 h-16 text-cyber-primary/30" />
                </div>
              </div>
              <div className="absolute -inset-4 bg-cyber-primary/10 rounded-full blur-xl animate-cyber-pulse"></div>
            </div>
          </div>
          
          <h1 className="text-6xl md:text-7xl font-bold text-white mb-6 tracking-tight font-cyber relative glitch" data-text="CYBERINTEL">
            <span className="bg-clip-text text-transparent bg-gradient-to-r from-cyber-primary via-cyber-accent to-cyber-primary">
              CYBERINTEL
            </span>
            <div className="absolute -inset-1 bg-gradient-to-r from-cyber-primary/0 via-cyber-primary/10 to-cyber-primary/0 blur-xl opacity-50"></div>
          </h1>
          
          <div className="h-8 mb-8">
            <p className="text-xl md:text-2xl text-cyber-primary font-cyber inline-flex items-center">
              <span>{animatedText}</span>
              <span className={`ml-1 w-3 h-6 bg-cyber-primary ${showCursor ? 'opacity-100' : 'opacity-0'} transition-opacity duration-100`}></span>
            </p>
          </div>

          {/* 3D Rotating Cube */}
          <div className="cyber-depth w-full max-w-4xl mx-auto mb-12 perspective">
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 transform rotateX-5 hover:rotateX-0 transition-transform duration-500">
              {[
                { icon: Brain, label: 'AI Analysis', color: 'text-purple-400' },
                { icon: Shield, label: 'Protection', color: 'text-cyber-primary' },
                { icon: Activity, label: 'Monitoring', color: 'text-cyber-warning' },
                { icon: Database, label: 'Forensics', color: 'text-cyber-accent' },
                { icon: Eye, label: 'Scanning', color: 'text-cyber-danger' },
                { icon: Lock, label: 'Prevention', color: 'text-cyan-400' }
              ].map((feature, index) => {
                const Icon = feature.icon;
                return (
                  <div
                    key={index}
                    className="cyber-card p-4 transform hover:scale-105 transition-all duration-300"
                    style={{
                      transform: `translateZ(${20 + index * 5}px)`,
                      transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)'
                    }}
                  >
                    <Icon className={`w-8 h-8 ${feature.color} mx-auto mb-2`} />
                    <div className="text-xs text-center font-cyber">{feature.label}</div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="text-lg text-cyber-primary mb-12 font-cyber neon-text">
            SELECT ACCESS LEVEL
          </div>
        </div>

        {/* Access Type Selection */}
        <div className="grid md:grid-cols-2 gap-8 max-w-4xl w-full">
          {/* User Access Card */}
          <div
            className={`cyber-card group relative p-8 cursor-pointer transition-all duration-500 hover:scale-105 ${
              hoveredCard === 'user' ? 'neon-border' : ''
            }`}
            onMouseEnter={() => setHoveredCard('user')}
            onMouseLeave={() => setHoveredCard(null)}
            onClick={() => onSelectUserType('user')}
            style={{
              transform: hoveredCard === 'user' ? 'translateZ(30px) rotateX(5deg)' : 'translateZ(0)',
              transition: 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)'
            }}
          >
            {/* Circuit pattern overlay */}
            <div className="absolute inset-0 pointer-events-none opacity-5">
              <svg width="100%" height="100%" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <path d="M10,10 L90,10 L90,90 L10,90 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                <path d="M20,20 L80,20 L80,80 L20,80 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                <path d="M30,30 L70,30 L70,70 L30,70 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                <path d="M10,10 L30,30" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                <path d="M90,10 L70,30" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                <path d="M10,90 L30,70" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                <path d="M90,90 L70,70" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                <circle cx="10" cy="10" r="2" fill="#00ff41" />
                <circle cx="90" cy="10" r="2" fill="#00ff41" />
                <circle cx="10" cy="90" r="2" fill="#00ff41" />
                <circle cx="90" cy="90" r="2" fill="#00ff41" />
              </svg>
            </div>
            
            {/* Scan line effect */}
            <div className={`absolute inset-0 overflow-hidden ${hoveredCard === 'user' ? 'opacity-100' : 'opacity-0'} transition-opacity duration-300`}>
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyber-primary to-transparent animate-cyber-scan"></div>
            </div>

            <div className="relative z-10">
              <div className="flex items-center justify-center mb-6">
                <div className={`relative p-4 rounded-2xl transition-all duration-300 ${
                  hoveredCard === 'user' ? 'bg-cyber-primary/20' : 'bg-gray-700/30'
                }`}>
                  <User className={`w-12 h-12 transition-colors duration-300 ${
                    hoveredCard === 'user' ? 'text-cyber-primary' : 'text-gray-400'
                  }`} />
                  {hoveredCard === 'user' && (
                    <div className="absolute inset-0 bg-cyber-primary/20 rounded-2xl animate-cyber-pulse"></div>
                  )}
                </div>
              </div>

              <h3 className="text-2xl font-bold text-white text-center mb-4 font-cyber">
                USER ACCESS
              </h3>
              
              <p className="text-gray-300 text-center mb-6 leading-relaxed">
                Access cybersecurity tools for URL scanning, file analysis, QR code checking, and threat monitoring
              </p>

              <div className="space-y-3 mb-8">
                <div className="flex items-center space-x-3 text-sm text-gray-300">
                  <div className="w-2 h-2 bg-cyber-primary rounded-full"></div>
                  <span>URL & File Security Analysis</span>
                </div>
                <div className="flex items-center space-x-3 text-sm text-gray-300">
                  <div className="w-2 h-2 bg-cyber-accent rounded-full"></div>
                  <span>QR Code Threat Detection</span>
                </div>
                <div className="flex items-center space-x-3 text-sm text-gray-300">
                  <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
                  <span>Real-time Threat Intelligence</span>
                </div>
                <div className="flex items-center space-x-3 text-sm text-gray-300">
                  <div className="w-2 h-2 bg-cyber-warning rounded-full"></div>
                  <span>AI-Powered Security Reports</span>
                </div>
              </div>

              <div className={`flex items-center justify-center space-x-2 text-cyber-primary font-medium transition-all duration-300 ${
                hoveredCard === 'user' ? 'transform translate-x-2' : ''
              }`}>
                <span className="font-cyber">CONTINUE AS USER</span>
                <ArrowRight className="w-5 h-5" />
              </div>
            </div>
          </div>

          {/* Officer Access Card */}
          <div
            className={`cyber-card group relative p-8 cursor-pointer transition-all duration-500 hover:scale-105 ${
              hoveredCard === 'officer' ? 'neon-border' : ''
            }`}
            onMouseEnter={() => setHoveredCard('officer')}
            onMouseLeave={() => setHoveredCard(null)}
onClick={() => {
  console.log('Officer Access Clicked');
  onSelectUserType('officer');
}}
            style={{
              transform: hoveredCard === 'officer' ? 'translateZ(30px) rotateX(5deg)' : 'translateZ(0)',
              transition: 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)'
            }}
          >
            {/* Circuit pattern overlay */}
            <div className="absolute inset-0 pointer-events-none opacity-5">
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
            
            {/* Scan line effect */}
            <div className={`absolute inset-0 overflow-hidden ${hoveredCard === 'officer' ? 'opacity-100' : 'opacity-0'} transition-opacity duration-300`}>
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyber-danger to-transparent animate-cyber-scan"></div>
            </div>

            <div className="relative z-10">
              <div className="flex items-center justify-center mb-6">
                <div className={`relative p-4 rounded-2xl transition-all duration-300 ${
                  hoveredCard === 'officer' ? 'bg-cyber-danger/20' : 'bg-gray-700/30'
                }`}>
                  <UserCheck className={`w-12 h-12 transition-colors duration-300 ${
                    hoveredCard === 'officer' ? 'text-cyber-danger' : 'text-gray-400'
                  }`} />
                  {hoveredCard === 'officer' && (
                    <div className="absolute inset-0 bg-cyber-danger/20 rounded-2xl animate-cyber-pulse"></div>
                  )}
                </div>
              </div>

              <h3 className="text-2xl font-bold text-white text-center mb-4 font-cyber">
                OFFICER ACCESS
              </h3>
              
              <p className="text-gray-300 text-center mb-6 leading-relaxed">
                Advanced security operations center for incident response, forensics, and threat management
              </p>

              <div className="space-y-3 mb-8">
                <div className="flex items-center space-x-3 text-sm text-gray-300">
                  <div className="w-2 h-2 bg-cyber-danger rounded-full"></div>
                  <span>Incident Response Management</span>
                </div>
                <div className="flex items-center space-x-3 text-sm text-gray-300">
                  <div className="w-2 h-2 bg-cyber-warning rounded-full"></div>
                  <span>Digital Forensics & Audit Trails</span>
                </div>
                <div className="flex items-center space-x-3 text-sm text-gray-300">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
                  <span>Vulnerability Management</span>
                </div>
                <div className="flex items-center space-x-3 text-sm text-gray-300">
                  <div className="w-2 h-2 bg-cyber-accent rounded-full"></div>
                  <span>Data Loss Prevention</span>
                </div>
              </div>

              <div className={`flex items-center justify-center space-x-2 text-cyber-danger font-medium transition-all duration-300 ${
                hoveredCard === 'officer' ? 'transform translate-x-2' : ''
              }`}>
                <span className="font-cyber">OFFICER ACCESS</span>
                <ArrowRight className="w-5 h-5" />
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-16 text-center">
          <div className="text-gray-500 text-sm mb-4 font-cyber-alt">
            POWERED BY ADVANCED AI AND MACHINE LEARNING
          </div>
          
        </div>
      </div>
    </div>
  );
};

export default LandingPage;