import React from 'react';
import { Shield, Zap, Eye, Brain, Users, Award, Github, Mail } from 'lucide-react';

interface AboutProps {
  onNavigate: (page: string) => void;
}

const About: React.FC<AboutProps> = ({ onNavigate }) => {
  const features = [
    {
      icon: Brain,
      title: 'AI-Powered Analysis',
      description: 'Advanced machine learning algorithms analyze URLs and files for sophisticated threats that traditional scanners might miss.'
    },
    {
      icon: Zap,
      title: 'Real-time Processing',
      description: 'Lightning-fast security analysis with detailed reporting in seconds, not minutes.'
    },
    {
      icon: Eye,
      title: 'Detailed Insights',
      description: 'Comprehensive security reports that explain threats in plain English, helping you understand the risks.'
    },
    {
      icon: Shield,
      title: 'Multi-layer Protection',
      description: 'Combines URL reputation analysis, file signature detection, and behavioral analysis for complete protection.'
    }
  ];

  const stats = [
    { label: 'Threats Detected', value: '50,000+', icon: Shield },
    { label: 'Files Analyzed', value: '25,000+', icon: Eye },
    { label: 'URLs Scanned', value: '100,000+', icon: Zap },
    { label: 'Security Score', value: '99.8%', icon: Award }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(34,197,94,0.05),transparent)] pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_20%,rgba(168,85,247,0.05),transparent)] pointer-events-none" />
      
      <div className="relative max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Hero Section */}
        <div className="text-center mb-16">
          <div className="flex justify-center mb-6">
            <div className="relative">
              <Shield className="w-20 h-20 text-green-400" />
              <div className="absolute inset-0 animate-pulse">
                <Shield className="w-20 h-20 text-green-400/30" />
              </div>
            </div>
          </div>
          <h1 className="text-5xl font-bold bg-gradient-to-r from-green-400 via-blue-500 to-purple-500 bg-clip-text text-transparent mb-6">
            CyberIntel
          </h1>
          <p className="text-xl text-gray-300 max-w-3xl mx-auto leading-relaxed mb-8">
            An AI-powered real-time digital spybot that scans suspicious URLs and uploaded files, 
            providing detailed explanations of potential risks to protect users from phishing, scams, and malware.
          </p>
          
          <div className="flex flex-wrap justify-center gap-4">
            <button
              onClick={() => onNavigate('url-scanner')}
              className="px-6 py-3 bg-gradient-to-r from-green-500 to-blue-600 text-white rounded-lg font-medium hover:from-green-600 hover:to-blue-700 transition-all duration-200"
            >
              Start Scanning
            </button>
            <button
              onClick={() => onNavigate('dashboard')}
              className="px-6 py-3 bg-gray-700/50 hover:bg-gray-600/50 text-gray-300 rounded-lg font-medium transition-colors"
            >
              Go to Dashboard
            </button>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {stats.map((stat, index) => {
            const Icon = stat.icon;
            return (
              <div
                key={index}
                className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-6 text-center hover:scale-105 transition-all duration-300"
              >
                <Icon className="w-8 h-8 text-green-400 mx-auto mb-3" />
                <div className="text-2xl font-bold text-white mb-1">{stat.value}</div>
                <div className="text-sm text-gray-400">{stat.label}</div>
              </div>
            );
          })}
        </div>

        {/* Features Grid */}
        <div className="mb-16">
          <h2 className="text-3xl font-bold text-white text-center mb-12">
            Why Choose CyberIntel?
          </h2>
          <div className="grid md:grid-cols-2 gap-8">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <div
                  key={index}
                  className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8 hover:border-green-500/30 transition-all duration-300"
                >
                  <div className="flex items-start space-x-4">
                    <div className="bg-green-500/20 rounded-xl p-3 flex-shrink-0">
                      <Icon className="w-6 h-6 text-green-400" />
                    </div>
                    <div>
                      <h3 className="text-xl font-bold text-white mb-3">{feature.title}</h3>
                      <p className="text-gray-300 leading-relaxed">{feature.description}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Mission Statement */}
        <div className="bg-gradient-to-r from-green-500/10 to-purple-500/10 rounded-2xl p-8 mb-16 border border-green-500/20">
          <div className="text-center">
            <h2 className="text-3xl font-bold text-white mb-6">Our Mission</h2>
            <p className="text-lg text-gray-300 max-w-4xl mx-auto leading-relaxed">
              In an era where cyber threats are becoming increasingly sophisticated, CyberIntel stands as your 
              digital guardian. Our mission is to democratize cybersecurity by making advanced threat detection 
              accessible to everyone. We believe that every user deserves to browse the internet safely and 
              confidently, without fear of malicious attacks or data breaches.
            </p>
          </div>
        </div>

        {/* Technology Stack */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8 mb-16">
          <h2 className="text-3xl font-bold text-white text-center mb-8">Built with Cutting-Edge Technology</h2>
          <div className="grid md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="bg-blue-500/20 rounded-xl p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <Brain className="w-8 h-8 text-blue-400" />
              </div>
              <h3 className="text-lg font-bold text-white mb-2">AI & Machine Learning</h3>
              <p className="text-gray-400">Advanced neural networks for pattern recognition and threat detection</p>
            </div>
            <div className="text-center">
              <div className="bg-green-500/20 rounded-xl p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <Zap className="w-8 h-8 text-green-400" />
              </div>
              <h3 className="text-lg font-bold text-white mb-2">Real-time Processing</h3>
              <p className="text-gray-400">Lightning-fast analysis with cloud-powered infrastructure</p>
            </div>
            <div className="text-center">
              <div className="bg-purple-500/20 rounded-xl p-4 w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <Shield className="w-8 h-8 text-purple-400" />
              </div>
              <h3 className="text-lg font-bold text-white mb-2">Enterprise Security</h3>
              <p className="text-gray-400">Bank-level encryption and security protocols</p>
            </div>
          </div>
        </div>


        {/* Accessibility Note */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8 mb-16">
          <div className="flex items-start space-x-4">
            <div className="bg-blue-500/20 rounded-xl p-3 flex-shrink-0">
              <Eye className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-white mb-3">Accessibility & Voice AI</h3>
              <p className="text-gray-300 leading-relaxed">
                CyberIntel includes voice narration capabilities to make cybersecurity accessible to all users. 
                The voice AI feature reads security reports aloud, ensuring that visually impaired users can fully 
                benefit from our threat analysis capabilities. This represents our commitment to inclusive design 
                and universal accessibility in cybersecurity tools.
              </p>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-r from-purple-500/10 to-blue-500/10 rounded-2xl p-8 mb-16 border border-purple-500/20">
          <div className="text-center">
            <Award className="w-16 h-16 text-purple-400 mx-auto mb-6" />
            <h2 className="text-3xl font-bold text-white mb-4">Built by Vannoor Sab</h2>
            <p className="text-lg text-gray-300 max-w-3xl mx-auto leading-relaxed mb-6">
              CyberIntel is a solo project crafted by Vannoor Sab, blending AI and cybersecurity to deliver real-time threat detection and accessible security insights for everyone.
            </p>
            <div className="flex items-center justify-center space-x-4 mt-4">
              <a
                href="https://www.linkedin.com/in/vannoorsab/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center space-x-2 px-5 py-2 bg-blue-700/20 hover:bg-blue-700/30 text-blue-400 rounded-lg transition-colors"
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.761 0 5-2.239 5-5v-14c0-2.761-2.239-5-5-5zm-11 19h-3v-10h3v10zm-1.5-11.268c-.966 0-1.75-.784-1.75-1.75s.784-1.75 1.75-1.75 1.75.784 1.75 1.75-.784 1.75-1.75 1.75zm13.5 11.268h-3v-5.604c0-1.337-.025-3.063-1.868-3.063-1.868 0-2.154 1.459-2.154 2.967v5.7h-3v-10h2.881v1.367h.041c.401-.761 1.379-1.563 2.841-1.563 3.04 0 3.601 2.002 3.601 4.604v5.592z"/>
                </svg>
                <span>LinkedIn</span>
              </a>
              <a
                href="https://github.com/vannoorsab"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center space-x-2 px-5 py-2 bg-gray-700/50 hover:bg-gray-600/50 text-gray-300 rounded-lg transition-colors"
              >
                <Github className="w-5 h-5" />
                <span>GitHub</span>
              </a>
            </div>
          </div>
        </div>

        {/* Contact Section */}
        <div className="text-center">
          <h2 className="text-2xl font-bold text-white mb-6">Get in Touch</h2>
          <div className="flex justify-center space-x-6">
            <a
              href="mailto:contact@cyberintel.ai"
              className="flex items-center space-x-2 px-6 py-3 bg-green-500/20 hover:bg-green-500/30 text-green-400 rounded-lg transition-colors"
            >
              <Mail className="w-5 h-5" />
              <span>Contact Us</span>
            </a>
            <a
              href="https://github.com/vannoor/cyberintel"
              className="flex items-center space-x-2 px-6 py-3 bg-gray-700/50 hover:bg-gray-600/50 text-gray-300 rounded-lg transition-colors"
            >
              <Github className="w-5 h-5" />
              <span>View Source</span>
            </a>
          </div>
        </div>

       
      </div>
    </div>
  );
};

export default About;