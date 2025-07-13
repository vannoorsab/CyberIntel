import React, { useState, useEffect, useRef } from 'react';
import { Brain, MessageSquare, BarChart3, Zap, Search, Settings, Play, Pause, TrendingUp, AlertTriangle, Shield, Database, Activity, Mic, MicOff, Volume2, VolumeX, Send, Bot, User, Eye, Filter, Download, RefreshCw } from 'lucide-react';
import { useAlert } from '../contexts/AlertContext';
import { AIMLEngine, BehavioralModel, ChatMessage, LogClassification, AnomalyDetection, ThreatPrediction } from '../utils/aimlEngine';

interface AIMLIntegrationProps {
  onNavigate: (page: string) => void;
}

const AIMLIntegration: React.FC<AIMLIntegrationProps> = ({ onNavigate }) => {
  const [activeTab, setActiveTab] = useState('chatbot');
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [voiceEnabled, setVoiceEnabled] = useState(true);
  const [behavioralModels, setBehavioralModels] = useState<BehavioralModel[]>([]);
  const [logClassifications, setLogClassifications] = useState<LogClassification[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyDetection[]>([]);
  const [predictions, setPredictions] = useState<ThreatPrediction[]>([]);
  const [isTraining, setIsTraining] = useState(false);
  const [modelAccuracy, setModelAccuracy] = useState(94.2);
  const [processingLogs, setProcessingLogs] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const recognitionRef = useRef<any>(null);
  const synthRef = useRef<SpeechSynthesis | null>(null);
  const { addAlert } = useAlert();

  const aimlEngine = new AIMLEngine();

  useEffect(() => {
    loadMockData();
    initializeSpeechServices();
    
    // Add welcome message
    const welcomeMessage: ChatMessage = {
      id: 'welcome',
      type: 'assistant',
      content: "Hello! I'm your AI security assistant. I can help you analyze threats, investigate incidents, manage vulnerabilities, and answer security questions. How can I assist you today?",
      timestamp: new Date(),
      confidence: 100,
      intent: 'greeting',
      entities: []
    };
    setChatMessages([welcomeMessage]);

    // Simulate real-time ML processing
    const interval = setInterval(() => {
      simulateRealTimeProcessing();
    }, 10000); // Every 10 seconds

    return () => {
      clearInterval(interval);
      if (recognitionRef.current) {
        recognitionRef.current.stop();
      }
    };
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [chatMessages]);

  const loadMockData = () => {
    // Mock Behavioral Models
    const mockModels: BehavioralModel[] = [
      {
        id: 'user_behavior_001',
        name: 'User Login Patterns',
        type: 'behavioral_analysis',
        description: 'Analyzes user login patterns to detect anomalous access',
        accuracy: 96.8,
        lastTrained: new Date(Date.now() - 86400000),
        status: 'active',
        features: ['login_time', 'source_ip', 'device_fingerprint', 'geolocation'],
        anomaliesDetected: 23,
        falsePositiveRate: 2.1,
        trainingData: 50000,
        modelType: 'isolation_forest'
      },
      {
        id: 'network_traffic_001',
        name: 'Network Traffic Analysis',
        type: 'network_analysis',
        description: 'Detects unusual network traffic patterns and potential data exfiltration',
        accuracy: 92.4,
        lastTrained: new Date(Date.now() - 172800000),
        status: 'active',
        features: ['packet_size', 'frequency', 'destination', 'protocol', 'timing'],
        anomaliesDetected: 45,
        falsePositiveRate: 4.2,
        trainingData: 100000,
        modelType: 'lstm_autoencoder'
      },
      {
        id: 'file_access_001',
        name: 'File Access Behavior',
        type: 'data_access',
        description: 'Monitors file access patterns to identify potential insider threats',
        accuracy: 89.7,
        lastTrained: new Date(Date.now() - 259200000),
        status: 'training',
        features: ['access_time', 'file_type', 'user_role', 'access_frequency'],
        anomaliesDetected: 12,
        falsePositiveRate: 6.8,
        trainingData: 75000,
        modelType: 'random_forest'
      }
    ];

    // Mock Log Classifications
    const mockClassifications: LogClassification[] = [
      {
        id: 'log_001',
        timestamp: new Date(Date.now() - 1800000),
        originalLog: 'Failed login attempt from 203.0.113.42 for user admin',
        classification: 'security_event',
        confidence: 98.5,
        severity: 'high',
        category: 'authentication_failure',
        extractedEntities: [
          { type: 'ip_address', value: '203.0.113.42', confidence: 99.9 },
          { type: 'username', value: 'admin', confidence: 95.0 },
          { type: 'action', value: 'failed_login', confidence: 98.0 }
        ],
        suggestedActions: ['block_ip', 'alert_admin', 'investigate_source'],
        relatedEvents: ['log_002', 'log_005']
      },
      {
        id: 'log_002',
        timestamp: new Date(Date.now() - 1200000),
        originalLog: 'Large file transfer detected: 2.5GB to external.domain.com',
        classification: 'data_exfiltration',
        confidence: 87.3,
        severity: 'critical',
        category: 'data_transfer',
        extractedEntities: [
          { type: 'file_size', value: '2.5GB', confidence: 99.0 },
          { type: 'destination', value: 'external.domain.com', confidence: 96.0 },
          { type: 'action', value: 'file_transfer', confidence: 92.0 }
        ],
        suggestedActions: ['block_transfer', 'quarantine_file', 'investigate_user'],
        relatedEvents: ['log_001', 'log_003']
      }
    ];

    // Mock Anomalies
    const mockAnomalies: AnomalyDetection[] = [
      {
        id: 'anomaly_001',
        timestamp: new Date(Date.now() - 900000),
        type: 'behavioral_anomaly',
        description: 'User accessing files outside normal working hours',
        severity: 'medium',
        confidence: 84.2,
        affectedEntity: 'john.doe@company.com',
        baselineDeviation: 3.2,
        features: {
          access_time: '02:30 AM',
          normal_hours: '09:00-17:00',
          file_count: 45,
          typical_count: 12
        },
        modelUsed: 'user_behavior_001',
        suggestedActions: ['verify_user_identity', 'check_authorization', 'monitor_activity']
      },
      {
        id: 'anomaly_002',
        timestamp: new Date(Date.now() - 600000),
        type: 'network_anomaly',
        description: 'Unusual outbound traffic volume detected',
        severity: 'high',
        confidence: 91.7,
        affectedEntity: '192.168.1.150',
        baselineDeviation: 5.8,
        features: {
          traffic_volume: '500MB',
          normal_volume: '50MB',
          destination_count: 25,
          typical_destinations: 5
        },
        modelUsed: 'network_traffic_001',
        suggestedActions: ['investigate_traffic', 'check_malware', 'isolate_endpoint']
      }
    ];

    // Mock Predictions
    const mockPredictions: ThreatPrediction[] = [
      {
        id: 'pred_001',
        timestamp: new Date(),
        predictionType: 'attack_likelihood',
        description: 'Increased probability of phishing attack based on recent patterns',
        probability: 78.5,
        timeframe: '24-48 hours',
        confidence: 82.0,
        factors: [
          'Increased suspicious email activity',
          'Recent credential harvesting attempts',
          'Similar attack patterns in threat intelligence'
        ],
        recommendedActions: [
          'Enhance email filtering',
          'Increase user awareness training',
          'Monitor for phishing indicators'
        ],
        modelUsed: 'threat_prediction_ensemble'
      }
    ];

    setBehavioralModels(mockModels);
    setLogClassifications(mockClassifications);
    setAnomalies(mockAnomalies);
    setPredictions(mockPredictions);
  };

  const initializeSpeechServices = () => {
    // Initialize Speech Recognition
    if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
      const SpeechRecognition = (window as any).webkitSpeechRecognition || (window as any).SpeechRecognition;
      recognitionRef.current = new SpeechRecognition();
      recognitionRef.current.continuous = false;
      recognitionRef.current.interimResults = false;
      recognitionRef.current.lang = 'en-US';

      recognitionRef.current.onresult = (event: any) => {
        const transcript = event.results[0][0].transcript;
        setInputMessage(transcript);
        setIsListening(false);
      };

      recognitionRef.current.onerror = () => {
        setIsListening(false);
      };

      recognitionRef.current.onend = () => {
        setIsListening(false);
      };
    }

    // Initialize Speech Synthesis
    if ('speechSynthesis' in window) {
      synthRef.current = window.speechSynthesis;
    }
  };

  const simulateRealTimeProcessing = () => {
    // Simulate new log classification
    if (Math.random() < 0.3) {
      const newClassification = aimlEngine.generateMockLogClassification();
      setLogClassifications(prev => [newClassification, ...prev.slice(0, 19)]);
    }

    // Simulate anomaly detection
    if (Math.random() < 0.2) {
      const newAnomaly = aimlEngine.generateMockAnomaly();
      setAnomalies(prev => [newAnomaly, ...prev.slice(0, 19)]);

      // Auto-alert for high-severity anomalies
      if (newAnomaly.severity === 'high' || newAnomaly.severity === 'critical') {
        addAlert({
          type: 'ThreatScan',
          userEmail: 'ai-system@agentphantom.ai',
          message: `🤖 AI detected ${newAnomaly.severity} anomaly: ${newAnomaly.description}`,
          status: 'unread',
          relatedId: newAnomaly.id,
          priority: newAnomaly.severity === 'critical' ? 'critical' : 'high'
        });
      }
    }

    // Update model accuracy (simulate drift)
    setModelAccuracy(prev => {
      const change = (Math.random() - 0.5) * 0.5;
      return Math.max(85, Math.min(99, prev + change));
    });
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage: ChatMessage = {
      id: `user_${Date.now()}`,
      type: 'user',
      content: inputMessage,
      timestamp: new Date(),
      confidence: 100,
      intent: 'query',
      entities: []
    };

    setChatMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsTyping(true);

    // Simulate AI processing
    setTimeout(async () => {
      const response = await aimlEngine.processNaturalLanguageQuery(inputMessage);
      const assistantMessage: ChatMessage = {
        id: `assistant_${Date.now()}`,
        type: 'assistant',
        content: response.content,
        timestamp: new Date(),
        confidence: response.confidence,
        intent: response.intent,
        entities: response.entities,
        actions: response.actions
      };

      setChatMessages(prev => [...prev, assistantMessage]);
      setIsTyping(false);

      // Text-to-speech for assistant responses
      if (voiceEnabled && synthRef.current) {
        speakText(response.content);
      }
    }, 1500);
  };

  const startListening = () => {
    if (recognitionRef.current && !isListening) {
      setIsListening(true);
      recognitionRef.current.start();
    }
  };

  const speakText = (text: string) => {
    if (synthRef.current && voiceEnabled) {
      setIsSpeaking(true);
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 0.9;
      utterance.pitch = 1.0;
      utterance.volume = 0.8;
      
      utterance.onend = () => {
        setIsSpeaking(false);
      };

      synthRef.current.speak(utterance);
    }
  };

  const stopSpeaking = () => {
    if (synthRef.current) {
      synthRef.current.cancel();
      setIsSpeaking(false);
    }
  };

  const retrainModel = async (modelId: string) => {
    setIsTraining(true);
    
    // Simulate model retraining
    setTimeout(() => {
      setBehavioralModels(prev => prev.map(model => 
        model.id === modelId 
          ? { 
              ...model, 
              lastTrained: new Date(), 
              accuracy: Math.min(99, model.accuracy + Math.random() * 2),
              status: 'active'
            }
          : model
      ));
      setIsTraining(false);
    }, 3000);
  };

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getModelStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-400 bg-green-500/20 border-green-500/30';
      case 'training': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'inactive': return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(147,51,234,0.1),transparent)] pointer-events-none" />
      
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-purple-400 to-pink-500 bg-clip-text text-transparent mb-2">
            🤖 AI/ML Security Intelligence
          </h1>
          <p className="text-gray-300">Advanced AI-powered behavioral analytics, natural language interface, and automated threat detection</p>
        </div>

        {/* Tab Navigation */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-2 mb-8">
          <div className="flex space-x-2">
            {[
              { id: 'chatbot', label: '🤖 AI Assistant', icon: MessageSquare },
              { id: 'behavioral', label: '📊 Behavioral Analytics', icon: BarChart3 },
              { id: 'classification', label: '🏷️ Log Classification', icon: Database },
              { id: 'anomalies', label: '⚠️ Anomaly Detection', icon: AlertTriangle },
              { id: 'predictions', label: '🔮 Threat Prediction', icon: TrendingUp }
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-1 px-4 py-3 rounded-xl font-medium transition-all duration-200 flex items-center justify-center space-x-2 ${
                    activeTab === tab.id
                      ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                      : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span className="hidden sm:inline">{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* AI Chatbot Tab */}
        {activeTab === 'chatbot' && (
          <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white flex items-center">
                <Bot className="w-5 h-5 mr-3 text-purple-400" />
                AI Security Assistant
              </h3>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setVoiceEnabled(!voiceEnabled)}
                  className={`p-2 rounded-lg transition-colors ${
                    voiceEnabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                  }`}
                  title={voiceEnabled ? 'Voice enabled' : 'Voice disabled'}
                >
                  {voiceEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
                </button>
                {isSpeaking && (
                  <button
                    onClick={stopSpeaking}
                    className="p-2 bg-red-500/20 text-red-400 rounded-lg transition-colors"
                    title="Stop speaking"
                  >
                    <VolumeX className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>

            {/* Chat Messages */}
            <div className="bg-black/30 rounded-xl p-6 h-96 overflow-y-auto mb-6 border border-gray-700/30">
              <div className="space-y-4">
                {chatMessages.map((message) => (
                  <div
                    key={message.id}
                    className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div className={`max-w-xs lg:max-w-md px-4 py-3 rounded-2xl ${
                      message.type === 'user'
                        ? 'bg-purple-500/20 text-purple-100 border border-purple-500/30'
                        : 'bg-gray-700/50 text-gray-100 border border-gray-600/30'
                    }`}>
                      <div className="flex items-start space-x-2">
                        {message.type === 'assistant' && <Bot className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />}
                        {message.type === 'user' && <User className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />}
                        <div className="flex-1">
                          <p className="text-sm leading-relaxed">{message.content}</p>
                          {message.confidence && message.confidence < 90 && (
                            <div className="mt-2 text-xs text-yellow-400">
                              Confidence: {message.confidence.toFixed(1)}%
                            </div>
                          )}
                          {message.actions && message.actions.length > 0 && (
                            <div className="mt-2 space-y-1">
                              {message.actions.map((action, index) => (
                                <button
                                  key={index}
                                  onClick={() => {/* Handle action */}}
                                  className="block w-full text-left px-2 py-1 bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 rounded text-xs transition-colors"
                                >
                                  {action}
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="text-xs text-gray-400 mt-1 text-right">
                        {message.timestamp.toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                ))}
                
                {isTyping && (
                  <div className="flex justify-start">
                    <div className="bg-gray-700/50 text-gray-100 border border-gray-600/30 px-4 py-3 rounded-2xl">
                      <div className="flex items-center space-x-2">
                        <Bot className="w-4 h-4 text-purple-400" />
                        <div className="flex space-x-1">
                          <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" />
                          <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }} />
                          <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>
            </div>

            {/* Input Area */}
            <div className="flex items-center space-x-4">
              <div className="flex-1 relative">
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                  placeholder="Ask me about threats, incidents, vulnerabilities, or security analysis..."
                  className="w-full px-4 py-3 pr-12 bg-black/50 border border-gray-600 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500 transition-all duration-200"
                  disabled={isTyping}
                />
                <button
                  onClick={startListening}
                  disabled={isListening || isTyping}
                  className={`absolute right-3 top-1/2 transform -translate-y-1/2 p-1 rounded-lg transition-colors ${
                    isListening 
                      ? 'bg-red-500/20 text-red-400 animate-pulse' 
                      : 'bg-gray-600/20 text-gray-400 hover:text-purple-400'
                  }`}
                  title={isListening ? 'Listening...' : 'Voice input'}
                >
                  {isListening ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
                </button>
              </div>
              <button
                onClick={handleSendMessage}
                disabled={!inputMessage.trim() || isTyping}
                className="px-6 py-3 bg-gradient-to-r from-purple-500 to-pink-600 text-white rounded-xl font-medium hover:from-purple-600 hover:to-pink-700 focus:outline-none focus:ring-2 focus:ring-purple-500/50 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center space-x-2"
              >
                <Send className="w-4 h-4" />
                <span>Send</span>
              </button>
            </div>

            {/* Quick Actions */}
            <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                'Analyze recent threats',
                'Check system vulnerabilities',
                'Review security incidents',
                'Generate threat report'
              ].map((action, index) => (
                <button
                  key={index}
                  onClick={() => setInputMessage(action)}
                  className="px-3 py-2 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 rounded-lg text-sm transition-colors border border-purple-500/20"
                >
                  {action}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Behavioral Analytics Tab */}
        {activeTab === 'behavioral' && (
          <div className="space-y-6">
            {/* Model Overview */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white">ML Model Performance</h3>
                <div className="flex items-center space-x-4">
                  <div className="text-right">
                    <div className="text-sm text-gray-400">Overall Accuracy</div>
                    <div className="text-2xl font-bold text-green-400">{modelAccuracy.toFixed(1)}%</div>
                  </div>
                  <button
                    onClick={() => setProcessingLogs(!processingLogs)}
                    className={`px-4 py-2 rounded-lg font-medium transition-colors flex items-center space-x-2 ${
                      processingLogs 
                        ? 'bg-red-500/20 hover:bg-red-500/30 text-red-400' 
                        : 'bg-green-500/20 hover:bg-green-500/30 text-green-400'
                    }`}
                  >
                    {processingLogs ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                    <span>{processingLogs ? 'Pause' : 'Start'} Processing</span>
                  </button>
                </div>
              </div>

              <div className="grid md:grid-cols-3 gap-6">
                {behavioralModels.map((model) => (
                  <div key={model.id} className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h4 className="text-lg font-bold text-white mb-1">{model.name}</h4>
                        <p className="text-gray-400 text-sm">{model.description}</p>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getModelStatusColor(model.status)}`}>
                        {model.status.toUpperCase()}
                      </span>
                    </div>

                    <div className="space-y-3 mb-4">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400 text-sm">Accuracy:</span>
                        <span className="text-green-400 font-bold">{model.accuracy.toFixed(1)}%</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400 text-sm">False Positive Rate:</span>
                        <span className="text-yellow-400 font-bold">{model.falsePositiveRate.toFixed(1)}%</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400 text-sm">Anomalies Detected:</span>
                        <span className="text-red-400 font-bold">{model.anomaliesDetected}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400 text-sm">Training Data:</span>
                        <span className="text-blue-400 font-bold">{model.trainingData.toLocaleString()}</span>
                      </div>
                    </div>

                    <div className="mb-4">
                      <span className="text-gray-400 text-sm">Features:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {model.features.map((feature, index) => (
                          <span key={index} className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">
                            {feature}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="text-xs text-gray-400 mb-4">
                      Last trained: {model.lastTrained.toLocaleDateString()}
                    </div>

                    <button
                      onClick={() => retrainModel(model.id)}
                      disabled={isTraining || model.status === 'training'}
                      className="w-full px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center space-x-2"
                    >
                      {isTraining || model.status === 'training' ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Training...</span>
                        </>
                      ) : (
                        <>
                          <Brain className="w-4 h-4" />
                          <span>Retrain Model</span>
                        </>
                      )}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Log Classification Tab */}
        {activeTab === 'classification' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                <Database className="w-5 h-5 mr-3 text-blue-400" />
                Automated Log Classification
              </h3>
              
              <div className="space-y-4">
                {logClassifications.map((classification) => (
                  <div key={classification.id} className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <span className={`px-3 py-1 rounded border text-sm font-medium ${getSeverityColor(classification.severity)}`}>
                            {classification.severity.toUpperCase()}
                          </span>
                          <span className="px-3 py-1 bg-blue-500/20 text-blue-400 rounded text-sm font-medium">
                            {classification.category.replace('_', ' ').toUpperCase()}
                          </span>
                          <span className="text-gray-400 text-sm">
                            Confidence: {classification.confidence.toFixed(1)}%
                          </span>
                        </div>
                        <div className="bg-gray-800/50 rounded-lg p-3 mb-3">
                          <code className="text-gray-300 text-sm">{classification.originalLog}</code>
                        </div>
                        <div className="text-sm text-gray-400">
                          Classification: <span className="text-white">{classification.classification.replace('_', ' ')}</span>
                        </div>
                      </div>
                      <div className="text-right text-sm text-gray-400">
                        {classification.timestamp.toLocaleString()}
                      </div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-4 mb-4">
                      <div>
                        <span className="text-gray-400 text-sm">Extracted Entities:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {classification.extractedEntities.map((entity, index) => (
                            <span key={index} className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">
                              {entity.type}: {entity.value} ({entity.confidence.toFixed(0)}%)
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <span className="text-gray-400 text-sm">Suggested Actions:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {classification.suggestedActions.map((action, index) => (
                            <span key={index} className="px-2 py-1 bg-orange-500/20 text-orange-400 rounded text-xs">
                              {action.replace('_', ' ')}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    {classification.relatedEvents.length > 0 && (
                      <div className="text-sm text-gray-400">
                        Related Events: {classification.relatedEvents.join(', ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Anomaly Detection Tab */}
        {activeTab === 'anomalies' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-3 text-red-400" />
                Real-time Anomaly Detection
              </h3>
              
              <div className="space-y-4">
                {anomalies.map((anomaly) => (
                  <div key={anomaly.id} className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <div className="flex items-center space-x-3 mb-2">
                          <span className={`px-3 py-1 rounded border text-sm font-medium ${getSeverityColor(anomaly.severity)}`}>
                            {anomaly.severity.toUpperCase()}
                          </span>
                          <span className="px-3 py-1 bg-purple-500/20 text-purple-400 rounded text-sm font-medium">
                            {anomaly.type.replace('_', ' ').toUpperCase()}
                          </span>
                          <span className="text-gray-400 text-sm">
                            Confidence: {anomaly.confidence.toFixed(1)}%
                          </span>
                        </div>
                        <h4 className="text-lg font-bold text-white mb-2">{anomaly.description}</h4>
                        <div className="text-sm text-gray-400">
                          Affected Entity: <span className="text-white">{anomaly.affectedEntity}</span>
                        </div>
                        <div className="text-sm text-gray-400">
                          Baseline Deviation: <span className="text-red-400">{anomaly.baselineDeviation.toFixed(1)}σ</span>
                        </div>
                      </div>
                      <div className="text-right text-sm text-gray-400">
                        {anomaly.timestamp.toLocaleString()}
                      </div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-4 mb-4">
                      <div>
                        <span className="text-gray-400 text-sm">Anomaly Features:</span>
                        <div className="bg-gray-800/50 rounded-lg p-3 mt-1">
                          {Object.entries(anomaly.features).map(([key, value]) => (
                            <div key={key} className="flex justify-between text-sm">
                              <span className="text-gray-400">{key.replace('_', ' ')}:</span>
                              <span className="text-white">{value}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div>
                        <span className="text-gray-400 text-sm">Suggested Actions:</span>
                        <div className="space-y-1 mt-1">
                          {anomaly.suggestedActions.map((action, index) => (
                            <button
                              key={index}
                              className="block w-full text-left px-3 py-2 bg-orange-500/20 hover:bg-orange-500/30 text-orange-400 rounded text-sm transition-colors"
                            >
                              {action.replace('_', ' ')}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="text-sm text-gray-400">
                      Model Used: <span className="text-purple-400">{anomaly.modelUsed}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Threat Prediction Tab */}
        {activeTab === 'predictions' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                <TrendingUp className="w-5 h-5 mr-3 text-green-400" />
                AI Threat Prediction
              </h3>
              
              <div className="space-y-6">
                {predictions.map((prediction) => (
                  <div key={prediction.id} className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h4 className="text-lg font-bold text-white mb-2">{prediction.description}</h4>
                        <div className="flex items-center space-x-4 mb-3">
                          <div className="flex items-center space-x-2">
                            <span className="text-gray-400 text-sm">Probability:</span>
                            <span className={`text-lg font-bold ${
                              prediction.probability >= 80 ? 'text-red-400' :
                              prediction.probability >= 60 ? 'text-orange-400' :
                              prediction.probability >= 40 ? 'text-yellow-400' : 'text-green-400'
                            }`}>
                              {prediction.probability.toFixed(1)}%
                            </span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-gray-400 text-sm">Timeframe:</span>
                            <span className="text-white">{prediction.timeframe}</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-gray-400 text-sm">Confidence:</span>
                            <span className="text-blue-400">{prediction.confidence.toFixed(1)}%</span>
                          </div>
                        </div>
                      </div>
                      <div className="text-right text-sm text-gray-400">
                        {prediction.timestamp.toLocaleString()}
                      </div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-6">
                      <div>
                        <span className="text-gray-400 text-sm">Contributing Factors:</span>
                        <ul className="mt-2 space-y-1">
                          {prediction.factors.map((factor, index) => (
                            <li key={index} className="text-gray-300 text-sm flex items-start">
                              <span className="text-orange-400 mr-2">•</span>
                              {factor}
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <span className="text-gray-400 text-sm">Recommended Actions:</span>
                        <div className="space-y-1 mt-2">
                          {prediction.recommendedActions.map((action, index) => (
                            <button
                              key={index}
                              className="block w-full text-left px-3 py-2 bg-green-500/20 hover:bg-green-500/30 text-green-400 rounded text-sm transition-colors"
                            >
                              {action}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="mt-4 text-sm text-gray-400">
                      Model: <span className="text-purple-400">{prediction.modelUsed}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Built with Bolt Badge */}
        <div className="mt-12 text-center">
          <div className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-blue-500/20 to-purple-500/20 border border-blue-500/30 rounded-xl">
            <Zap className="w-5 h-5 text-blue-400 mr-2" />
            <span className="text-blue-400 font-medium">Built with Bolt</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AIMLIntegration;