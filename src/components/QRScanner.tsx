import React, { useState, useRef } from 'react';
import { QrCode, Upload, Search, Shield, AlertTriangle, Ban, Copy, Zap, Camera, FileImage } from 'lucide-react';
import { analyzeQRCode } from '../utils/mockAI';
import { ScanResult } from '../types';
import { useAlert } from '../contexts/AlertContext';
import { createThreatAlert } from '../utils/alertUtils';

interface QRScannerProps {
  onNavigate: (page: string) => void;
}

const QRScanner: React.FC<QRScannerProps> = ({ onNavigate }) => {
  const [selectedImage, setSelectedImage] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { addAlert } = useAlert();

  const handleImageSelect = (file: File) => {
    const maxSize = 10 * 1024 * 1024; // 10MB limit
    
    if (file.size > maxSize) {
      setError('Image size must be less than 10MB');
      return;
    }

    // Check if file is an image
    if (!file.type.startsWith('image/')) {
      setError('Please select a valid image file (PNG, JPG, JPEG, GIF, WebP)');
      return;
    }

    setSelectedImage(file);
    setError('');
    setResult(null);

    // Create preview
    const reader = new FileReader();
    reader.onload = (e) => {
      setImagePreview(e.target?.result as string);
    };
    reader.readAsDataURL(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      handleImageSelect(files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleImageSelect(files[0]);
    }
  };

  const handleScan = async () => {
    if (!selectedImage) {
      setError('Please select a QR code image to scan');
      return;
    }

    setIsScanning(true);
    setError('');
    setResult(null);

    try {
      const scanResult = await analyzeQRCode(selectedImage.name, selectedImage.type);
      setResult(scanResult);

      // 🚨 AUTO ALERT SYSTEM: Trigger alert for high-risk QR codes
      if (scanResult.riskLevel === 'dangerous') {
        const alertData = createThreatAlert(
          scanResult.userEmail || 'current.user@example.com',
          scanResult.target,
          scanResult.riskLevel,
          scanResult.id
        );
        addAlert(alertData);
      }
    } catch (err) {
      setError('QR code analysis failed. Please try again with a clearer image.');
    } finally {
      setIsScanning(false);
    }
  };

  const copyReport = () => {
    if (result) {
      navigator.clipboard.writeText(result.report);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getRiskDisplay = () => {
    if (!result) return null;

    const riskConfig = {
      safe: {
        icon: Shield,
        color: 'text-green-400',
        bg: 'bg-green-500/20',
        border: 'border-green-500/30',
        label: '✅ Safe',
        description: 'This QR code appears to be safe'
      },
      suspicious: {
        icon: AlertTriangle,
        color: 'text-yellow-400',
        bg: 'bg-yellow-500/20',
        border: 'border-yellow-500/30',
        label: '⚠️ Suspicious',
        description: 'Exercise caution with this QR code'
      },
      dangerous: {
        icon: Ban,
        color: 'text-red-400',
        bg: 'bg-red-500/20',
        border: 'border-red-500/30',
        label: '🚫 Dangerous',
        description: 'This QR code contains malicious content'
      }
    };

    return riskConfig[result.riskLevel];
  };

  const riskDisplay = getRiskDisplay();

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_30%,rgba(139,69,19,0.1),transparent)] pointer-events-none" />
      
      <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex justify-center mb-4">
            <div className="relative">
              <QrCode className="w-16 h-16 text-orange-400" />
              <div className="absolute inset-0 animate-pulse">
                <QrCode className="w-16 h-16 text-orange-400/30" />
              </div>
            </div>
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-orange-400 to-red-500 bg-clip-text text-transparent mb-4">
            QR Code Security Scanner
          </h1>
          <p className="text-gray-300 text-lg max-w-2xl mx-auto">
            Upload QR code images to analyze them for malicious URLs, phishing attempts, and other security threats before scanning.
          </p>
        </div>

        {/* QR Code Upload Area */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8 mb-8">
          <div
            className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all duration-300 ${
              dragOver
                ? 'border-orange-500 bg-orange-500/10'
                : selectedImage
                ? 'border-green-500 bg-green-500/10'
                : 'border-gray-600 hover:border-orange-500/50 hover:bg-orange-500/5'
            }`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            {selectedImage && imagePreview ? (
              <div className="space-y-4">
                <div className="flex justify-center">
                  <img
                    src={imagePreview}
                    alt="QR Code Preview"
                    className="max-w-xs max-h-64 rounded-lg border border-gray-600 object-contain"
                  />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-white mb-2">{selectedImage.name}</h3>
                  <p className="text-gray-400 mb-1">
                    Type: {selectedImage.type} • Size: {formatFileSize(selectedImage.size)}
                  </p>
                  <p className="text-green-400 text-sm">✅ QR code image loaded and ready for analysis</p>
                </div>
                <button
                  onClick={() => {
                    setSelectedImage(null);
                    setImagePreview(null);
                    setResult(null);
                    setError('');
                  }}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  Select a different image
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                <QrCode className="w-16 h-16 text-gray-400 mx-auto" />
                <div>
                  <h3 className="text-xl font-bold text-white mb-2">Drop your QR code image here</h3>
                  <p className="text-gray-400 mb-4">
                    or click to browse (Max size: 10MB)
                  </p>
                  <div className="flex justify-center space-x-4">
                    <button
                      onClick={() => fileInputRef.current?.click()}
                      className="px-6 py-3 bg-gradient-to-r from-orange-500 to-red-600 text-white rounded-lg font-medium hover:from-orange-600 hover:to-red-700 transition-all duration-200 flex items-center space-x-2"
                    >
                      <FileImage className="w-5 h-5" />
                      <span>Browse Images</span>
                    </button>
                  </div>
                </div>
                <p className="text-gray-500 text-sm">
                  Supported formats: PNG, JPG, JPEG, GIF, WebP
                </p>
              </div>
            )}
          </div>

          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileInputChange}
            className="hidden"
            accept="image/*"
          />

          {error && (
            <div className="mt-4 bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
              {error}
            </div>
          )}

          {selectedImage && (
            <div className="mt-6 text-center">
              <button
                onClick={handleScan}
                disabled={isScanning}
                className="px-8 py-4 bg-gradient-to-r from-orange-500 to-red-600 text-white rounded-xl font-medium hover:from-orange-600 hover:to-red-700 focus:outline-none focus:ring-2 focus:ring-orange-500/50 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center space-x-2 mx-auto"
              >
                {isScanning ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent" />
                    <span>Analyzing QR Code...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-5 h-5" />
                    <span>Analyze QR Code</span>
                  </>
                )}
              </button>
            </div>
          )}
        </div>

        {/* Analysis Results */}
        {result && riskDisplay && (
          <div className="space-y-6">
            {/* Risk Level Badge */}
            <div className={`${riskDisplay.bg} ${riskDisplay.border} border rounded-2xl p-6`}>
              <div className="flex items-center space-x-4">
                <riskDisplay.icon className={`w-12 h-12 ${riskDisplay.color}`} />
                <div>
                  <h3 className={`text-2xl font-bold ${riskDisplay.color}`}>
                    {riskDisplay.label}
                  </h3>
                  <p className="text-gray-300 mt-1">{riskDisplay.description}</p>
                  {result.riskLevel === 'dangerous' && (
                    <div className="mt-3 bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                      <p className="text-red-400 text-sm font-medium">
                        🚨 CRITICAL ALERT: Officers have been automatically notified
                      </p>
                      <p className="text-red-300 text-xs mt-1">
                        📧 Email alert sent to vanursab71@gmail.com and security team
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Detailed Report */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white">QR Code Analysis Report</h3>
                <div className="flex space-x-3">
                  <button
                    onClick={copyReport}
                    className="px-4 py-2 bg-gray-700/50 hover:bg-gray-600/50 text-gray-300 rounded-lg transition-colors flex items-center space-x-2"
                  >
                    <Copy className="w-4 h-4" />
                    <span>Copy</span>
                  </button>
                </div>
              </div>

              <div className="bg-black/30 rounded-xl p-6 border border-gray-700/30">
                <div className="text-gray-300 whitespace-pre-line leading-relaxed">
                  {result.report}
                </div>
              </div>

              <div className="mt-6 flex items-center justify-between text-sm text-gray-400">
                <span>QR Code: {result.target}</span>
                <span>Analysis completed at {result.timestamp.toLocaleTimeString()}</span>
              </div>
            </div>
          </div>
        )}

        {/* Security Tips */}
        <div className="mt-12 bg-blue-500/10 border border-blue-500/20 rounded-2xl p-8">
          <h3 className="text-xl font-bold text-blue-400 mb-4">🛡️ QR Code Security Tips</h3>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="text-white font-medium mb-2">Before Scanning:</h4>
              <ul className="text-gray-300 space-y-1 text-sm">
                <li>• 🔍 Always verify the source of QR codes</li>
                <li>• 📱 Use this scanner to check suspicious codes</li>
                <li>• 🚫 Avoid QR codes from unknown sources</li>
                <li>• 👀 Look for signs of tampering or overlay stickers</li>
              </ul>
            </div>
            <div>
              <h4 className="text-white font-medium mb-2">Red Flags:</h4>
              <ul className="text-gray-300 space-y-1 text-sm">
                <li>• 🚨 QR codes in unexpected locations</li>
                <li>• 📧 Codes received via suspicious emails</li>
                <li>• 💰 Codes promising unrealistic rewards</li>
                <li>• ⚡ Codes creating urgency or pressure</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="mt-12 grid md:grid-cols-3 gap-6">
          <button
            onClick={() => onNavigate('url-scanner')}
            className="bg-gradient-to-r from-green-500/20 to-green-600/20 hover:from-green-500/30 hover:to-green-600/30 border border-green-500/30 rounded-xl p-6 text-left transition-all duration-300 hover:scale-105"
          >
            <h3 className="text-lg font-bold text-white mb-2">Scan a URL</h3>
            <p className="text-gray-300">Analyze suspicious links for threats</p>
          </button>
          
          <button
            onClick={() => onNavigate('file-upload')}
            className="bg-gradient-to-r from-purple-500/20 to-purple-600/20 hover:from-purple-500/30 hover:to-purple-600/30 border border-purple-500/30 rounded-xl p-6 text-left transition-all duration-300 hover:scale-105"
          >
            <h3 className="text-lg font-bold text-white mb-2">Upload a File</h3>
            <p className="text-gray-300">Analyze files for malware and threats</p>
          </button>
          
          <button
            onClick={() => onNavigate('dashboard')}
            className="bg-gradient-to-r from-gray-700/20 to-gray-800/20 hover:from-gray-700/30 hover:to-gray-800/30 border border-gray-600/30 rounded-xl p-6 text-left transition-all duration-300 hover:scale-105"
          >
            <h3 className="text-lg font-bold text-white mb-2">Back to Dashboard</h3>
            <p className="text-gray-300">Return to your security command center</p>
          </button>
        </div>

       
      </div>
    </div>
  );
};

export default QRScanner;