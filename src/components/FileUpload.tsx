import React, { useState, useRef } from 'react';
import { Upload, File, Search, Shield, AlertTriangle, Ban, Copy, Zap } from 'lucide-react';
import { analyzeFile } from '../utils/mockAI';
import { ScanResult } from '../types';
import { useAlert } from '../contexts/AlertContext';
import { createThreatAlert } from '../utils/alertUtils';

interface FileUploadProps {
  onNavigate: (page: string) => void;
}

const FileUpload: React.FC<FileUploadProps> = ({ onNavigate }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { addAlert } = useAlert();

  const handleFileSelect = (file: File) => {
    const maxSize = 100 * 1024 * 1024; // 100MB limit
    
    if (file.size > maxSize) {
      setError('File size must be less than 100MB');
      return;
    }

    setSelectedFile(file);
    setError('');
    setResult(null);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      handleFileSelect(files[0]);
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
      handleFileSelect(files[0]);
    }
  };

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setError('Please select a file to analyze');
      return;
    }

    setIsAnalyzing(true);
    setError('');
    setResult(null);

    try {
      const scanResult = await analyzeFile(selectedFile.name, selectedFile.type);
      setResult(scanResult);

      // 🚨 AUTO ALERT SYSTEM: Trigger alert for high-risk file scans
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
      setError('Analysis failed. Please try again.');
    } finally {
      setIsAnalyzing(false);
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
        description: 'This file appears to be safe'
      },
      suspicious: {
        icon: AlertTriangle,
        color: 'text-yellow-400',
        bg: 'bg-yellow-500/20',
        border: 'border-yellow-500/30',
        label: '⚠️ Suspicious',
        description: 'Exercise caution with this file'
      },
      dangerous: {
        icon: Ban,
        color: 'text-red-400',
        bg: 'bg-red-500/20',
        border: 'border-red-500/30',
        label: '🚫 Dangerous',
        description: 'This file contains malware or threats'
      }
    };

    return riskConfig[result.riskLevel];
  };

  const riskDisplay = getRiskDisplay();

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_70%,rgba(168,85,247,0.1),transparent)] pointer-events-none" />
      
      <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex justify-center mb-4">
            <div className="relative">
              <Upload className="w-16 h-16 text-purple-400" />
              <div className="absolute inset-0 animate-pulse">
                <Upload className="w-16 h-16 text-purple-400/30" />
              </div>
            </div>
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-purple-400 to-green-500 bg-clip-text text-transparent mb-4">
            File Security Analyzer
          </h1>
          <p className="text-gray-300 text-lg max-w-2xl mx-auto">
            Upload suspicious files to analyze them for malware, ransomware, and other security threats before execution.
          </p>
        </div>

        {/* File Upload Area */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8 mb-8">
          <div
            className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all duration-300 ${
              dragOver
                ? 'border-purple-500 bg-purple-500/10'
                : selectedFile
                ? 'border-green-500 bg-green-500/10'
                : 'border-gray-600 hover:border-purple-500/50 hover:bg-purple-500/5'
            }`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            {selectedFile ? (
              <div className="space-y-4">
                <File className="w-16 h-16 text-green-400 mx-auto" />
                <div>
                  <h3 className="text-xl font-bold text-white mb-2">{selectedFile.name}</h3>
                  <p className="text-gray-400 mb-1">
                    Type: {selectedFile.type || 'Unknown'} • Size: {formatFileSize(selectedFile.size)}
                  </p>
                  <p className="text-green-400 text-sm">✅ File selected and ready for analysis</p>
                </div>
                <button
                  onClick={() => {
                    setSelectedFile(null);
                    setResult(null);
                    setError('');
                  }}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  Select a different file
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                <Upload className="w-16 h-16 text-gray-400 mx-auto" />
                <div>
                  <h3 className="text-xl font-bold text-white mb-2">Drop your file here</h3>
                  <p className="text-gray-400 mb-4">
                    or click to browse (Max size: 100MB)
                  </p>
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="px-6 py-3 bg-gradient-to-r from-purple-500 to-purple-600 text-white rounded-lg font-medium hover:from-purple-600 hover:to-purple-700 transition-all duration-200"
                  >
                    Browse Files
                  </button>
                </div>
                <p className="text-gray-500 text-sm">
                  Supported formats: .exe, .apk, .pdf, .zip, .rar, .doc, .docx, and more
                </p>
              </div>
            )}
          </div>

          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileInputChange}
            className="hidden"
            accept=".exe,.apk,.pdf,.zip,.rar,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.jpg,.png,.gif,.mp4,.avi,.mp3,.wav"
          />

          {error && (
            <div className="mt-4 bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
              {error}
            </div>
          )}

          {selectedFile && (
            <div className="mt-6 text-center">
              <button
                onClick={handleAnalyze}
                disabled={isAnalyzing}
                className="px-8 py-4 bg-gradient-to-r from-purple-500 to-green-600 text-white rounded-xl font-medium hover:from-purple-600 hover:to-green-700 focus:outline-none focus:ring-2 focus:ring-purple-500/50 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center space-x-2 mx-auto"
              >
                {isAnalyzing ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-5 h-5" />
                    <span>Analyze File</span>
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
                        📧 Email alert sent to vanursab18@gmail.com and security team
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Detailed Report */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white">File Analysis Report</h3>
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
                <span>File: {result.target}</span>
                <span>Analysis completed at {result.timestamp.toLocaleTimeString()}</span>
              </div>
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="mt-12 grid md:grid-cols-2 gap-6">
          <button
            onClick={() => onNavigate('url-scanner')}
            className="bg-gradient-to-r from-green-500/20 to-green-600/20 hover:from-green-500/30 hover:to-green-600/30 border border-green-500/30 rounded-xl p-6 text-left transition-all duration-300 hover:scale-105"
          >
            <h3 className="text-lg font-bold text-white mb-2">Scan a URL Next</h3>
            <p className="text-gray-300">Analyze suspicious links for threats</p>
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

export default FileUpload;