import React, { useState } from 'react';
import { Bug, Send, AlertTriangle, Zap } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useAlert } from '../contexts/AlertContext';
import { createBugAlert } from '../utils/alertUtils';
import { BugReport } from '../types';

interface ReportBugProps {
  onNavigate: (page: string) => void;
}

const ReportBug: React.FC<ReportBugProps> = ({ onNavigate }) => {
  const { user } = useAuth();
  const { addAlert } = useAlert();
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    url: '',
    file: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Create bug report
    const bugReport: BugReport = {
      id: Date.now().toString(),
      userId: user?.id || '',
      userEmail: user?.email || '',
      title: formData.title,
      description: formData.description,
      url: formData.url || undefined,
      file: formData.file || undefined,
      timestamp: new Date(),
      status: 'open'
    };

    // 🚨 AUTO ALERT SYSTEM: Trigger alert for new bug reports
    const alertData = createBugAlert(
      bugReport.userEmail,
      bugReport.title,
      bugReport.id
    );
    addAlert(alertData);

    // In real app, this would be sent to the server
    console.log('Bug report submitted:', bugReport);

    setIsSubmitting(false);
    setSubmitted(true);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  if (submitted) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(34,197,94,0.1),transparent)] pointer-events-none" />
        
        <div className="relative max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <div className="bg-gray-900/50 backdrop-blur-xl border border-green-500/30 rounded-2xl p-8 text-center">
            <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
              <Bug className="w-8 h-8 text-green-400" />
            </div>
            
            <h1 className="text-3xl font-bold text-white mb-4">Bug Report Submitted! ✅</h1>
            <p className="text-gray-300 text-lg mb-8">
              Thank you for helping improve CyberIntel. Our security team will review your report and respond soon.
            </p>
            
            <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 mb-6">
              <p className="text-green-400 font-medium">Report ID: #{Date.now().toString().slice(-6)}</p>
              <p className="text-gray-400 text-sm mt-1">Save this ID for tracking your report status</p>
            </div>

            <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4 mb-8">
              <p className="text-blue-400 text-sm font-medium">
                🚨 AUTOMATIC ALERT: Officers have been notified
              </p>
              <p className="text-blue-300 text-xs mt-1">
                📧 Email alert sent to vanursab18@gmail.com and security team
              </p>
            </div>

            <div className="flex space-x-4 justify-center">
              <button
                onClick={() => onNavigate('dashboard')}
                className="px-6 py-3 bg-gradient-to-r from-green-500 to-blue-600 text-white rounded-lg font-medium hover:from-green-600 hover:to-blue-700 transition-all duration-200"
              >
                Back to Dashboard
              </button>
              <button
                onClick={() => {
                  setSubmitted(false);
                  setFormData({ title: '', description: '', url: '', file: '' });
                }}
                className="px-6 py-3 bg-gray-700/50 hover:bg-gray-600/50 text-gray-300 rounded-lg font-medium transition-colors"
              >
                Report Another Bug
              </button>
            </div>
          </div>

         
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_30%,rgba(239,68,68,0.1),transparent)] pointer-events-none" />
      
      <div className="relative max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex justify-center mb-4">
            <div className="relative">
              <Bug className="w-16 h-16 text-red-400" />
              <div className="absolute inset-0 animate-pulse">
                <Bug className="w-16 h-16 text-red-400/30" />
              </div>
            </div>
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-red-400 to-orange-500 bg-clip-text text-transparent mb-4">
            Report a Security Bug
          </h1>
          <p className="text-gray-300 text-lg max-w-xl mx-auto">
            Help us improve CyberIntel by reporting security issues, bugs, or vulnerabilities you've discovered.
          </p>
        </div>

        {/* Alert */}
        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-6 mb-8">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-6 h-6 text-yellow-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-yellow-400 font-bold mb-2">Security Disclosure Policy</h3>
              <p className="text-gray-300 text-sm leading-relaxed">
                If you've discovered a critical security vulnerability, please report it responsibly. 
                Our security team will investigate and respond within 48 hours. Do not publicly 
                disclose the vulnerability until we've had a chance to address it.
              </p>
            </div>
          </div>
        </div>

        {/* Auto Alert Info */}
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-6 mb-8">
          <div className="flex items-start space-x-3">
            <Send className="w-6 h-6 text-blue-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-blue-400 font-bold mb-2">🚨 Automatic Alert System</h3>
              <p className="text-gray-300 text-sm leading-relaxed">
                When you submit a bug report, our officers are automatically notified via email to 
                <span className="text-blue-400 font-medium"> vanursab18@gmail.com</span> and the security team. 
                You'll receive a confirmation and tracking ID to monitor the status of your report.
              </p>
            </div>
          </div>
        </div>

        {/* Form */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="title" className="block text-sm font-medium text-gray-300 mb-2">
                Problem Title *
              </label>
              <input
                type="text"
                id="title"
                name="title"
                value={formData.title}
                onChange={handleChange}
                className="w-full px-4 py-3 bg-black/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-red-500 transition-all duration-200"
                placeholder="Brief description of the issue"
                required
              />
            </div>

            <div>
              <label htmlFor="description" className="block text-sm font-medium text-gray-300 mb-2">
                Detailed Description *
              </label>
              <textarea
                id="description"
                name="description"
                value={formData.description}
                onChange={handleChange}
                rows={6}
                className="w-full px-4 py-3 bg-black/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-red-500 transition-all duration-200 resize-none"
                placeholder="Provide detailed steps to reproduce the issue, expected vs actual behavior, and any error messages you encountered..."
                required
              />
            </div>

            <div>
              <label htmlFor="url" className="block text-sm font-medium text-gray-300 mb-2">
                Related URL (Optional)
              </label>
              <input
                type="url"
                id="url"
                name="url"
                value={formData.url}
                onChange={handleChange}
                className="w-full px-4 py-3 bg-black/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-red-500 transition-all duration-200"
                placeholder="https://example.com (if the bug is related to a specific URL)"
              />
            </div>

            <div>
              <label htmlFor="file" className="block text-sm font-medium text-gray-300 mb-2">
                Related File (Optional)
              </label>
              <input
                type="text"
                id="file"
                name="file"
                value={formData.file}
                onChange={handleChange}
                className="w-full px-4 py-3 bg-black/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-red-500 transition-all duration-200"
                placeholder="File name or type (if the bug is related to file analysis)"
              />
            </div>

            <div className="bg-gray-800/50 border border-gray-600/50 rounded-lg p-4">
              <h3 className="text-white font-medium mb-2">What happens next?</h3>
              <ul className="text-gray-400 text-sm space-y-1">
                <li>• 🚨 Officers are automatically alerted via email</li>
                <li>• Your report will be reviewed by our security team</li>
                <li>• We'll investigate and reproduce the issue</li>
                <li>• You'll receive updates on the resolution progress</li>
                <li>• Critical issues are prioritized and fixed immediately</li>
              </ul>
            </div>

            <button
              type="submit"
              disabled={isSubmitting || !formData.title || !formData.description}
              className="w-full bg-gradient-to-r from-red-500 to-orange-600 text-white py-4 px-6 rounded-xl font-medium hover:from-red-600 hover:to-orange-700 focus:outline-none focus:ring-2 focus:ring-red-500/50 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center justify-center space-x-2"
            >
              {isSubmitting ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent" />
                  <span>Submitting Report...</span>
                </>
              ) : (
                <>
                  <Send className="w-5 h-5" />
                  <span>Submit Bug Report</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Quick Actions */}
        <div className="mt-8 grid md:grid-cols-2 gap-6">
          <button
            onClick={() => onNavigate('dashboard')}
            className="bg-gradient-to-r from-gray-700/20 to-gray-800/20 hover:from-gray-700/30 hover:to-gray-800/30 border border-gray-600/30 rounded-xl p-6 text-left transition-all duration-300 hover:scale-105"
          >
            <h3 className="text-lg font-bold text-white mb-2">Back to Dashboard</h3>
            <p className="text-gray-300">Return to your security command center</p>
          </button>
          
          <button
            onClick={() => onNavigate('about')}
            className="bg-gradient-to-r from-blue-500/20 to-blue-600/20 hover:from-blue-500/30 hover:to-blue-600/30 border border-blue-500/30 rounded-xl p-6 text-left transition-all duration-300 hover:scale-105"
          >
            <h3 className="text-lg font-bold text-white mb-2">Learn More</h3>
            <p className="text-gray-300">About CyberIntel security features</p>
          </button>
        </div>

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

export default ReportBug;