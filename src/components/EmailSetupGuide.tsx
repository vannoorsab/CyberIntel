import React, { useState, useEffect } from 'react';
import { Mail, ExternalLink, Copy, CheckCircle, AlertTriangle, Settings, XCircle, Info, RefreshCw } from 'lucide-react';
import { emailService } from '../utils/emailService';

interface EmailSetupGuideProps {
  isOpen: boolean;
  onClose: () => void;
}

const EmailSetupGuide: React.FC<EmailSetupGuideProps> = ({ isOpen, onClose }) => {
  const [testEmailSent, setTestEmailSent] = useState(false);
  const [isTestingEmail, setIsTestingEmail] = useState(false);
  const [testEmailError, setTestEmailError] = useState<string | null>(null);
  const [isConfigured, setIsConfigured] = useState(false);
  const [configuration, setConfiguration] = useState<any>(null);

  useEffect(() => {
    setIsConfigured(emailService.isConfigured());
    setConfiguration(emailService.getConfiguration());
  }, []);

  const handleTestEmail = async () => {
    setIsTestingEmail(true);
    setTestEmailError(null);
    setTestEmailSent(false);
    
    try {
      const success = await emailService.sendTestEmail();
      if (success) {
        setTestEmailSent(true);
        setIsConfigured(true);
      } else {
        const configError = emailService.getConfigurationError();
        setTestEmailError(configError || 'Email service not properly configured');
        setIsConfigured(false);
      }
    } catch (error) {
      console.error('Test email failed:', error);
      setTestEmailError('Failed to send test email. Please check your EmailJS configuration.');
      setIsConfigured(false);
    } finally {
      setIsTestingEmail(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const isGmailAuthError = testEmailError && (
    testEmailError.includes('Gmail account needs to be reconnected') ||
    testEmailError.includes('Gmail authentication expired') ||
    testEmailError.includes('Invalid grant') ||
    testEmailError.includes('broader permissions') ||
    testEmailError.includes('insufficient authentication scopes')
  );

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900/95 backdrop-blur-xl border border-gray-700/50 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700/50">
          <div className="flex items-center space-x-3">
            <Mail className="w-6 h-6 text-blue-400" />
            <h2 className="text-xl font-bold text-white">📧 EmailJS Setup for vanursab71@gmail.com</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            ✕
          </button>
        </div>

        <div className="p-6 space-y-8">
          {/* Gmail Reconnection Alert - Show if Gmail auth error */}
          {isGmailAuthError && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6">
              <div className="flex items-start space-x-3">
                <RefreshCw className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-red-400 font-bold mb-2">🚨 Gmail Reconnection Required</h3>
                  <p className="text-gray-300 text-sm leading-relaxed mb-4">
                    Your Gmail account connection has expired or needs broader permissions. This is a common security feature where Gmail 
                    periodically requires re-authorization with proper permissions. You need to reconnect your Gmail account in the EmailJS dashboard.
                  </p>
                  <div className="bg-black/30 rounded-lg p-4 mb-4">
                    <p className="text-red-400 font-medium mb-2">🔧 Quick Fix Steps:</p>
                    <ol className="text-gray-300 text-sm space-y-1 list-decimal list-inside">
                      <li>Go to your EmailJS dashboard (link below)</li>
                      <li>Find your Gmail service "service_cyberintel"</li>
                      <li>Click "Reconnect" or "Re-authorize"</li>
                      <li>Sign in with vanursab71@gmail.com again</li>
                      <li><strong>Grant ALL permissions including email sending</strong></li>
                      <li>Save the service and test again</li>
                    </ol>
                  </div>
                  <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3 mb-4">
                    <p className="text-yellow-400 text-sm font-medium">⚠️ IMPORTANT: Make sure to grant full Gmail API access!</p>
                    <p className="text-gray-400 text-xs mt-1">
                      The error "insufficient authentication scopes" means Gmail needs broader permissions to send emails.
                    </p>
                  </div>
                  <a
                    href="https://dashboard.emailjs.com/admin/integration"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center space-x-2 px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-lg transition-colors"
                  >
                    <RefreshCw className="w-4 h-4" />
                    <span>Reconnect Gmail Account</span>
                  </a>
                </div>
              </div>
            </div>
          )}

          {/* Account Info */}
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-6">
            <div className="flex items-start space-x-3">
              <Info className="w-6 h-6 text-blue-400 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-blue-400 font-bold mb-2">📧 Your EmailJS Account</h3>
                <p className="text-gray-300 text-sm leading-relaxed mb-3">
                  You're logged into EmailJS with <span className="text-blue-400 font-medium">vanursab71@gmail.com</span>.
                  The system is configured to send alerts to this email address.
                </p>
                {configuration && (
                  <div className="bg-black/30 rounded-lg p-4">
                    <p className="text-gray-400 text-sm mb-2">Current Configuration:</p>
                    <ul className="text-gray-300 text-sm space-y-1">
                      <li>• Account: <span className="text-blue-400">vanursab71@gmail.com</span></li>
                      <li>• Public Key: <span className="text-yellow-400 font-mono">{configuration.publicKey}</span></li>
                      <li>• Service ID: <span className="text-green-400 font-mono">{configuration.serviceId}</span></li>
                      <li>• Status: <span className={isConfigured ? 'text-green-400' : 'text-red-400'}>
                        {isConfigured ? 'Configured' : 'Needs Setup'}
                      </span></li>
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Current Status */}
          <div className={`border rounded-xl p-6 ${
            isConfigured 
              ? 'bg-green-500/10 border-green-500/20' 
              : isGmailAuthError
              ? 'bg-red-500/10 border-red-500/20'
              : 'bg-yellow-500/10 border-yellow-500/20'
          }`}>
            <div className="flex items-start space-x-3">
              {isConfigured ? (
                <CheckCircle className="w-6 h-6 text-green-400 flex-shrink-0 mt-0.5" />
              ) : isGmailAuthError ? (
                <XCircle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
              ) : (
                <AlertTriangle className="w-6 h-6 text-yellow-400 flex-shrink-0 mt-0.5" />
              )}
              <div>
                <h3 className={`font-bold mb-2 ${
                  isConfigured ? 'text-green-400' : isGmailAuthError ? 'text-red-400' : 'text-yellow-400'
                }`}>
                  {isConfigured ? '✅ Email Service Ready' : isGmailAuthError ? '🚨 Gmail Reconnection Required' : '⚠️ Setup Required'}
                </h3>
                <p className="text-gray-300 text-sm leading-relaxed">
                  {isConfigured ? (
                    <>
                      Email notifications are active and will be sent to 
                      <span className="text-blue-400 font-medium"> vanursab71@gmail.com</span>.
                      Test the service below to confirm everything is working.
                    </>
                  ) : isGmailAuthError ? (
                    <>
                      Your Gmail account connection has expired or needs broader permissions. 
                      This is a normal security measure. Click the reconnection link above to fix this quickly.
                      <strong> Make sure to grant full Gmail API access when reconnecting!</strong>
                    </>
                  ) : (
                    <>
                      You need to create the EmailJS service and templates in your dashboard. 
                      Follow the steps below to complete the setup for 
                      <span className="text-blue-400 font-medium"> vanursab71@gmail.com</span>.
                    </>
                  )}
                </p>
              </div>
            </div>
          </div>

          {/* Test Email Section */}
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-6">
            <h3 className="text-blue-400 font-bold mb-4">🧪 Test Email Service</h3>
            <p className="text-gray-300 mb-4">
              Send a test email to vanursab71@gmail.com to verify the configuration.
            </p>
            
            <div className="flex items-center space-x-4 mb-4">
              <button
                onClick={handleTestEmail}
                disabled={isTestingEmail}
                className="px-6 py-3 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition-colors flex items-center space-x-2 disabled:opacity-50"
              >
                {isTestingEmail ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-2 border-blue-400 border-t-transparent" />
                    <span>Testing Email Service...</span>
                  </>
                ) : (
                  <>
                    <Mail className="w-4 h-4" />
                    <span>Send Test Email</span>
                  </>
                )}
              </button>

              {testEmailSent && (
                <div className="flex items-center space-x-2 text-green-400">
                  <CheckCircle className="w-5 h-5" />
                  <span>Test email sent to vanursab71@gmail.com!</span>
                </div>
              )}

              {testEmailError && (
                <div className="flex items-center space-x-2 text-red-400">
                  <XCircle className="w-5 h-5" />
                  <span>Error: {testEmailError}</span>
                </div>
              )}
            </div>

            {!isConfigured && !isGmailAuthError && (
              <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
                <p className="text-yellow-400 text-sm">
                  ⚠️ Email service not configured. Test emails will be logged locally.
                  Complete the setup steps below to enable real email delivery to vanursab71@gmail.com.
                </p>
              </div>
            )}
          </div>

          {/* Step-by-Step Setup */}
          <div className="space-y-6">
            <h3 className="text-xl font-bold text-white mb-4">🔧 Setup Instructions for vanursab71@gmail.com</h3>

            {/* Step 1 */}
            <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6">
              <div className="flex items-start space-x-4">
                <div className="bg-blue-500/20 rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0">
                  <span className="text-blue-400 font-bold">1</span>
                </div>
                <div className="flex-1">
                  <h4 className="text-white font-bold mb-2">Access Your EmailJS Dashboard</h4>
                  <p className="text-gray-300 mb-3">
                    You're already logged in with vanursab71@gmail.com. Go to your EmailJS dashboard.
                  </p>
                  <a
                    href="https://dashboard.emailjs.com/admin/integration"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition-colors"
                  >
                    <ExternalLink className="w-4 h-4" />
                    <span>Go to EmailJS Dashboard</span>
                  </a>
                </div>
              </div>
            </div>

            {/* Step 2 */}
            <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6">
              <div className="flex items-start space-x-4">
                <div className="bg-green-500/20 rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0">
                  <span className="text-green-400 font-bold">2</span>
                </div>
                <div className="flex-1">
                  <h4 className="text-white font-bold mb-2">Create Gmail Service</h4>
                  <p className="text-gray-300 mb-3">Create a new email service connected to your Gmail account.</p>
                  <div className="bg-black/30 rounded-lg p-4">
                    <p className="text-gray-400 text-sm mb-2">Service Configuration:</p>
                    <ul className="text-gray-300 text-sm space-y-1">
                      <li>• Service Type: <span className="text-blue-400">Gmail</span></li>
                      <li>• Your Email: <span className="text-blue-400">vanursab71@gmail.com</span></li>
                      <li>• Service ID: <span className="text-yellow-400 font-mono">service_cyberintel</span>
                        <button
                          onClick={() => copyToClipboard('service_cyberintel')}
                          className="ml-2 text-gray-400 hover:text-white"
                        >
                          <Copy className="w-3 h-3 inline" />
                        </button>
                      </li>
                    </ul>
                    <div className="mt-3 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <p className="text-red-400 text-sm font-medium">⚠️ CRITICAL: Service ID must be exactly "service_cyberintel"</p>
                      <p className="text-gray-400 text-xs mt-1">This is the ID currently configured in the application.</p>
                    </div>
                    <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                      <p className="text-yellow-400 text-sm font-medium">🔑 IMPORTANT: Grant Full Gmail API Access</p>
                      <p className="text-gray-400 text-xs mt-1">Make sure to allow all permissions when connecting Gmail, especially email sending permissions.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Step 3 */}
            <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6">
              <div className="flex items-start space-x-4">
                <div className="bg-purple-500/20 rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0">
                  <span className="text-purple-400 font-bold">3</span>
                </div>
                <div className="flex-1">
                  <h4 className="text-white font-bold mb-2">Create Email Templates</h4>
                  <p className="text-gray-300 mb-3">Create two templates for threat alerts and bug reports.</p>
                  
                  <div className="space-y-4">
                    <div className="bg-black/30 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-red-400 font-medium">🚨 Threat Alert Template</p>
                        <button
                          onClick={() => copyToClipboard('template_threat_alert')}
                          className="text-gray-400 hover:text-white"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                      </div>
                      <p className="text-gray-400 text-sm">Template ID: <span className="font-mono">template_threat_alert</span></p>
                    </div>

                    <div className="bg-black/30 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-purple-400 font-medium">🛠️ Bug Report Template</p>
                        <button
                          onClick={() => copyToClipboard('template_bug_report')}
                          className="text-gray-400 hover:text-white"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                      </div>
                      <p className="text-gray-400 text-sm">Template ID: <span className="font-mono">template_bug_report</span></p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Step 4 */}
            <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6">
              <div className="flex items-start space-x-4">
                <div className="bg-orange-500/20 rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0">
                  <span className="text-orange-400 font-bold">4</span>
                </div>
                <div className="flex-1">
                  <h4 className="text-white font-bold mb-2">Template Variables</h4>
                  <p className="text-gray-300 mb-3">Use these variables in your email templates:</p>
                  
                  <div className="bg-black/30 rounded-lg p-4">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <p className="text-blue-400 font-medium mb-2">Required Variables:</p>
                        <ul className="text-gray-300 space-y-1">
                          <li>• {`{{to_email}}`} - Recipient email</li>
                          <li>• {`{{to_name}}`} - Recipient name</li>
                          <li>• {`{{subject}}`} - Email subject</li>
                          <li>• {`{{message}}`} - Email content</li>
                        </ul>
                      </div>
                      <div>
                        <p className="text-green-400 font-medium mb-2">Optional Variables:</p>
                        <ul className="text-gray-300 space-y-1">
                          <li>• {`{{from_name}}`} - Sender name</li>
                          <li>• {`{{reply_to}}`} - Reply address</li>
                          <li>• {`{{timestamp}}`} - Alert time</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Step 5 */}
            <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6">
              <div className="flex items-start space-x-4">
                <div className="bg-red-500/20 rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0">
                  <span className="text-red-400 font-bold">5</span>
                </div>
                <div className="flex-1">
                  <h4 className="text-white font-bold mb-2">Verify Public Key</h4>
                  <p className="text-gray-300 mb-3">Confirm your EmailJS public key matches the configuration.</p>
                  
                  <div className="bg-black/30 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <p className="text-gray-400 text-sm">Current Public Key:</p>
                      <button
                        onClick={() => copyToClipboard('7XbpiUgcJ2P9CtJ_N')}
                        className="text-gray-400 hover:text-white"
                      >
                        <Copy className="w-4 h-4" />
                      </button>
                    </div>
                    <p className="text-yellow-400 font-mono text-sm">7XbpiUgcJ2P9CtJ_N</p>
                    <div className="mt-3 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                      <p className="text-blue-400 text-sm">
                        📋 Go to EmailJS Dashboard → Account → General → Public Key
                      </p>
                      <p className="text-gray-400 text-xs mt-1">
                        Verify this key matches your account. If different, update the configuration.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Links */}
          <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-6">
            <h3 className="text-green-400 font-bold mb-4">🔗 Quick Links for Setup</h3>
            <div className="grid md:grid-cols-2 gap-4">
              <a
                href="https://dashboard.emailjs.com/admin/integration"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center space-x-2 px-4 py-3 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
                <span>Email Services</span>
              </a>
              <a
                href="https://dashboard.emailjs.com/admin/templates"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center space-x-2 px-4 py-3 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 rounded-lg transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
                <span>Email Templates</span>
              </a>
              <a
                href="https://dashboard.emailjs.com/admin/account"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center space-x-2 px-4 py-3 bg-orange-500/20 hover:bg-orange-500/30 text-orange-400 rounded-lg transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
                <span>Account Settings</span>
              </a>
              <a
                href="https://www.emailjs.com/docs/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center space-x-2 px-4 py-3 bg-gray-600/20 hover:bg-gray-600/30 text-gray-400 rounded-lg transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
                <span>Documentation</span>
              </a>
            </div>
          </div>

          {/* Benefits */}
          <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-6">
            <h3 className="text-green-400 font-bold mb-4">✅ Benefits of Real Email Alerts</h3>
            <div className="grid md:grid-cols-2 gap-4">
              <ul className="text-gray-300 space-y-2">
                <li>• 📧 Instant notifications to vanursab71@gmail.com</li>
                <li>• 🚨 Real-time threat alerts</li>
                <li>• 🛠️ Bug report notifications</li>
                <li>• 📱 Mobile email notifications</li>
              </ul>
              <ul className="text-gray-300 space-y-2">
                <li>• 🔒 Secure email delivery</li>
                <li>• 📊 Email delivery tracking</li>
                <li>• 🎯 Professional alert formatting</li>
                <li>• 🔄 Automatic retry on failure</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EmailSetupGuide;