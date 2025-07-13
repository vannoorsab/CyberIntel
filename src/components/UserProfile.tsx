import React, { useState } from 'react';
import { X, User, Mail, Phone, Building, Shield, Key, LogOut, Save, Camera, Clock, Laptop, MapPin, AlertTriangle, CheckCircle, RefreshCw, Zap } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { User as UserType, UserSession, UserActivity } from '../types';

interface UserProfileProps {
  isOpen: boolean;
  onClose: () => void;
}

const UserProfile: React.FC<UserProfileProps> = ({ isOpen, onClose }) => {
  const { user, logout, updateProfile, changePassword } = useAuth();
  const [activeTab, setActiveTab] = useState('profile');
  const [editMode, setEditMode] = useState(false);
  const [profileData, setProfileData] = useState<Partial<UserType>>({
    fullName: user?.fullName || '',
    email: user?.email || '',
    department: user?.department || 'Security',
    phone: user?.phone || '',
  });
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  // Mock data for sessions and activity
  const mockSessions: UserSession[] = [
    {
      id: '1',
      deviceType: 'Desktop',
      browser: 'Chrome',
      operatingSystem: 'Windows 10',
      ipAddress: '192.168.1.1',
      location: 'New York, USA',
      lastActive: new Date(),
      isCurrentSession: true,
    },
    {
      id: '2',
      deviceType: 'Mobile',
      browser: 'Safari',
      operatingSystem: 'iOS 15',
      ipAddress: '192.168.1.2',
      location: 'Los Angeles, USA',
      lastActive: new Date(Date.now() - 86400000), // 1 day ago
      isCurrentSession: false,
    },
  ];

  const mockActivity: UserActivity[] = [
    {
      id: '1',
      action: 'Login',
      timestamp: new Date(),
      ipAddress: '192.168.1.1',
      deviceInfo: 'Chrome on Windows',
      details: 'Successful login',
    },
    {
      id: '2',
      action: 'URL Scan',
      timestamp: new Date(Date.now() - 3600000), // 1 hour ago
      ipAddress: '192.168.1.1',
      deviceInfo: 'Chrome on Windows',
      details: 'Scanned URL: example.com',
    },
    {
      id: '3',
      action: 'File Analysis',
      timestamp: new Date(Date.now() - 7200000), // 2 hours ago
      ipAddress: '192.168.1.1',
      deviceInfo: 'Chrome on Windows',
      details: 'Analyzed file: document.pdf',
    },
  ];

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setProfileData(prev => ({ ...prev, [name]: value }));
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setPasswordData(prev => ({ ...prev, [name]: value }));
  };

  const handleSaveProfile = async () => {
    setIsLoading(true);
    try {
      const success = await updateProfile(profileData);
      if (success) {
        setEditMode(false);
      }
    } catch (error) {
      console.error('Failed to update profile:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleChangePassword = async () => {
    setPasswordError('');
    setPasswordSuccess('');
    
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setPasswordError('New passwords do not match');
      return;
    }
    
    if (passwordData.newPassword.length < 6) {
      setPasswordError('Password must be at least 6 characters long');
      return;
    }
    
    setIsLoading(true);
    try {
      const success = await changePassword(passwordData.currentPassword, passwordData.newPassword);
      if (success) {
        setPasswordSuccess('Password changed successfully');
        setPasswordData({
          currentPassword: '',
          newPassword: '',
          confirmPassword: '',
        });
      } else {
        setPasswordError('Current password is incorrect');
      }
    } catch (error) {
      setPasswordError('Failed to change password');
      console.error('Failed to change password:', error);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen || !user) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="cyber-card w-full max-w-4xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-cyber-primary/30 bg-gradient-to-r from-cyber-dark to-black">
          <div className="flex items-center space-x-3">
            <div className="relative">
              <User className="w-8 h-8 text-cyber-primary" />
              <div className="absolute inset-0 animate-cyber-pulse">
                <User className="w-8 h-8 text-cyber-primary/30" />
              </div>
            </div>
            <h2 className="text-xl font-bold text-cyber-primary font-cyber">USER PROFILE</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-cyber-primary transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Content */}
        <div className="flex flex-col md:flex-row h-full">
          {/* Sidebar */}
          <div className="w-full md:w-64 border-r border-cyber-primary/20 bg-black/50">
            <div className="p-6 text-center border-b border-cyber-primary/20">
              <div className="relative w-24 h-24 mx-auto mb-4 rounded-full bg-gray-800 flex items-center justify-center overflow-hidden border-2 border-cyber-primary/50">
                {user.profilePicture ? (
                  <img 
                    src={user.profilePicture} 
                    alt={user.fullName} 
                    className="w-full h-full object-cover"
                  />
                ) : (
                  <User className="w-12 h-12 text-cyber-primary" />
                )}
                <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black/50"></div>
                <button className="absolute bottom-1 right-1 p-1 bg-cyber-primary/20 rounded-full text-cyber-primary hover:bg-cyber-primary/30 transition-colors">
                  <Camera className="w-4 h-4" />
                </button>
              </div>
              <h3 className="text-lg font-bold text-white mb-1 font-cyber">{user.fullName}</h3>
              <p className="text-cyber-primary text-sm">{user.role || 'Security Analyst'}</p>
            </div>

            <div className="p-4">
              <nav className="space-y-2">
                <button
                  onClick={() => setActiveTab('profile')}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-all duration-200 ${
                    activeTab === 'profile'
                      ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/30'
                      : 'text-gray-300 hover:text-white hover:bg-gray-700/30'
                  }`}
                >
                  <User className="w-5 h-5" />
                  <span>Profile</span>
                </button>
                <button
                  onClick={() => setActiveTab('security')}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-all duration-200 ${
                    activeTab === 'security'
                      ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/30'
                      : 'text-gray-300 hover:text-white hover:bg-gray-700/30'
                  }`}
                >
                  <Key className="w-5 h-5" />
                  <span>Security</span>
                </button>
                <button
                  onClick={() => setActiveTab('sessions')}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-all duration-200 ${
                    activeTab === 'sessions'
                      ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/30'
                      : 'text-gray-300 hover:text-white hover:bg-gray-700/30'
                  }`}
                >
                  <Laptop className="w-5 h-5" />
                  <span>Sessions</span>
                </button>
                <button
                  onClick={() => setActiveTab('activity')}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-all duration-200 ${
                    activeTab === 'activity'
                      ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/30'
                      : 'text-gray-300 hover:text-white hover:bg-gray-700/30'
                  }`}
                >
                  <Clock className="w-5 h-5" />
                  <span>Activity</span>
                </button>
              </nav>

              <div className="mt-8 pt-8 border-t border-gray-700/50">
                <button
                  onClick={logout}
                  className="w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-all duration-200 bg-cyber-danger/10 text-cyber-danger hover:bg-cyber-danger/20"
                >
                  <LogOut className="w-5 h-5" />
                  <span>Logout</span>
                </button>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1 overflow-y-auto p-6 bg-gradient-to-br from-black via-cyber-dark to-black">
            {/* Profile Tab */}
            {activeTab === 'profile' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-xl font-bold text-white font-cyber">PROFILE INFORMATION</h3>
                  {!editMode ? (
                    <button
                      onClick={() => setEditMode(true)}
                      className="cyber-button px-4 py-2 rounded-lg text-sm"
                    >
                      Edit Profile
                    </button>
                  ) : (
                    <button
                      onClick={handleSaveProfile}
                      disabled={isLoading}
                      className="cyber-button px-4 py-2 rounded-lg text-sm flex items-center space-x-2"
                    >
                      {isLoading ? (
                        <>
                          <div className="cyber-loading" />
                          <span>Saving...</span>
                        </>
                      ) : (
                        <>
                          <Save className="w-4 h-4" />
                          <span>Save Changes</span>
                        </>
                      )}
                    </button>
                  )}
                </div>

                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label htmlFor="fullName" className="block text-sm font-medium text-gray-300 mb-2">
                        Full Name
                      </label>
                      {editMode ? (
                        <input
                          type="text"
                          id="fullName"
                          name="fullName"
                          value={profileData.fullName}
                          onChange={handleInputChange}
                          className="w-full px-4 py-3 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                        />
                      ) : (
                        <div className="flex items-center space-x-3 px-4 py-3 bg-black/30 border border-gray-700/50 rounded-lg">
                          <User className="w-5 h-5 text-cyber-primary" />
                          <span className="text-white">{user.fullName}</span>
                        </div>
                      )}
                    </div>

                    <div>
                      <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2">
                        Email Address
                      </label>
                      {editMode ? (
                        <input
                          type="email"
                          id="email"
                          name="email"
                          value={profileData.email}
                          onChange={handleInputChange}
                          className="w-full px-4 py-3 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                          disabled
                        />
                      ) : (
                        <div className="flex items-center space-x-3 px-4 py-3 bg-black/30 border border-gray-700/50 rounded-lg">
                          <Mail className="w-5 h-5 text-cyber-primary" />
                          <span className="text-white">{user.email}</span>
                        </div>
                      )}
                    </div>

                    <div>
                      <label htmlFor="department" className="block text-sm font-medium text-gray-300 mb-2">
                        Department
                      </label>
                      {editMode ? (
                        <input
                          type="text"
                          id="department"
                          name="department"
                          value={profileData.department}
                          onChange={handleInputChange}
                          className="w-full px-4 py-3 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                        />
                      ) : (
                        <div className="flex items-center space-x-3 px-4 py-3 bg-black/30 border border-gray-700/50 rounded-lg">
                          <Building className="w-5 h-5 text-cyber-primary" />
                          <span className="text-white">{user.department || 'Security'}</span>
                        </div>
                      )}
                    </div>

                    <div>
                      <label htmlFor="phone" className="block text-sm font-medium text-gray-300 mb-2">
                        Phone Number
                      </label>
                      {editMode ? (
                        <input
                          type="tel"
                          id="phone"
                          name="phone"
                          value={profileData.phone}
                          onChange={handleInputChange}
                          className="w-full px-4 py-3 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                          placeholder="Enter your phone number"
                        />
                      ) : (
                        <div className="flex items-center space-x-3 px-4 py-3 bg-black/30 border border-gray-700/50 rounded-lg">
                          <Phone className="w-5 h-5 text-cyber-primary" />
                          <span className="text-white">{user.phone || 'Not provided'}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Role
                    </label>
                    <div className="flex items-center space-x-3 px-4 py-3 bg-black/30 border border-gray-700/50 rounded-lg">
                      <Shield className="w-5 h-5 text-cyber-primary" />
                      <span className="text-white">{user.role || 'Security Analyst'}</span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Last Login
                    </label>
                    <div className="flex items-center space-x-3 px-4 py-3 bg-black/30 border border-gray-700/50 rounded-lg">
                      <Clock className="w-5 h-5 text-cyber-primary" />
                      <span className="text-white">{user.lastLogin ? user.lastLogin.toLocaleString() : 'Unknown'}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Security Tab */}
            {activeTab === 'security' && (
              <div className="space-y-6">
                <h3 className="text-xl font-bold text-white font-cyber">SECURITY SETTINGS</h3>

                <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6 mb-6">
                  <h4 className="text-lg font-bold text-cyber-primary mb-4 font-cyber">Change Password</h4>
                  
                  {passwordError && (
                    <div className="mb-4 bg-cyber-danger/10 border border-cyber-danger/30 rounded-lg p-4 text-cyber-danger flex items-start space-x-3">
                      <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                      <span>{passwordError}</span>
                    </div>
                  )}
                  
                  {passwordSuccess && (
                    <div className="mb-4 bg-cyber-primary/10 border border-cyber-primary/30 rounded-lg p-4 text-cyber-primary flex items-start space-x-3">
                      <CheckCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                      <span>{passwordSuccess}</span>
                    </div>
                  )}
                  
                  <div className="space-y-4">
                    <div>
                      <label htmlFor="currentPassword" className="block text-sm font-medium text-gray-300 mb-2">
                        Current Password
                      </label>
                      <input
                        type="password"
                        id="currentPassword"
                        name="currentPassword"
                        value={passwordData.currentPassword}
                        onChange={handlePasswordChange}
                        className="w-full px-4 py-3 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                        placeholder="Enter your current password"
                      />
                    </div>
                    
                    <div>
                      <label htmlFor="newPassword" className="block text-sm font-medium text-gray-300 mb-2">
                        New Password
                      </label>
                      <input
                        type="password"
                        id="newPassword"
                        name="newPassword"
                        value={passwordData.newPassword}
                        onChange={handlePasswordChange}
                        className="w-full px-4 py-3 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                        placeholder="Enter new password"
                      />
                    </div>
                    
                    <div>
                      <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-300 mb-2">
                        Confirm New Password
                      </label>
                      <input
                        type="password"
                        id="confirmPassword"
                        name="confirmPassword"
                        value={passwordData.confirmPassword}
                        onChange={handlePasswordChange}
                        className="w-full px-4 py-3 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                        placeholder="Confirm new password"
                      />
                    </div>
                    
                    <button
                      onClick={handleChangePassword}
                      disabled={isLoading || !passwordData.currentPassword || !passwordData.newPassword || !passwordData.confirmPassword}
                      className="cyber-button px-6 py-3 rounded-lg flex items-center justify-center space-x-2 w-full"
                    >
                      {isLoading ? (
                        <>
                          <div className="cyber-loading" />
                          <span>Processing...</span>
                        </>
                      ) : (
                        <>
                          <Key className="w-5 h-5" />
                          <span>Change Password</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                  <h4 className="text-lg font-bold text-cyber-primary mb-4 font-cyber">Security Features</h4>
                  
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 bg-black/50 border border-gray-700/30 rounded-lg">
                      <div>
                        <h5 className="font-medium text-white">Two-Factor Authentication</h5>
                        <p className="text-sm text-gray-400">Add an extra layer of security to your account</p>
                      </div>
                      <button className="cyber-button px-4 py-2 rounded-lg text-sm">
                        Enable
                      </button>
                    </div>
                    
                    <div className="flex items-center justify-between p-4 bg-black/50 border border-gray-700/30 rounded-lg">
                      <div>
                        <h5 className="font-medium text-white">Login Notifications</h5>
                        <p className="text-sm text-gray-400">Get notified when someone logs into your account</p>
                      </div>
                      <button className="cyber-button px-4 py-2 rounded-lg text-sm">
                        Enable
                      </button>
                    </div>
                    
                    <div className="flex items-center justify-between p-4 bg-black/50 border border-gray-700/30 rounded-lg">
                      <div>
                        <h5 className="font-medium text-white">Trusted Devices</h5>
                        <p className="text-sm text-gray-400">Manage devices that can access your account</p>
                      </div>
                      <button className="cyber-button px-4 py-2 rounded-lg text-sm">
                        Manage
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Sessions Tab */}
            {activeTab === 'sessions' && (
              <div className="space-y-6">
                <h3 className="text-xl font-bold text-white font-cyber">ACTIVE SESSIONS</h3>
                
                <div className="space-y-4">
                  {mockSessions.map((session) => (
                    <div 
                      key={session.id} 
                      className={`p-4 border rounded-xl ${
                        session.isCurrentSession 
                          ? 'bg-cyber-primary/10 border-cyber-primary/30' 
                          : 'bg-black/30 border-gray-700/50'
                      }`}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <div className={`p-2 rounded-lg ${
                            session.isCurrentSession ? 'bg-cyber-primary/20' : 'bg-gray-800'
                          }`}>
                            <Laptop className={`w-5 h-5 ${
                              session.isCurrentSession ? 'text-cyber-primary' : 'text-gray-400'
                            }`} />
                          </div>
                          <div>
                            <div className="font-medium text-white">
                              {session.browser} on {session.operatingSystem}
                              {session.isCurrentSession && (
                                <span className="ml-2 text-xs bg-cyber-primary/20 text-cyber-primary px-2 py-0.5 rounded">
                                  Current Session
                                </span>
                              )}
                            </div>
                            <div className="text-sm text-gray-400">
                              {session.deviceType} • Last active: {session.lastActive.toLocaleString()}
                            </div>
                          </div>
                        </div>
                        
                        {!session.isCurrentSession && (
                          <button className="px-3 py-1 bg-cyber-danger/20 hover:bg-cyber-danger/30 text-cyber-danger rounded text-xs transition-colors">
                            Terminate
                          </button>
                        )}
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div className="flex items-center space-x-2 text-gray-400">
                          <MapPin className="w-4 h-4" />
                          <span>{session.location}</span>
                        </div>
                        <div className="flex items-center space-x-2 text-gray-400">
                          <Shield className="w-4 h-4" />
                          <span>IP: {session.ipAddress}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Activity Tab */}
            {activeTab === 'activity' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-xl font-bold text-white font-cyber">ACCOUNT ACTIVITY</h3>
                  <button className="cyber-button px-4 py-2 rounded-lg text-sm flex items-center space-x-2">
                    <RefreshCw className="w-4 h-4" />
                    <span>Refresh</span>
                  </button>
                </div>
                
                <div className="space-y-4">
                  {mockActivity.map((activity) => (
                    <div key={activity.id} className="p-4 bg-black/30 border border-gray-700/50 rounded-xl">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <div className="p-2 bg-gray-800 rounded-lg">
                            {activity.action === 'Login' ? (
                              <Key className="w-5 h-5 text-cyber-primary" />
                            ) : activity.action === 'URL Scan' ? (
                              <Search className="w-5 h-5 text-cyber-accent" />
                            ) : (
                              <File className="w-5 h-5 text-cyber-warning" />
                            )}
                          </div>
                          <div>
                            <div className="font-medium text-white">{activity.action}</div>
                            <div className="text-sm text-gray-400">
                              {activity.timestamp.toLocaleString()}
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      <div className="text-sm text-gray-300 mb-2">
                        {activity.details}
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-gray-400">
                        <div className="flex items-center space-x-2">
                          <Laptop className="w-3 h-3" />
                          <span>{activity.deviceInfo}</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Shield className="w-3 h-3" />
                          <span>IP: {activity.ipAddress}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};

export default UserProfile;