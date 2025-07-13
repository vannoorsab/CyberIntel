import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { Alert, AlertContextType } from '../types';
import { emailService } from '../utils/emailService';

const AlertContext = createContext<AlertContextType | undefined>(undefined);

export const useAlert = () => {
  const context = useContext(AlertContext);
  if (context === undefined) {
    throw new Error('useAlert must be used within an AlertProvider');
  }
  return context;
};

interface AlertProviderProps {
  children: ReactNode;
}

export const AlertProvider: React.FC<AlertProviderProps> = ({ children }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    // Load alerts from localStorage on mount
    const savedAlerts = localStorage.getItem('cyberintel_alerts');
    if (savedAlerts) {
      try {
        const parsedAlerts = JSON.parse(savedAlerts).map((alert: any) => ({
          ...alert,
          timestamp: new Date(alert.timestamp)
        }));
        setAlerts(parsedAlerts);
      } catch (error) {
        console.error('Error loading alerts from localStorage:', error);
        localStorage.removeItem('cyberintel_alerts');
      }
    }
  }, []);

  useEffect(() => {
    // Save alerts to localStorage whenever alerts change
    try {
      localStorage.setItem('cyberintel_alerts', JSON.stringify(alerts));
    } catch (error) {
      console.error('Error saving alerts to localStorage:', error);
    }
  }, [alerts]);

  const addAlert = (alertData: Omit<Alert, 'id' | 'timestamp'>) => {
    const newAlert: Alert = {
      ...alertData,
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date()
    };

    setAlerts(prev => [newAlert, ...prev.slice(0, 99)]); // Keep only last 100 alerts

    // Show toast notification
    showToastNotification(newAlert);

    // Play alert sound
    playAlertSound(newAlert.priority);

    // Send email notification for critical alerts
    if (newAlert.priority === 'critical') {
      sendEmailNotification(newAlert);
    }

    return newAlert;
  };

  const markAsRead = (alertId: string) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, status: 'read' } : alert
    ));
  };

  const markAsAcknowledged = (alertId: string) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, status: 'acknowledged' } : alert
    ));
  };

  const getUnreadCount = () => {
    return alerts.filter(alert => alert.status === 'unread').length;
  };

  const getCriticalCount = () => {
    return alerts.filter(alert => alert.priority === 'critical' && alert.status === 'unread').length;
  };

  const clearAllAlerts = () => {
    setAlerts([]);
    localStorage.removeItem('cyberintel_alerts');
  };

  const deleteAlert = (alertId: string) => {
    setAlerts(prev => prev.filter(alert => alert.id !== alertId));
  };

  // Enhanced toast notification system
  const showToastNotification = (alert: Alert) => {
    // Remove any existing toasts first
    const existingToasts = document.querySelectorAll('.alert-toast');
    existingToasts.forEach(toast => toast.remove());

    // Create new toast element
    const toast = document.createElement('div');
    toast.className = `alert-toast fixed top-4 right-4 z-[9999] max-w-md p-4 rounded-xl border backdrop-blur-xl transform transition-all duration-500 translate-x-full opacity-0 ${
      alert.priority === 'critical' 
        ? 'bg-red-900/90 border-red-500/50 text-red-100' 
        : alert.priority === 'high'
        ? 'bg-orange-900/90 border-orange-500/50 text-orange-100'
        : 'bg-blue-900/90 border-blue-500/50 text-blue-100'
    }`;

    const icon = alert.priority === 'critical' ? '🚨' : 
                 alert.priority === 'high' ? '⚠️' : 
                 alert.type === 'ThreatScan' ? '🛡️' : '🛠️';
    
    toast.innerHTML = `
      <div class="flex items-start space-x-3">
        <div class="text-2xl flex-shrink-0">${icon}</div>
        <div class="flex-1 min-w-0">
          <div class="font-bold text-sm mb-1">
            ${alert.type === 'ThreatScan' ? 'Security Threat Detected' : 
              alert.type === 'BugReport' ? 'New Bug Report' :
              alert.type === 'DLPViolation' ? 'Data Loss Prevention Alert' :
              alert.type === 'ForensicEvent' ? 'Forensic Event Detected' : 'Security Alert'}
          </div>
          <div class="text-xs opacity-90 mb-2 break-words">${alert.message}</div>
          <div class="text-xs opacity-75">📧 Email sent to vanursab71@gmail.com</div>
        </div>
        <button class="text-white/60 hover:text-white text-lg leading-none flex-shrink-0 ml-2" onclick="this.parentElement.parentElement.remove()">×</button>
      </div>
    `;

    document.body.appendChild(toast);

    // Animate in
    setTimeout(() => {
      toast.classList.remove('translate-x-full', 'opacity-0');
    }, 100);

    // Auto remove after 8 seconds
    setTimeout(() => {
      if (toast.parentNode) {
        toast.classList.add('translate-x-full', 'opacity-0');
        setTimeout(() => {
          if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
          }
        }, 500);
      }
    }, 8000);
  };

  // Enhanced alert sound system
  const playAlertSound = (priority: string) => {
    if ('AudioContext' in window || 'webkitAudioContext' in window) {
      try {
        const AudioContext = window.AudioContext || (window as any).webkitAudioContext;
        const audioContext = new AudioContext();
        
        if (priority === 'critical') {
          // Critical alert: Three urgent beeps
          [0, 0.3, 0.6].forEach((delay) => {
            setTimeout(() => {
              const oscillator = audioContext.createOscillator();
              const gainNode = audioContext.createGain();
              
              oscillator.connect(gainNode);
              gainNode.connect(audioContext.destination);
              
              oscillator.frequency.setValueAtTime(880, audioContext.currentTime); // Higher pitch for critical
              oscillator.type = 'sine';
              
              gainNode.gain.setValueAtTime(0.2, audioContext.currentTime);
              gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.2);
              
              oscillator.start(audioContext.currentTime);
              oscillator.stop(audioContext.currentTime + 0.2);
            }, delay * 1000);
          });
        } else if (priority === 'high') {
          // High priority: Two beeps
          [0, 0.4].forEach((delay) => {
            setTimeout(() => {
              const oscillator = audioContext.createOscillator();
              const gainNode = audioContext.createGain();
              
              oscillator.connect(gainNode);
              gainNode.connect(audioContext.destination);
              
              oscillator.frequency.setValueAtTime(660, audioContext.currentTime);
              oscillator.type = 'sine';
              
              gainNode.gain.setValueAtTime(0.15, audioContext.currentTime);
              gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.25);
              
              oscillator.start(audioContext.currentTime);
              oscillator.stop(audioContext.currentTime + 0.25);
            }, delay * 1000);
          });
        } else {
          // Regular alert: Single beep
          const oscillator = audioContext.createOscillator();
          const gainNode = audioContext.createGain();
          
          oscillator.connect(gainNode);
          gainNode.connect(audioContext.destination);
          
          oscillator.frequency.setValueAtTime(440, audioContext.currentTime);
          oscillator.type = 'sine';
          
          gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
          gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
          
          oscillator.start(audioContext.currentTime);
          oscillator.stop(audioContext.currentTime + 0.3);
        }
      } catch (error) {
        console.log('Audio notification not available:', error);
      }
    }
  };

  // Email notification for critical alerts
  const sendEmailNotification = async (alert: Alert) => {
    try {
      const subject = `🚨 CRITICAL ALERT - ${alert.type}`;
      const message = `
CRITICAL SECURITY ALERT
=======================

Alert Type: ${alert.type}
Priority: ${alert.priority.toUpperCase()}
Time: ${alert.timestamp.toLocaleString()}

Message: ${alert.message}

User: ${alert.userEmail}
Alert ID: ${alert.id}

This is an automated critical alert from CyberIntel.
Immediate attention required.

Access Alert Dashboard: https://cyberintel.ai
      `;

      await emailService.sendEmail({
        to: 'vanursab71@gmail.com',
        subject,
        message,
        type: 'alert'
      });
    } catch (error) {
      console.error('Failed to send email notification:', error);
    }
  };

  const value: AlertContextType = {
    alerts,
    addAlert,
    markAsRead,
    markAsAcknowledged,
    getUnreadCount,
    getCriticalCount,
    clearAllAlerts,
    deleteAlert
  };

  return <AlertContext.Provider value={value}>{children}</AlertContext.Provider>;
};