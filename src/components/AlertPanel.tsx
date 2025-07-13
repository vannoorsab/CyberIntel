import React, { useState } from 'react';
import { X, CheckCircle, Eye, Clock, AlertTriangle, Bug, Shield, Trash2, RefreshCw } from 'lucide-react';
import { useAlert } from '../contexts/AlertContext';
import { Alert } from '../types';

interface AlertPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

const AlertPanel: React.FC<AlertPanelProps> = ({ isOpen, onClose }) => {
  const { alerts, markAsRead, markAsAcknowledged, clearAllAlerts, deleteAlert } = useAlert();
  const [filter, setFilter] = useState<'all' | 'unread' | 'critical'>('all');

  const filteredAlerts = alerts.filter(alert => {
    switch (filter) {
      case 'unread':
        return alert.status === 'unread';
      case 'critical':
        return alert.priority === 'critical';
      default:
        return true;
    }
  });

  const handleAlertClick = (alert: Alert) => {
    if (alert.status === 'unread') {
      markAsRead(alert.id);
    }
  };

  const handleAcknowledge = (alertId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    markAsAcknowledged(alertId);
  };

  const handleDelete = (alertId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (deleteAlert) {
      deleteAlert(alertId);
    }
  };

  const handleClearAll = () => {
    if (clearAllAlerts && window.confirm('Are you sure you want to clear all alerts?')) {
      clearAllAlerts();
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical':
        return 'border-red-500/50 bg-red-500/10 text-red-400';
      case 'high':
        return 'border-orange-500/50 bg-orange-500/10 text-orange-400';
      case 'medium':
        return 'border-yellow-500/50 bg-yellow-500/10 text-yellow-400';
      default:
        return 'border-blue-500/50 bg-blue-500/10 text-blue-400';
    }
  };

  const getStatusIcon = (alert: Alert) => {
    switch (alert.status) {
      case 'acknowledged':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'read':
        return <Eye className="w-4 h-4 text-blue-400" />;
      default:
        return <Clock className="w-4 h-4 text-orange-400" />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ThreatScan':
        return <Shield className="w-5 h-5 text-red-400" />;
      case 'BugReport':
        return <Bug className="w-5 h-5 text-purple-400" />;
      case 'DLPViolation':
        return <Shield className="w-5 h-5 text-orange-400" />;
      case 'ForensicEvent':
        return <Eye className="w-5 h-5 text-indigo-400" />;
      default:
        return <AlertTriangle className="w-5 h-5 text-yellow-400" />;
    }
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case 'ThreatScan':
        return '🔴 Critical Threat Detected';
      case 'BugReport':
        return '🛠️ New Bug Report';
      case 'DLPViolation':
        return '🛡️ Data Loss Prevention Alert';
      case 'ForensicEvent':
        return '🔍 Forensic Event Detected';
      default:
        return '⚠️ Security Alert';
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-start justify-end z-50 p-4">
      <div className="bg-gray-900/95 backdrop-blur-xl border border-gray-700/50 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700/50">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="w-6 h-6 text-orange-400" />
            <h2 className="text-xl font-bold text-white">Security Alerts</h2>
            {alerts.length > 0 && (
              <span className="px-2 py-1 bg-orange-500/20 text-orange-400 rounded text-sm font-medium">
                {alerts.length}
              </span>
            )}
          </div>
          <div className="flex items-center space-x-2">
            {alerts.length > 0 && clearAllAlerts && (
              <button
                onClick={handleClearAll}
                className="p-2 text-gray-400 hover:text-red-400 transition-colors"
                title="Clear all alerts"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            )}
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <X className="w-6 h-6" />
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="p-4 border-b border-gray-700/50">
          <div className="flex space-x-2">
            <button
              onClick={() => setFilter('all')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                filter === 'all'
                  ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
              }`}
            >
              All ({alerts.length})
            </button>
            <button
              onClick={() => setFilter('unread')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                filter === 'unread'
                  ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
              }`}
            >
              Unread ({alerts.filter(a => a.status === 'unread').length})
            </button>
            <button
              onClick={() => setFilter('critical')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                filter === 'critical'
                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
              }`}
            >
              Critical ({alerts.filter(a => a.priority === 'critical').length})
            </button>
          </div>
        </div>

        {/* Alerts List */}
        <div className="overflow-y-auto max-h-[60vh]">
          {filteredAlerts.length === 0 ? (
            <div className="p-8 text-center">
              <AlertTriangle className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400">
                {filter === 'all' ? 'No alerts found' : `No ${filter} alerts found`}
              </p>
            </div>
          ) : (
            <div className="space-y-2 p-4">
              {filteredAlerts.map((alert) => (
                <div
                  key={alert.id}
                  onClick={() => handleAlertClick(alert)}
                  className={`border rounded-xl p-4 cursor-pointer transition-all duration-200 hover:scale-[1.02] ${
                    getPriorityColor(alert.priority)
                  } ${
                    alert.status === 'unread' ? 'ring-2 ring-orange-500/30' : ''
                  }`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      {getTypeIcon(alert.type)}
                      <div>
                        <div className="font-bold text-sm">
                          {getTypeLabel(alert.type)}
                        </div>
                        <div className="text-xs opacity-75">
                          From: {alert.userEmail} • {alert.timestamp.toLocaleString()}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(alert)}
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        alert.priority === 'critical' ? 'bg-red-500/20 text-red-400' :
                        alert.priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        alert.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-blue-500/20 text-blue-400'
                      }`}>
                        {alert.priority.toUpperCase()}
                      </span>
                    </div>
                  </div>

                  <p className="text-sm mb-3 leading-relaxed">{alert.message}</p>

                  <div className="flex items-center justify-between">
                    <div className="text-xs opacity-75">
                      📧 Email sent to vanursab71@gmail.com
                    </div>
                    <div className="flex space-x-2">
                      {alert.status !== 'acknowledged' && (
                        <button
                          onClick={(e) => handleAcknowledge(alert.id, e)}
                          className="px-3 py-1 bg-green-500/20 hover:bg-green-500/30 text-green-400 rounded text-xs transition-colors flex items-center space-x-1"
                        >
                          <CheckCircle className="w-3 h-3" />
                          <span>Acknowledge</span>
                        </button>
                      )}
                      {deleteAlert && (
                        <button
                          onClick={(e) => handleDelete(alert.id, e)}
                          className="px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded text-xs transition-colors flex items-center space-x-1"
                        >
                          <Trash2 className="w-3 h-3" />
                          <span>Delete</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-700/50 bg-gray-800/50">
          <div className="text-center text-xs text-gray-400">
            🔒 All alerts are logged and monitored • Real-time threat detection active
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlertPanel;