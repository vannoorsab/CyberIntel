import React from 'react';
import { Bell, AlertTriangle } from 'lucide-react';
import { useAlert } from '../contexts/AlertContext';

interface AlertBadgeProps {
  onClick?: () => void;
  className?: string;
}

const AlertBadge: React.FC<AlertBadgeProps> = ({ onClick, className = '' }) => {
  const { getUnreadCount, getCriticalCount } = useAlert();
  
  const unreadCount = getUnreadCount();
  const criticalCount = getCriticalCount();

  if (unreadCount === 0) {
    return (
      <button
        onClick={onClick}
        className={`relative p-2 text-gray-400 hover:text-white transition-colors ${className}`}
        title="No new alerts"
      >
        <Bell className="w-6 h-6" />
      </button>
    );
  }

  return (
    <button
      onClick={onClick}
      className={`relative p-2 text-white transition-colors hover:scale-110 ${className}`}
      title={`${unreadCount} unread alerts${criticalCount > 0 ? `, ${criticalCount} critical` : ''}`}
    >
      {criticalCount > 0 ? (
        <AlertTriangle className="w-6 h-6 text-red-400 animate-pulse" />
      ) : (
        <Bell className="w-6 h-6 text-orange-400" />
      )}
      
      {/* Badge */}
      <div className={`absolute -top-1 -right-1 min-w-[20px] h-5 rounded-full flex items-center justify-center text-xs font-bold text-white ${
        criticalCount > 0 
          ? 'bg-red-500 animate-pulse shadow-lg shadow-red-500/50' 
          : 'bg-orange-500 shadow-lg shadow-orange-500/50'
      }`}>
        {unreadCount > 99 ? '99+' : unreadCount}
      </div>
      
      {/* Pulse animation for critical alerts */}
      {criticalCount > 0 && (
        <div className="absolute inset-0 rounded-full bg-red-500/30 animate-ping" />
      )}
    </button>
  );
};

export default AlertBadge;