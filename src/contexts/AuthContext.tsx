import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User, AuthContextType } from '../types';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    const savedUser = localStorage.getItem('cyberintel_user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const login = async (email: string, password: string): Promise<boolean> => {
    // Mock authentication - in real app, this would call an API
    const savedUsers = JSON.parse(localStorage.getItem('cyberintel_users') || '[]');
    const existingUser = savedUsers.find((u: any) => u.email === email && u.password === password);
    
    if (existingUser) {
      const userData: User = {
        id: existingUser.id,
        fullName: existingUser.fullName,
        email: existingUser.email,
        profilePicture: existingUser.profilePicture || null,
        role: existingUser.role || 'User',
        department: existingUser.department || 'Security',
        phone: existingUser.phone || '',
        lastLogin: new Date()
      };
      setUser(userData);
      localStorage.setItem('cyberintel_user', JSON.stringify(userData));
      return true;
    }
    return false;
  };

  const signup = async (fullName: string, email: string, password: string): Promise<boolean> => {
    // Mock registration - in real app, this would call an API
    const savedUsers = JSON.parse(localStorage.getItem('cyberintel_users') || '[]');
    const existingUser = savedUsers.find((u: any) => u.email === email);
    
    if (existingUser) {
      return false; // User already exists
    }

    const newUser = {
      id: Date.now().toString(),
      fullName,
      email,
      password,
      role: 'User',
      department: 'Security',
      createdAt: new Date(),
      lastLogin: new Date()
    };

    savedUsers.push(newUser);
    localStorage.setItem('cyberintel_users', JSON.stringify(savedUsers));

    const userData: User = {
      id: newUser.id,
      fullName: newUser.fullName,
      email: newUser.email,
      role: newUser.role,
      department: newUser.department,
      lastLogin: new Date()
    };
    
    setUser(userData);
    localStorage.setItem('cyberintel_user', JSON.stringify(userData));
    return true;
  };

  const updateProfile = async (updatedUser: Partial<User>): Promise<boolean> => {
    if (!user) return false;
    
    const updatedUserData = { ...user, ...updatedUser };
    
    // Update in local storage
    localStorage.setItem('cyberintel_user', JSON.stringify(updatedUserData));
    
    // Update in state
    setUser(updatedUserData);
    
    // Update in users array
    const savedUsers = JSON.parse(localStorage.getItem('cyberintel_users') || '[]');
    const updatedUsers = savedUsers.map((u: any) => 
      u.id === user.id ? { ...u, ...updatedUser, password: u.password } : u
    );
    localStorage.setItem('cyberintel_users', JSON.stringify(updatedUsers));
    
    return true;
  };

  const changePassword = async (currentPassword: string, newPassword: string): Promise<boolean> => {
    if (!user) return false;
    
    // Verify current password
    const savedUsers = JSON.parse(localStorage.getItem('cyberintel_users') || '[]');
    const currentUser = savedUsers.find((u: any) => u.id === user.id);
    
    if (!currentUser || currentUser.password !== currentPassword) {
      return false; // Current password is incorrect
    }
    
    // Update password
    const updatedUsers = savedUsers.map((u: any) => 
      u.id === user.id ? { ...u, password: newPassword } : u
    );
    localStorage.setItem('cyberintel_users', JSON.stringify(updatedUsers));
    
    return true;
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('cyberintel_user');
  };

  const value: AuthContextType = {
    user,
    login,
    signup,
    logout,
    updateProfile,
    changePassword,
    isAuthenticated: !!user
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};