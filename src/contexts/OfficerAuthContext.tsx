import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { Officer, OfficerAuthContextType } from '../types';

const OfficerAuthContext = createContext<OfficerAuthContextType | undefined>(undefined);

export const useOfficerAuth = () => {
  const context = useContext(OfficerAuthContext);
  if (context === undefined) {
    throw new Error('useOfficerAuth must be used within an OfficerAuthProvider');
  }
  return context;
};

interface OfficerAuthProviderProps {
  children: ReactNode;
}

export const OfficerAuthProvider: React.FC<OfficerAuthProviderProps> = ({ children }) => {
  const [officer, setOfficer] = useState<Officer | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);

  useEffect(() => {
    try {
      const savedOfficer = localStorage.getItem('cyberintel_officer');
      if (savedOfficer) {
        const parsedOfficer = JSON.parse(savedOfficer);
        console.log('Loaded officer from localStorage:', parsedOfficer);
        setOfficer(parsedOfficer);
      }
    } catch (error) {
      console.error('Error loading officer from localStorage:', error);
      localStorage.removeItem('cyberintel_officer');
    } finally {
      setIsInitialized(true);
    }
  }, []);

  const login = async (officerId: string, password: string): Promise<boolean> => {
    console.log('Officer login attempt:', { officerId });
    
    // Mock officer authentication - in real app, this would call a secure API
    const mockOfficers = [
      { 
        id: '1', 
        officerId: 'CBI001', 
        password: 'secure123', 
        fullName: 'Agent Sarah Connor', 
        department: 'CBI Cyber Division', 
        rank: 'Senior Investigator',
        email: 'sarah.connor@cbi.gov.in'
      },
      { 
        id: '2', 
        officerId: 'CYBER002', 
        password: 'redteam456', 
        fullName: 'Lt. John Matrix', 
        department: 'Red Team Operations', 
        rank: 'Team Lead',
        email: 'john.matrix@cyberops.gov.in'
      },
      { 
        id: '3', 
        officerId: 'SEC003', 
        password: 'forensic789', 
        fullName: 'Dr. Lisa Chen', 
        department: 'Digital Forensics', 
        rank: 'Chief Analyst',
        email: 'lisa.chen@forensics.gov.in'
      },
      { 
        id: '4', 
        officerId: 'ADMIN001', 
        password: 'admin2024', 
        fullName: 'Vannoor Sab', 
        department: 'Cybersecurity Administration', 
        rank: 'Chief Security Officer',
        email: 'vanursab18@gmail.com'
      }
    ];
    
    console.log('Available officers:', mockOfficers.map(o => ({ id: o.officerId, name: o.fullName })));
    
    const validOfficer = mockOfficers.find(o => {
      return o.officerId === officerId && o.password === password;
    });
    
    console.log('Found valid officer:', validOfficer ? validOfficer.fullName : 'None');
    
    if (validOfficer) {
      const officerData: Officer = {
        id: validOfficer.id,
        officerId: validOfficer.officerId,
        fullName: validOfficer.fullName,
        department: validOfficer.department,
        rank: validOfficer.rank,
        email: validOfficer.email
      };
      
      console.log('Setting officer data:', officerData);
      setOfficer(officerData);
      
      try {
        localStorage.setItem('cyberintel_officer', JSON.stringify(officerData));
        console.log('Officer data saved to localStorage');
      } catch (error) {
        console.error('Error saving officer to localStorage:', error);
      }
      
      return true;
    }
    
    console.log('Login failed - invalid credentials');
    return false;
  };

  const logout = () => {
    console.log('Officer logout');
    setOfficer(null);
    try {
      localStorage.removeItem('cyberintel_officer');
    } catch (error) {
      console.error('Error removing officer from localStorage:', error);
    }
  };

  const value: OfficerAuthContextType = {
    officer,
    login,
    logout,
    isAuthenticated: !!officer,
    isInitialized
  };

  console.log('OfficerAuthContext value:', { isAuthenticated: !!officer, officer: officer?.fullName });

  return <OfficerAuthContext.Provider value={value}>{children}</OfficerAuthContext.Provider>;
};