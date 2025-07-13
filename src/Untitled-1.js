// ...existing code...

// Officer Panel route should come first!
if (currentRoute === '/officer-panel') {
  return (
    <AlertProvider>
      <OfficerAuthProvider>
        <OfficerPanelPage onNavigate={navigate} />
      </OfficerAuthProvider>
    </AlertProvider>
  );
}

// Officer login route
if (currentRoute === '/officer-login' || userType === 'officer') {
  return (
    <AlertProvider>
      <OfficerAuthProvider>
        <OfficerLoginPage onNavigate={navigate} />
      </OfficerAuthProvider>
    </AlertProvider>
  );
}

// ...existing code...