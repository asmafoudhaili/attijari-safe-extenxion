document.addEventListener('DOMContentLoaded', () => {
  const statusElement = document.getElementById('status');
  const userInfoElement = document.getElementById('user-info');
  const loginForm = document.getElementById('login-form');
  const loginButton = document.getElementById('login-button');
  const logoutButton = document.getElementById('logout-button');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const errorElement = document.getElementById('error');

  // Check if chrome.storage is available
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
    console.error('Chrome storage API is not available');
    userInfoElement.textContent = 'Extension environment error';
    loginForm.style.display = 'none';
    logoutButton.style.display = 'none';
    statusElement.style.display = 'none';
    return;
  }

  // Check sign-in status on popup load
  chrome.storage.local.get(['username', 'token'], (result) => {
    console.log('Initial storage check:', result);
    if (result.username && result.token) {
      userInfoElement.textContent = `Signed in as ${result.username}`;
      loginForm.style.display = 'none';
      logoutButton.style.display = 'block';
      // Show phishing status when signed in
      statusElement.style.display = 'block';
    } else {
      userInfoElement.textContent = 'Not signed in';
      loginForm.style.display = 'block';
      logoutButton.style.display = 'none';
      // Hide phishing status when not signed in
      statusElement.style.display = 'none';
    }
  });

  // Check phishing status for the current tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0].url;
    statusElement.textContent = 'Checking...';

    chrome.runtime.sendMessage({ type: 'checkPhishing', url }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('Runtime error:', chrome.runtime.lastError);
        statusElement.textContent = '❓ Error checking site.';
        return;
      }
      if (response?.isPhishing === undefined) {
        statusElement.textContent = '❓ Unknown status.';
      } else if (response.isPhishing) {
        statusElement.textContent = '⚠️ This is a phishing site!';
      } else {
        statusElement.textContent = '✅ This site is secure.';
      }
    });
  });

  // Handle Sign In
  loginButton.addEventListener('click', () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();

    if (!username || !password) {
      errorElement.textContent = 'Please enter username and password';
      return;
    }

    userInfoElement.textContent = 'Authenticating...';
    errorElement.textContent = '';

    chrome.runtime.sendMessage({ type: 'login', username, password }, (response) => {
      if (response.success) {
        console.log('Login response:', response);
        userInfoElement.textContent = `Signed in as ${username}`;
        loginForm.style.display = 'none';
        logoutButton.style.display = 'block';
        usernameInput.value = '';
        passwordInput.value = '';
        // Show phishing status when signed in
        statusElement.style.display = 'block';
        // Notify content script to recheck
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]) {
            chrome.runtime.sendMessage({ type: 'checkPhishing', url: tabs[0].url });
          }
        });
      } else {
        errorElement.textContent = response.error || 'Authentication failed';
        userInfoElement.textContent = 'Not signed in';
        console.error('Login error:', response.error);
      }
    });
  });

  // Handle Sign Out
  logoutButton.addEventListener('click', () => {
    chrome.storage.local.remove(['username', 'token'], () => {
      console.log('Logged out, storage cleared');
      userInfoElement.textContent = 'Not signed in';
      loginForm.style.display = 'block';
      logoutButton.style.display = 'none';
      usernameInput.value = '';
      passwordInput.value = '';
      errorElement.textContent = '';
      // Hide phishing status when logged out
      statusElement.style.display = 'none';
      // Notify content script to clear status
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.runtime.sendMessage({ type: 'secure' });
        }
      });
    });
  });
});