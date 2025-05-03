console.log('Content script loaded!');

if (!window.contentScriptLoaded) {
  window.contentScriptLoaded = true;

  chrome.storage.local.get(['username', 'token'], (result) => {
    console.log('Content script storage check:', result);
    const username = result.username || 'unknown';
    const token = result.token || '';

    if (!username || !token || username === 'unknown') {
      console.error('Missing username or token in chrome.storage.local:', { username, token });
      return;
    }

    const sendHeartbeat = () => {
      console.log('Sending heartbeat for username:', username, 'token:', token.substring(0, 10) + '...');
      fetch('http://localhost:8080/api/user/heartbeat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ username })
      })
        .then(response => {
          if (!response.ok) {
            throw new Error(`Heartbeat failed: ${response.status}`);
          }
          return response.json();
        })
        .then(data => console.log('Heartbeat sent:', data))
        .catch(error => console.error('Error sending heartbeat:', error.message));
    };

    sendHeartbeat();
    const heartbeatInterval = setInterval(sendHeartbeat, 15000);

    chrome.storage.local.onChanged.addListener((changes) => {
      if (changes.token && !changes.token.newValue) {
        console.log('Token removed, stopping heartbeats');
        clearInterval(heartbeatInterval);
      }
    });

    console.log('Checking phishing for URL:', window.location.href);
    fetch('http://localhost:8080/api/admin/phishing', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ url: window.location.href })
    })
      .then(response => {
        if (!response.ok) {
          throw new Error(`Phishing check failed: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        console.log('Initial checkPhishing response: isPhishing =', data.isPhishing);
        chrome.runtime.sendMessage({ type: data.isPhishing ? 'phishing' : 'secure' });
      })
      .catch(error => console.error('Error checking phishing:', error.message));
  });

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Received message in content script:', message);
    if (message.type === 'phishing' || message.type === 'secure') {
      console.log('Updating phishing status in content script:', message.type);
    }
  });
} else {
  console.log('Content script already loaded, skipping re-injection.');
}