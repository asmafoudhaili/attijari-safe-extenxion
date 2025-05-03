const sentNotifications = {
  phishing: {},
  codeSafety: {},
  timeout: {}
};

// Cache phishing results with timestamps
const phishingCache = {};
const CACHE_TIMEOUT = 5 * 60 * 1000; // 5 minutes in milliseconds

function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return hash.toString();
}

function normalizeUrl(url) {
  try {
    const urlObj = new URL(url);
    urlObj.pathname = urlObj.pathname.replace(/\/+$/, '');
    urlObj.search = '';
    urlObj.hash = '';
    return urlObj.toString();
  } catch (error) {
    console.error('Error normalizing URL:', url, error.message);
    return url;
  }
}

async function fetchWithRetry(url, options, retries = 3, delay = 1000) {
  for (let i = 0; i < retries; i++) {
    try {
      console.log(`Fetch attempt ${i + 1} for ${url} with options:`, options);
      const response = await fetch(url, options);
      if (!response.ok) {
        const errorText = await response.text();
        console.log(`Response headers:`, [...response.headers]);
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }
      return response;
    } catch (error) {
      console.error(`Fetch attempt ${i + 1} failed for ${url}:`, error.message, 'Options:', options);
      if (i === retries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

async function getAuthToken() {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(['token', 'username'], (result) => {
      console.log('Background getAuthToken storage check:', result);
      if (result.token && result.username) {
        console.log('Using cached token:', result.token.substring(0, 10) + '...');
        resolve(result.token);
      } else if (result.username) {
        console.log('Token missing but username exists, attempting refresh');
        refreshToken(result.username, result.token)
          .then(newToken => resolve(newToken))
          .catch(error => {
            console.error('Token refresh failed:', error.message);
            reject(new Error('Unable to refresh token'));
          });
      } else {
        console.error('No token or username found in chrome.storage.local');
        reject(new Error('User not authenticated'));
      }
    });
  });
}

async function refreshToken(username, currentToken) {
  try {
    const response = await fetchWithRetry('http://localhost:8080/api/refresh', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentToken || ''}`
      },
      body: JSON.stringify({ username })
    });
    const data = await response.json();
    chrome.storage.local.set({ token: data.jwt }, () => {
      console.log('Token refreshed:', data.jwt.substring(0, 10) + '...');
    });
    return data.jwt;
  } catch (error) {
    console.error('Token refresh failed:', error.message);
    throw error;
  }
}

async function login(username, password) {
  try {
    console.log('Attempting login for username:', username, 'with Origin:', 'chrome-extension://' + chrome.runtime.id);
    const response = await fetchWithRetry('http://localhost:8080/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'chrome-extension://' + chrome.runtime.id
      },
      body: JSON.stringify({ username, password })
    });
    const data = await response.json();
    console.log('Login response received:', data);
    chrome.storage.local.set({ token: data.jwt, username }, () => {
      console.log('Login successful, token stored:', data.jwt.substring(0, 10) + '...');
      chrome.storage.local.get(['username', 'token'], (result) => {
        console.log('Storage after login:', result);
      });
    });
    return data;
  } catch (error) {
    let errorMessage = error.message;
    if (error.response) {
      errorMessage += ' Response: ' + (await error.response.text() || 'No response');
    }
    console.error('Login failed:', errorMessage, 'Status:', error.status);
    throw new Error(errorMessage);
  }
}

async function checkPhishing(url, token, retries = 3) {
  const normalizedUrl = normalizeUrl(url);
  if (phishingCache[normalizedUrl]?.inProgress) {
    console.log(`Check already in progress for URL: ${normalizedUrl}`);
    return phishingCache[normalizedUrl].isPhishing;
  }
  phishingCache[normalizedUrl] = { inProgress: true };
  try {
    console.log(`Checking phishing for URL (attempt 1):`, normalizedUrl);
    const response = await fetchWithRetry('http://localhost:8080/api/admin/phishing', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ url: normalizedUrl })
    });
    const data = await response.json();
    console.log('Phishing check result:', data);
    phishingCache[normalizedUrl] = {
      isPhishing: data.isPhishing,
      timestamp: Date.now(),
      inProgress: false
    };
    return data.isPhishing;
  } catch (error) {
    console.error(`Phishing check failed:`, error.message);
    phishingCache[normalizedUrl] = {
      isPhishing: true,
      timestamp: Date.now(),
      inProgress: false
    };
    return true;
  }
}

async function checkCodeSafety(code, token) {
  const codeHash = simpleHash(code);
  try {
    const response = await fetchWithRetry('http://localhost:8080/api/admin/code-safety', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ code })
    });
    const data = await response.json();
    return { isSafe: data.isSafe, positives: data.positives || 0 };
  } catch (error) {
    console.error('Backend code safety check error:', error.message);
    return { isSafe: false, positives: 0 };
  }
}

async function ensureContentScript(tabId) {
  return new Promise((resolve, reject) => {
    chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    }, (results) => {
      if (chrome.runtime.lastError) {
        console.error(`Failed to inject content script into tab ${tabId}:`, chrome.runtime.lastError.message);
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        console.log(`Content script injected into tab ${tabId}`);
        resolve();
      }
    });
  });
}

async function sendMessageToTab(tabId, message, retries = 3, delay = 1000) {
  return new Promise((resolve, reject) => {
    chrome.tabs.get(tabId, async (tab) => {
      if (chrome.runtime.lastError || !tab) {
        console.error(`Tab ${tabId} does not exist:`, chrome.runtime.lastError?.message || 'Tab not found');
        reject(new Error('Tab does not exist'));
        return;
      }

      console.log(`Tab ${tabId} status: ${tab.status}, URL: ${tab.url}`);

      if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || tab.url.startsWith('file://')) {
        console.log(`Skipping message send to tab ${tabId} due to unsupported URL: ${tab.url}`);
        resolve({ skipped: true });
        return;
      }

      if (tab.status !== 'complete') {
        console.log(`Tab ${tabId} is not fully loaded (status: ${tab.status}), retrying after delay...`);
        if (retries > 0) {
          setTimeout(() => {
            sendMessageToTab(tabId, message, retries - 1, delay).then(resolve).catch(reject);
          }, delay);
          return;
        } else {
          console.error(`Tab ${tabId} still not loaded after max retries, giving up.`);
          reject(new Error('Tab not fully loaded after max retries'));
          return;
        }
      }

      try {
        await ensureContentScript(tabId);
      } catch (error) {
        console.error(`Cannot send message to tab ${tabId} due to injection failure:`, error.message);
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon.png',
          title: 'CyberGuard Error',
          message: '⚠️ Failed to load phishing detection on this page.',
          priority: 2
        }, (notificationId) => {
          if (chrome.runtime.lastError) {
            console.error('Error notification error:', chrome.runtime.lastError.message);
          } else {
            console.log('Error notification created:', notificationId);
          }
        });
        reject(error);
        return;
      }

      chrome.tabs.sendMessage(tabId, message, (response) => {
        if (chrome.runtime.lastError) {
          console.error(`Failed to send message to tab ${tabId}:`, chrome.runtime.lastError.message);
          if (retries > 0) {
            console.log(`Retrying message send to tab ${tabId}, ${retries} attempts left...`);
            setTimeout(() => {
              sendMessageToTab(tabId, message, retries - 1, delay).then(resolve).catch(reject);
            }, delay);
          } else {
            console.error(`Max retries reached for tab ${tabId}, giving up.`);
            chrome.notifications.create({
              type: 'basic',
              iconUrl: 'icons/icon.png',
              title: 'CyberGuard Error',
              message: '⚠️ Failed to communicate with the page. Please refresh.',
              priority: 2
            }, (notificationId) => {
              if (chrome.runtime.lastError) {
                console.error('Error notification error:', chrome.runtime.lastError.message);
              } else {
                console.log('Error notification created:', notificationId);
              }
            });
            reject(new Error(`Max retries reached: ${chrome.runtime.lastError.message}`));
          }
        } else {
          console.log(`Message sent to tab ${tabId}:`, message);
          resolve(response);
        }
      });
    });
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Background script active, received message:', message);

  if (message.type === 'checkAuth') {
    chrome.storage.local.get(['username', 'token'], (result) => {
      console.log('checkAuth storage check:', result);
      if (result.username && result.token) {
        sendResponse({ success: true, userInfo: { email: result.username }, token: result.token });
      } else {
        sendResponse({ success: false, error: 'Not authenticated' });
      }
    });
    return true;
  }

  if (message.type === 'login') {
    login(message.username, message.password)
      .then((data) => {
        chrome.storage.local.set({ username: message.username, token: data.jwt }, () => {
          console.log('Login successful, credentials stored');
          sendResponse({ success: true, token: data.jwt });
        });
      })
      .catch((error) => {
        console.error('Login failed:', error.message, 'Status:', error.status);
        sendResponse({ success: false, error: error.message });
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon.png',
          title: 'CyberGuard Alert',
          message: '⚠️ Login failed: ' + error.message,
          priority: 2
        });
      });
    return true;
  }

  if (message.type === 'authenticate') {
    chrome.storage.local.get(['username', 'token'], (result) => {
      console.log('authenticate storage check:', result);
      if (result.username && result.token) {
        sendResponse({ success: true, userInfo: { email: result.username }, token: result.token });
      } else {
        sendResponse({ success: false, error: 'Authentication required' });
      }
    });
    return true;
  }

  if (message.type === 'signOut') {
    chrome.storage.local.remove(['username', 'token'], () => {
      console.log('signOut storage cleared');
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === 'checkPhishing') {
    const normalizedUrl = normalizeUrl(message.url);
    console.log(`Received checkPhishing message for URL: ${normalizedUrl}`);
    getAuthToken()
      .then((token) => {
        if (phishingCache.hasOwnProperty(normalizedUrl) && (Date.now() - phishingCache[normalizedUrl].timestamp >= CACHE_TIMEOUT || phishingCache[normalizedUrl].isPhishing === null)) {
          delete phishingCache[normalizedUrl];
        }
        if (phishingCache.hasOwnProperty(normalizedUrl) && (Date.now() - phishingCache[normalizedUrl].timestamp < CACHE_TIMEOUT)) {
          console.log('Returning cached phishing result for URL:', normalizedUrl, phishingCache[normalizedUrl].isPhishing);
          sendResponse({ isPhishing: phishingCache[normalizedUrl].isPhishing });
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
              sendMessageToTab(tabs[0].id, {
                type: phishingCache[normalizedUrl].isPhishing ? 'phishing' : 'secure'
              }).catch((error) => {
                console.error('Failed to send cached result to content script:', error.message);
              });
            }
          });
          return;
        }
        checkPhishing(normalizedUrl, token)
          .then((isPhishing) => {
            console.log(`checkPhishing result for ${normalizedUrl}: isPhishing = ${isPhishing}`);
            sendResponse({ isPhishing });
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
              if (tabs[0]) {
                sendMessageToTab(tabs[0].id, {
                  type: isPhishing ? 'phishing' : 'secure'
                }).catch((error) => {
                  console.error('Failed to send phishing result to content script:', error.message);
                });
              }
            });
          })
          .catch((error) => {
            console.error('Error checking phishing:', error.message);
            sendResponse({ isPhishing: true });
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
              if (tabs[0]) {
                sendMessageToTab(tabs[0].id, { type: 'phishing' })
                  .catch((error) => {
                    console.error('Failed to send error status to content script:', error.message);
                  });
              }
            });
          });
      })
      .catch((error) => {
        console.error('Authentication error:', error.message);
        sendResponse({ isPhishing: true, error: 'Please log in to perform phishing checks.' });
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon.png',
          title: 'CyberGuard Alert',
          message: '⚠️ Please log in to enable phishing detection.',
          priority: 2
        });
      });
    return true;
  }

  if (message.type === 'checkCode') {
    console.log('Received checkCode message:', message.code);
    getAuthToken()
      .then((token) => {
        checkCodeSafety(message.code, token)
          .then(({ isSafe, positives }) => {
            console.log('Code safety check complete, isSafe:', isSafe, 'positives:', positives);
            sendResponse({ isSafe });
            if (!sentNotifications.codeSafety[simpleHash(message.code)]) {
              chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon.png',
                title: 'CyberGuard: Code Safety',
                message: isSafe ? '✅ Code is safe to copy.' : `⚠️ Unsafe code detected! (${positives} detections)`,
                priority: 1
              }, (notificationId) => {
                if (chrome.runtime.lastError) {
                  console.error('Code safety notification error:', chrome.runtime.lastError.message);
                } else {
                  console.log('Code safety notification created:', notificationId);
                }
              });
              sentNotifications.codeSafety[simpleHash(message.code)] = true;
              console.log('Code safety notification sent:', message.code);
            }
          })
          .catch((error) => {
            console.error('Error in code safety check:', error.message);
            sendResponse({ isSafe: false });
          });
      })
      .catch((error) => {
        console.error('Authentication error:', error.message);
        sendResponse({ isSafe: false, error: 'Please log in to perform code safety checks.' });
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon.png',
          title: 'CyberGuard Alert',
          message: '⚠️ Please log in to enable code safety checks.',
          priority: 2
        });
      });
    return true;
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    const normalizedUrl = normalizeUrl(tab.url);
    console.log(`Tab updated for URL: ${normalizedUrl}, tabId: ${tabId}`);

    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || tab.url.startsWith('file://')) {
      console.log(`Skipping phishing check for unsupported URL: ${tab.url}`);
      return;
    }

    // Check if user is authenticated before proceeding
    try {
      const authCheck = await new Promise((resolve) => {
        chrome.storage.local.get(['username', 'token'], (result) => {
          if (result.username && result.token) {
            resolve(true);
          } else {
            resolve(false);
          }
        });
      });

      if (!authCheck) {
        console.log('User not authenticated, skipping phishing check for URL:', normalizedUrl);
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon.png',
          title: 'CyberGuard Alert',
          message: '⚠️ Please log in to enable phishing detection.',
          priority: 2
        });
        return;
      }

      Object.keys(phishingCache).forEach(url => {
        if (Date.now() - phishingCache[url].timestamp >= CACHE_TIMEOUT) {
          delete phishingCache[url];
          console.log(`Cleared stale cache entry for URL: ${url}`);
        }
      });

      if (phishingCache.hasOwnProperty(normalizedUrl) && (Date.now() - phishingCache[normalizedUrl].timestamp >= CACHE_TIMEOUT || phishingCache[normalizedUrl].isPhishing === null)) {
        delete phishingCache[normalizedUrl];
      }

      if (phishingCache.hasOwnProperty(normalizedUrl) && (Date.now() - phishingCache[normalizedUrl].timestamp < CACHE_TIMEOUT)) {
        console.log('Using cached phishing result for URL:', normalizedUrl, phishingCache[normalizedUrl].isPhishing);
        setTimeout(() => {
          sendMessageToTab(tabId, {
            type: phishingCache[normalizedUrl].isPhishing ? 'phishing' : 'secure'
          }).catch((error) => {
            console.error('Failed to send cached result to content script from tabs.onUpdated:', error.message);
          });
        }, 2000);
        if (phishingCache[normalizedUrl].isPhishing && !sentNotifications.phishing[tabId]) {
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon.png',
            title: 'CyberGuard Alert',
            message: '⚠️ Phishing site detected!',
            priority: 2
          }, (notificationId) => {
            if (chrome.runtime.lastError) {
              console.error('Phishing notification error:', chrome.runtime.lastError.message);
            } else {
              console.log('Phishing notification created:', notificationId);
            }
          });
          sentNotifications.phishing[tabId] = true;
          console.log('Phishing notification sent for tab:', tabId);
        }
        return;
      }

      const token = await getAuthToken();
      const isPhishing = await checkPhishing(normalizedUrl, token);
      console.log(`tabs.onUpdated checkPhishing result for ${normalizedUrl}: isPhishing = ${isPhishing}`);
      setTimeout(() => {
        sendMessageToTab(tabId, {
          type: isPhishing ? 'phishing' : 'secure'
        }).catch((error) => {
          console.error('Failed to send phishing result to content script from tabs.onUpdated:', error.message);
        });
      }, 2000);

      if (isPhishing && !sentNotifications.phishing[tabId]) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon.png',
          title: 'CyberGuard Alert',
          message: '⚠️ Phishing site detected!',
          priority: 2
        }, (notificationId) => {
          if (chrome.runtime.lastError) {
            console.error('Phishing notification error:', chrome.runtime.lastError.message);
          } else {
            console.log('Phishing notification created:', notificationId);
          }
        });
        sentNotifications.phishing[tabId] = true;
        console.log('Phishing notification sent for tab:', tabId);
      }
    } catch (error) {
      console.error('Error during phishing check in tabs.onUpdated:', error.message);
      phishingCache[normalizedUrl] = {
        isPhishing: true,
        timestamp: Date.now()
      };
      setTimeout(() => {
        sendMessageToTab(tabId, { type: 'phishing' })
          .catch((error) => {
            console.error('Failed to send error status to content script from tabs.onUpdated:', error.message);
          });
      }, 2000);
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon.png',
        title: 'CyberGuard Alert',
        message: '⚠️ Error during phishing check. Please log in again.',
        priority: 2
      });
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete sentNotifications.phishing[tabId];
});