// background.js — PhishNet Service Worker
// Handles extension lifecycle and context menu actions

chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishNet installed');

  // Context menu: analyze selected text
  chrome.contextMenus.create({
    id: 'phishnet-analyze-text',
    title: '🛡 PhishNet: Analyze this text',
    contexts: ['selection']
  });

  // Context menu: analyze link
  chrome.contextMenus.create({
    id: 'phishnet-analyze-link',
    title: '🛡 PhishNet: Check this link',
    contexts: ['link']
  });
});

// Handle context menu clicks — open popup with pre-filled data
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'phishnet-analyze-text' && info.selectionText) {
    chrome.storage.local.set({
      prefill: { type: 'text', value: info.selectionText }
    }, () => {
      chrome.action.openPopup();
    });
  }

  if (info.menuItemId === 'phishnet-analyze-link' && info.linkUrl) {
    chrome.storage.local.set({
      prefill: { type: 'url', value: info.linkUrl }
    }, () => {
      chrome.action.openPopup();
    });
  }
});
