'use strict';

const {
  app, BrowserWindow, ipcMain, Tray, Menu, nativeImage,
  globalShortcut, screen, dialog, shell,
} = require('electron');
const path = require('path');
const Store = require('electron-store');

// ── Config store ─────────────────────────────────────────
const store = new Store({
  defaults: {
    deviceId:    generateDeviceId(),
    deviceName:  require('os').hostname(),
    apiUrl:      'https://nexdesk-production.up.railway.app',
    signalingUrl:'https://nexdesk-production-12b3.up.railway.app',
    quality:     'balanced',
    startWithOs: false,
    theme:       'dark',
  },
});

// Force update to Railway URLs
store.set('apiUrl', 'https://nexdesk-production.up.railway.app');
store.set('signalingUrl', 'https://nexdesk-production-12b3.up.railway.app');

// ── Windows ──────────────────────────────────────────────
let mainWindow   = null;
let sessionWindow = null;
let tray         = null;
let token        = null;

const isDev = process.env.NODE_ENV === 'development';

// ── Create main window ───────────────────────────────────
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width:  960,
    height: 600,
    minWidth:  860,
    minHeight: 520,
    frame:     false,          // Custom titlebar
    transparent: false,
    backgroundColor: '#0c0c0e',
    show: false,
    webPreferences: {
      preload:              path.join(__dirname, 'preload.js'),
      contextIsolation:     true,
      nodeIntegration:      false,
      webSecurity:          true,
    },
    icon: getAppIcon(),
  });

  mainWindow.loadFile(path.join(__dirname, 'windows', 'home.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (isDev) mainWindow.webContents.openDevTools({ mode: 'detach' });
  });

  mainWindow.on('close', (e) => {
    if (tray) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => { mainWindow = null; });
}

// ── Create session window ────────────────────────────────
function createSessionWindow(sessionData) {
  const { width, height } = screen.getPrimaryDisplay().workAreaSize;

  sessionWindow = new BrowserWindow({
    width:  Math.min(1400, width - 100),
    height: Math.min(900, height - 60),
    minWidth:  800,
    minHeight: 500,
    frame: false,
    backgroundColor: '#080809',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  sessionWindow.loadFile(path.join(__dirname, 'windows', 'session.html'));

  sessionWindow.once('ready-to-show', () => {
    sessionWindow.show();
    sessionWindow.webContents.send('session-init', sessionData);
  });

  sessionWindow.on('closed', () => {
    sessionWindow = null;
    // Notify main window
    if (mainWindow) mainWindow.webContents.send('session-closed');
  });
}

// ── Tray ─────────────────────────────────────────────────
function createTray() {
  const icon = nativeImage.createEmpty();
  tray = new Tray(icon);
  tray.setToolTip('NexDesk');
  updateTray();

  tray.on('click', () => {
    if (mainWindow) {
      mainWindow.isVisible() ? mainWindow.focus() : mainWindow.show();
    } else {
      createMainWindow();
    }
  });
}

function updateTray(sessionCount = 0) {
  if (!tray) return;
  const menu = Menu.buildFromTemplate([
    { label: `NexDesk — ${sessionCount} session(s)`, enabled: false },
    { type: 'separator' },
    { label: 'Ouvrir', click: () => mainWindow?.show() },
    { type: 'separator' },
    { label: 'Quitter', click: () => { tray = null; app.quit(); } },
  ]);
  tray.setContextMenu(menu);
}

// ── IPC Handlers ─────────────────────────────────────────

// Window controls
ipcMain.on('win:minimize', () => mainWindow?.minimize());
ipcMain.on('win:maximize', () => {
  if (!mainWindow) return;
  mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
});
ipcMain.on('win:close', () => mainWindow?.close());
ipcMain.on('session-win:minimize', () => sessionWindow?.minimize());
ipcMain.on('session-win:maximize', () => {
  if (!sessionWindow) return;
  sessionWindow.isMaximized() ? sessionWindow.unmaximize() : sessionWindow.maximize();
});
ipcMain.on('session-win:close', () => sessionWindow?.close());

// Config
ipcMain.handle('config:get', (_, key) => store.get(key));
ipcMain.handle('config:set', (_, key, val) => { store.set(key, val); return true; });
ipcMain.handle('config:all', () => store.store);

// Token management
ipcMain.handle('auth:set-token', (_, t) => { token = t; return true; });
ipcMain.handle('auth:get-token', () => token);

// Open session window
ipcMain.handle('session:open', (_, data) => {
  createSessionWindow(data);
  return true;
});

// Screen capture sources
ipcMain.handle('capture:sources', async () => {
  const { desktopCapturer } = require('electron');
  const sources = await desktopCapturer.getSources({
    types: ['screen'],
    thumbnailSize: { width: 320, height: 180 },
  });
  return sources.map(s => ({
    id: s.id, name: s.name,
    thumbnail: s.thumbnail.toDataURL(),
  }));
});

// Get monitors
ipcMain.handle('capture:monitors', () => {
  return screen.getAllDisplays().map((d, i) => ({
    index: i,
    label: `Écran ${i + 1} (${d.size.width}×${d.size.height})`,
    primary: d.id === screen.getPrimaryDisplay().id,
    bounds: d.bounds,
  }));
});

// File dialog
ipcMain.handle('dialog:open-file', async () => {
  if (!mainWindow && !sessionWindow) return null;
  const win = sessionWindow || mainWindow;
  const result = await dialog.showOpenDialog(win, {
    properties: ['openFile', 'multiSelections'],
  });
  return result.canceled ? null : result.filePaths;
});

// Open external URL
ipcMain.on('open-external', (_, url) => shell.openExternal(url));


// ── App lifecycle ────────────────────────────────────────
app.whenReady().then(() => {
  createMainWindow();
  createTray();

  // Global shortcut — restore main window
  globalShortcut.register('CommandOrControl+Shift+N', () => {
    if (mainWindow) { mainWindow.show(); mainWindow.focus(); }
    else createMainWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin' && !tray) app.quit();
});

app.on('activate', () => {
  if (!mainWindow) createMainWindow();
  else mainWindow.show();
});

app.on('will-quit', () => {
  globalShortcut.unregisterAll();
});

// ── Helpers ──────────────────────────────────────────────
function generateDeviceId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from({ length: 3 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `${seg()}-${seg()}-${seg()}`;
}

function getAppIcon() {
  try {
    return path.join(__dirname, '..', 'build', 'icon.png');
  } catch {
    return undefined;
  }
}
