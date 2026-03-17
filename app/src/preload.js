'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // Window controls
  win: {
    minimize: ()      => ipcRenderer.send('win:minimize'),
    maximize: ()      => ipcRenderer.send('win:maximize'),
    close:    ()      => ipcRenderer.send('win:close'),
  },
  sessionWin: {
    minimize: ()      => ipcRenderer.send('session-win:minimize'),
    maximize: ()      => ipcRenderer.send('session-win:maximize'),
    close:    ()      => ipcRenderer.send('session-win:close'),
  },

  // Config
  config: {
    get:  (key)       => ipcRenderer.invoke('config:get', key),
    set:  (key, val)  => ipcRenderer.invoke('config:set', key, val),
    all:  ()          => ipcRenderer.invoke('config:all'),
  },

  // Auth token
  auth: {
    setToken: (t)     => ipcRenderer.invoke('auth:set-token', t),
    getToken: ()      => ipcRenderer.invoke('auth:get-token'),
  },

  // Session window
  session: {
    open:     (data)  => ipcRenderer.invoke('session:open', data),
    onInit:   (cb)    => ipcRenderer.on('session-init',   (_, d) => cb(d)),
    onClosed: (cb)    => ipcRenderer.on('session-closed', ()     => cb()),
  },

  // Screen capture
  capture: {
    sources:  ()      => ipcRenderer.invoke('capture:sources'),
    monitors: ()      => ipcRenderer.invoke('capture:monitors'),
  },

  // Dialogs
  dialog: {
    openFile: ()      => ipcRenderer.invoke('dialog:open-file'),
  },

  // External
  openExternal: (url) => ipcRenderer.send('open-external', url),
});
