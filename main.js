var import_obsidian = require("obsidian");

const DEFAULT_SETTINGS = {
    enableProxy: false,
    httpProxy: "",
    httpsProxy: "",
    socksProxy: "",
    bypassRules: "<local>,127.*,10.*,172.16.*,172.17.*,172.18.*,172.19.*,172.20.*,172.21.*,172.22.*,172.23.*,172.24.*,172.25.*,172.26.*,172.27.*,172.28.*,172.29.*,172.30.*,172.31.*,192.168.*",
    pluginTokens: "persist:surfing-vault-${appId}"
};

var GlobalProxyPlugin = class extends import_obsidian.Plugin {
  async onload() {
    this.loginHandlers = new Map(); // Tracks active login handlers
    await this.loadSettings();
    this.addSettingTab(new GlobalProxySettingTab(this.app, this));
  }
  
  async onunload() {
    await this.disableProxy();
  }
  
  async loadSettings() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    this.sessionMap = {};
    await this.enableProxy();
  }
  
  async saveSettings() {
    await this.saveData(this.settings);
  }
  
  getElectronSession() {
    // Try different ways of obtaining the session module
    try {
      // First try @electron/remote
      const remoteModule = require('@electron/remote');
      if (remoteModule && remoteModule.session) {
        return remoteModule.session;
      }
    } catch (e) {
      // @electron/remote not available
    }
    
    try {
      // Try the legacy remote API
      const electron = require('electron');
      if (electron.remote && electron.remote.session) {
        return electron.remote.session;
      }
    } catch (e) {
      // Legacy API not available either
    }
    
    // Last resort: direct access
    try {
      const { session } = require('electron');
      if (session) {
        return session;
      }
    } catch (e) {
      console.error('Unable to access Electron session API');
    }
    
    return null;
  }
  
  async enableProxy() {
    if (!this.settings.enableProxy) {
      return;
    }
    
    const sessionModule = this.getElectronSession();
    if (!sessionModule) {
      new import_obsidian.Notice('Error: Cannot access Electron session API');
      return;
    }
    
    let sessions = [];
    this.sessionMap.default = sessionModule.defaultSession;
    sessions.push(this.sessionMap.default);
      
    if (this.settings.pluginTokens) {
      let pluginTokens = this.settings.pluginTokens.split("\n");
      for (let token of pluginTokens) {
        if (!token || !token.trim()) {
          continue;
        }
        token = token.trim().replace("${appId}", this.app.appId);
        try {
          let sessionObj = sessionModule.fromPartition(token);
          sessions.push(sessionObj);
          this.sessionMap[token] = sessionObj;
        } catch (e) {
          console.error(`Failed to create session for token: ${token}`, e);
        }
      }
    }

    let proxyRules = this.composeProxyRules();
    let proxyBypassRules = proxyRules ? this.settings.bypassRules : undefined;

    // First set the proxy for all sessions
    for (let session of sessions) {
      try {
        await session.setProxy({ 
          proxyRules: proxyRules || "", 
          proxyBypassRules: proxyBypassRules || "" 
        });
        
        // Then configure authentication
        this.setupProxyAuth(session);
      } catch (e) {
        console.error('Failed to set proxy for session', e);
      }
    }

    // Catch any session Electron creates from here on (webviews, popouts,
    // other browser-style plugins) that we didn't already know to proxy by
    // partition name via pluginTokens.
    const electronApp = this.getElectronApp();
    if (electronApp) {
      if (this.webContentsCreatedHandler) {
        electronApp.removeListener('web-contents-created', this.webContentsCreatedHandler);
      }
      this.webContentsCreatedHandler = (event, contents) => {
        try {
          // Only handle actual embedded browser views (<webview> tags), not
          // Obsidian's/Electron's own short-lived internal webContents --
          // those can be destroyed before the async setProxy() call below
          // resolves, which throws deep inside @electron/remote's IPC layer,
          // outside this function's own try/catch.
          if (contents.getType() !== 'webview') {
            return;
          }
          const newSession = contents.session;
          if (!newSession || sessions.includes(newSession)) {
            return;
          }
          newSession.setProxy({
            proxyRules: proxyRules || "",
            proxyBypassRules: proxyBypassRules || ""
          }).then(() => {
            if (!contents.isDestroyed()) {
              this.setupProxyAuth(newSession);
            }
          }).catch((e) => console.error('Failed to set proxy for new webview session', e));
        } catch (e) {
          console.error('web-contents-created handler failed', e);
        }
      };
      electronApp.on('web-contents-created', this.webContentsCreatedHandler);
    }

    if (proxyRules) {
      new import_obsidian.Notice('Proxy enabled successfully!');
    }
  }
  
  setupProxyAuth(session) {
    // Remove the old handler if one exists
    const oldHandler = this.loginHandlers.get(session);
    if (oldHandler) {
      session.removeListener('login', oldHandler);
      this.loginHandlers.delete(session);
    }
    
    // Get the authentication credentials
    const proxyAuth = this.extractAuthFromSettings();
    
    if (proxyAuth && proxyAuth.username && proxyAuth.password) {
      // Create a new handler
      const loginHandler = (event, webContents, details, authInfo, callback) => {
        // Check that this is a proxy authentication request
        if (authInfo.isProxy) {
          event.preventDefault();
          // Small delay for stability
          setTimeout(() => {
            callback(proxyAuth.username, proxyAuth.password);
          }, 100);
        } else {
          // Not proxy authentication -- pass through
          callback();
        }
      };
      
      session.on('login', loginHandler);
      this.loginHandlers.set(session, loginHandler);
    }
  }
  
  extractAuthFromSettings() {
    const proxies = [
      { type: 'http', value: this.settings.httpProxy },
      { type: 'https', value: this.settings.httpsProxy },
      { type: 'socks', value: this.settings.socksProxy }
    ];
    
    for (const proxy of proxies) {
      if (proxy.value && proxy.value.trim()) {
        // Improved regex for different formats
        // Supports: scheme://user:pass@host:port
        const authMatch = proxy.value.match(/^(\w+):\/\/([^:@]+):([^@]+)@([^:]+):(\d+)$/);
        if (authMatch) {
          return {
            scheme: authMatch[1],
            username: decodeURIComponent(authMatch[2]),
            password: decodeURIComponent(authMatch[3]),
            host: authMatch[4],
            port: authMatch[5]
          };
        }
        
        // Alternative format without a scheme: user:pass@host:port
        const simpleAuthMatch = proxy.value.match(/^([^:@]+):([^@]+)@([^:]+):(\d+)$/);
        if (simpleAuthMatch) {
          return {
            scheme: proxy.type,
            username: decodeURIComponent(simpleAuthMatch[1]),
            password: decodeURIComponent(simpleAuthMatch[2]),
            host: simpleAuthMatch[3],
            port: simpleAuthMatch[4]
          };
        }
      }
    }
    return null;
  }

  getElectronApp() {
    try {
      const remoteModule = require('@electron/remote');
      if (remoteModule && remoteModule.app) {
        return remoteModule.app;
      }
    } catch (e) {}

    try {
      const electron = require('electron');
      if (electron.remote && electron.remote.app) {
        return electron.remote.app;
      }
    } catch (e) {}

    try {
      const { app } = require('electron');
      if (app) {
        return app;
      }
    } catch (e) {
      console.error('Unable to access Electron app API');
    }

    return null;
  }

  async disableProxy() {
    const electronApp = this.getElectronApp();
    if (electronApp && this.webContentsCreatedHandler) {
      electronApp.removeListener('web-contents-created', this.webContentsCreatedHandler);
      this.webContentsCreatedHandler = null;
    }

    let sessions = [];
    for (const key in this.sessionMap) {
      if (this.sessionMap[key]) {
        sessions.push(this.sessionMap[key]);
      }
    }
    
    for (let session of sessions) {
      try {
        // Remove the login handler
        const handler = this.loginHandlers.get(session);
        if (handler) {
          session.removeListener('login', handler);
          this.loginHandlers.delete(session);
        }
        
        // Reset the proxy
        await session.setProxy({});
        
        // Close connections to apply the change
        await session.closeAllConnections();
      } catch (e) {
        console.error('Failed to disable proxy for session', e);
      }
    }
    
    new import_obsidian.Notice('Proxy disabled!');
  }
  
  composeProxyRules() {
    // Validate all configured proxies
    const validProxies = ["socksProxy", "httpProxy", "httpsProxy"]
      .every(p => !this.settings[p] || isValidFormat(this.settings[p]));
    
    if (!validProxies) {
      new import_obsidian.Notice('Invalid proxy format detected!');
      return undefined;
    }
    
    // Strip credentials out of the URL
    const stripAuth = (url) => {
      if (!url) return "";
      // Remove user:pass@ from the URL
      return url.replace(/^(\w+):\/\/[^@]+@/, '$1://');
    };
    
    // Build the proxy rules string
    let rules = [];
    
    if (isValidFormat(this.settings.socksProxy)) {
      rules.push(stripAuth(this.settings.socksProxy));
    }
    
    if (isValidFormat(this.settings.httpProxy)) {
      rules.push("http=" + stripAuth(this.settings.httpProxy));
    }
    
    if (isValidFormat(this.settings.httpsProxy)) {
      rules.push("https=" + stripAuth(this.settings.httpsProxy));
    }
    
    if (rules.length === 0) {
      return undefined;
    }
    
    // Append direct:// so bypass-rule matches fall through directly
    return rules.join(";") + ",direct://";
  }
};

var GlobalProxySettingTab = class extends import_obsidian.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  
  display() {
    const { containerEl } = this;
    containerEl.empty();
    
    new import_obsidian.Setting(containerEl)
      .setName("Enable proxy")
      .setDesc("Toggle proxy on/off")
      .addToggle((toggle) => toggle
        .setValue(this.plugin.settings.enableProxy)
        .onChange(async (value) => {
          this.plugin.settings.enableProxy = value;
          await this.plugin.saveSettings();
          if (value) {
            await this.plugin.enableProxy();
          } else {
            await this.plugin.disableProxy();
          }
        }));
    
    new import_obsidian.Setting(containerEl)
      .setName("SOCKS Proxy")
      .setDesc("SOCKS proxy configuration (e.g., socks5://user:pass@host:port)")
      .addText((text) => text
        .setPlaceholder("socks5://[user:pass@]host:port")
        .setValue(this.plugin.settings.socksProxy)
        .onChange(async (value) => {
          await this.refreshProxy("socksProxy", value);
        }));

    new import_obsidian.Setting(containerEl)
      .setName("HTTP Proxy")
      .setDesc("HTTP proxy configuration (e.g., http://user:pass@host:port)")
      .addText((text) => text
        .setPlaceholder("http://[user:pass@]host:port")
        .setValue(this.plugin.settings.httpProxy)
        .onChange(async (value) => {
          await this.refreshProxy("httpProxy", value);
        }));

    new import_obsidian.Setting(containerEl)
      .setName("HTTPS Proxy")
      .setDesc("HTTPS proxy configuration (e.g., http://user:pass@host:port)")
      .addText((text) => text
        .setPlaceholder("http://[user:pass@]host:port")
        .setValue(this.plugin.settings.httpsProxy)
        .onChange(async (value) => {
          await this.refreshProxy("httpsProxy", value);
        }));
    
    new import_obsidian.Setting(containerEl)
      .setName("Plugin Tokens")
      .setDesc("Session tokens for specific plugins (one per line)")
      .addTextArea((text) => text
        .setValue(this.plugin.settings.pluginTokens)
        .onChange(async (value) => {
          await this.refreshProxy("pluginTokens", value);
        }));
    
    new import_obsidian.Setting(containerEl)
      .setName("Bypass Rules")
      .setDesc("Hosts to bypass proxy (comma-separated)")
      .addTextArea((text) => text
        .setPlaceholder("<local>, 192.168.*, *.local")
        .setValue(this.plugin.settings.bypassRules)
        .onChange(async (value) => {
          await this.refreshProxy("bypassRules", value);
        }));
  }
  
  async refreshProxy(key, value) {
    this.plugin.settings[key] = value;
    await this.plugin.saveSettings();
    
    if (this.plugin.settings.enableProxy) {
      await this.plugin.enableProxy();
    }
  }
};

function isValidFormat(proxyUrl) {
  if (!proxyUrl || !proxyUrl.trim()) {
    return false;
  }
  
  // Regex to validate proxy format
  // Supports: scheme://[user:pass@]host:port
  const regex = /^(\w+):\/\/(?:([^:@]+):([^@]+)@)?([^:/]+):(\d+)$/;
  
  // Alternative format without a scheme
  const simpleRegex = /^(?:([^:@]+):([^@]+)@)?([^:/]+):(\d+)$/;
  
  return regex.test(proxyUrl) || simpleRegex.test(proxyUrl);
}

module.exports = GlobalProxyPlugin;
