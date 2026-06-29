/*
 Copyright 2026 NXP
 SPDX-License-Identifier: BSD-3-Clause

*/

// src/agent/web/static/app.js
// ============================================================================
// WebSocket Manager
// ============================================================================
class WebSocketManager {
    constructor(eventBus) {
        this.eventBus = eventBus;
        this.ws = null;
        this.reconnectInterval = null;
        this.pingInterval = null;
        this.reconnectDelay = 5000;
        this.pingDelay = 30000;
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        this.ws = new WebSocket(wsUrl);
        this.ws.onopen = () => this.handleOpen();
        this.ws.onmessage = (event) => this.handleMessage(event);
        this.ws.onclose = () => this.handleClose();
        this.ws.onerror = (error) => this.handleError(error);
    }

    handleOpen() {
        console.log('WebSocket connected');
        this.eventBus.emit('ws:connected');
        this.clearReconnectInterval();
        this.startPingInterval();
    }

    handleMessage(event) {
        try {
            const data = JSON.parse(event.data);
            this.eventBus.emit(`ws:${data.type}`, data.data);
        } catch (error) {
            console.error('Error parsing WebSocket message:', error);
        }
    }

    handleClose() {
        console.log('WebSocket disconnected');
        this.eventBus.emit('ws:disconnected');
        this.stopPingInterval();
        this.attemptReconnect();
    }

    handleError(error) {
        console.error('WebSocket error:', error);
        this.eventBus.emit('ws:error', error);
    }

    send(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(typeof message === 'string' ? message : JSON.stringify(message));
        }
    }

    startPingInterval() {
        this.pingInterval = setInterval(() => {
            this.send('ping');
        }, this.pingDelay);
    }

    stopPingInterval() {
        if (this.pingInterval) {
            clearInterval(this.pingInterval);
            this.pingInterval = null;
        }
    }

    attemptReconnect() {
        if (!this.reconnectInterval) {
            this.reconnectInterval = setInterval(() => {
                console.log('Attempting to reconnect...');
                this.connect();
            }, this.reconnectDelay);
        }
    }

    clearReconnectInterval() {
        if (this.reconnectInterval) {
            clearInterval(this.reconnectInterval);
            this.reconnectInterval = null;
        }
    }

    disconnect() {
        this.clearReconnectInterval();
        this.stopPingInterval();
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

// ============================================================================
// Event Bus - Simple pub/sub pattern
// ============================================================================
class EventBus {
    constructor() {
        this.listeners = {};
    }

    on(event, callback) {
        if (!this.listeners[event]) {
            this.listeners[event] = [];
        }
        this.listeners[event].push(callback);
    }

    off(event, callback) {
        if (!this.listeners[event]) return;
        this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
    }

    emit(event, data) {
        if (!this.listeners[event]) return;
        this.listeners[event].forEach(callback => callback(data));
    }
}

// ============================================================================
// API Client
// ============================================================================
class ApiClient {
    constructor(baseUrl = '/api') {
        this.baseUrl = baseUrl;
    }

    async get(endpoint, params = {}) {
        const url = new URL(`${window.location.origin}${this.baseUrl}${endpoint}`);
        Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));
        
        const response = await fetch(url);
        return this.handleResponse(response);
    }

    async post(endpoint, data = {}) {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return this.handleResponse(response);
    }

    async handleResponse(response) {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }
}

// ============================================================================
// Utility Classes
// ============================================================================
class DateFormatter {
    static formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        return date.toLocaleString();
    }

    static formatTimeAgo(timestamp) {
        if (!timestamp) return 'N/A';
        
        const now = new Date();
        const time = new Date(timestamp);
        const diffMs = now - time;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        
        return time.toLocaleDateString();
    }
}

class AnomalyFormatter {
    static formatType(type) {
        const typeMap = {
            'duplicate_ip': 'Duplicate IP Address',
            'duplicate_instance': 'Duplicate Device Instance',
            'multi_instance_ip': 'Multi-Instance IP',
            'mac_multi_ip': 'MAC with Multiple IPs',
            'arp_conflict': 'ARP Conflict'
        };
        return typeMap[type] || type;
    }
}

// ============================================================================
// Connection Status Manager
// ============================================================================
class ConnectionStatusManager {
    constructor(statusDotId, statusTextId) {
        this.statusDot = document.getElementById(statusDotId);
        this.statusText = document.getElementById(statusTextId);
    }

    setConnected() {
        if (this.statusDot) this.statusDot.classList.add('connected');
        if (this.statusText) this.statusText.textContent = 'Connected';
    }

    setDisconnected() {
        if (this.statusDot) this.statusDot.classList.remove('connected');
        if (this.statusText) this.statusText.textContent = 'Disconnected';
    }
}

// ============================================================================
// Navigation Manager
// ============================================================================
class NavigationManager {
    constructor(eventBus) {
        this.eventBus = eventBus;
        this.navItems = document.querySelectorAll('.nav-item');
        this.views = document.querySelectorAll('.view');
        this.activeView = null;
        this.initialize();
    }

    initialize() {
        this.navItems.forEach(item => {
            item.addEventListener('click', (e) => this.handleNavClick(e, item));
        });
    }

    handleNavClick(e, item) {
        e.preventDefault();
        const viewName = item.dataset.view;
        this.showView(viewName);
    }

    showView(viewName) {
        // Update navigation
        this.navItems.forEach(nav => nav.classList.remove('active'));
        const activeNav = document.querySelector(`[data-view="${viewName}"]`);
        if (activeNav) activeNav.classList.add('active');

        // Update views
        this.views.forEach(view => view.classList.remove('active'));
        const targetView = document.getElementById(`${viewName}-view`);
        
        if (targetView) {
            targetView.classList.add('active');
            this.activeView = viewName;
            this.eventBus.emit('view:changed', viewName);
        }
    }

    getActiveView() {
        return this.activeView;
    }
}

// ============================================================================
// Base View Controller
// ============================================================================
class BaseViewController {
    constructor(apiClient, eventBus) {
        this.apiClient = apiClient;
        this.eventBus = eventBus;
        this.isLoading = false;
    }

    showLoading(container, message = 'Loading...') {
        if (container) {
            container.innerHTML = `<div class="loading">${message}</div>`;
        }
    }

    showError(container, message = 'Error loading data') {
        if (container) {
            container.innerHTML = `<div class="loading">${message}</div>`;
        }
    }
}

// ============================================================================
// Dashboard Controller
// ============================================================================
class DashboardController extends BaseViewController {
    constructor(apiClient, eventBus) {
        super(apiClient, eventBus);
        this.autoRefreshInterval = null;
        this.refreshDelay = 30000;
    }

    async load() {
        if (this.isLoading) return;
        this.isLoading = true;

        try {
            const [statsData, anomaliesData] = await Promise.all([
                this.apiClient.get('/statistics'),
                this.apiClient.get('/anomalies', { limit: 5 })
            ]);

            if (statsData.status === 'success') {
                this.updateStatistics(statsData.statistics);
            }

            if (anomaliesData.status === 'success') {
                this.displayRecentAnomalies(anomaliesData.anomalies);
            }
        } catch (error) {
            console.error('Error loading dashboard:', error);
        } finally {
            this.isLoading = false;
        }
    }

    updateStatistics(stats) {
        this.updateElement('totalDevices', stats.total_devices || 0);
        this.updateElement('totalAnomalies', stats.total_anomalies || 0);
        this.updateElement('recentAnomalies', stats.recent_anomalies_24h || 0);

        const networkStatus = this.calculateNetworkStatus(stats.recent_anomalies_24h);
        this.updateElement('networkStatus', networkStatus);
    }

    calculateNetworkStatus(recentAnomalies) {
        if (recentAnomalies > 10) return 'At Risk';
        if (recentAnomalies > 0) return 'Warning';
        return 'Healthy';
    }

    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }

    displayRecentAnomalies(anomalies) {
        const container = document.getElementById('recentAnomaliesList');
        if (!container) return;

        if (anomalies.length === 0) {
            this.showLoading(container, 'No anomalies detected');
            return;
        }

        container.innerHTML = anomalies.map(anomaly => this.renderAnomalyItem(anomaly)).join('');
    }

    renderAnomalyItem(anomaly) {
        return `
            <div class="anomaly-item ${anomaly.severity}">
                <div class="anomaly-header">
                    <span class="anomaly-type">${AnomalyFormatter.formatType(anomaly.anomaly_type)}</span>
                    <span class="anomaly-severity severity-${anomaly.severity}">${anomaly.severity}</span>
                </div>
                <div class="anomaly-description">${anomaly.description}</div>
                <div class="anomaly-meta">
                    <span><i class="fas fa-clock"></i> ${DateFormatter.formatTimestamp(anomaly.timestamp)}</span>
                    <span><i class="fas fa-file"></i> ${anomaly.source_file || 'N/A'}</span>
                </div>
            </div>
        `;
    }

    startAutoRefresh() {
        this.stopAutoRefresh();
        this.autoRefreshInterval = setInterval(() => this.load(), this.refreshDelay);
    }

    stopAutoRefresh() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
            this.autoRefreshInterval = null;
        }
    }

    refresh() {
        this.load();
    }
}

// ============================================================================
// Devices Controller
// ============================================================================
class DevicesController extends BaseViewController {
    constructor(apiClient, eventBus) {
        super(apiClient, eventBus);
        this.containerId = 'devicesTable';
    }

    async load() {
        const container = document.getElementById(this.containerId);
        this.showLoading(container, 'Loading devices...');

        try {
            const data = await this.apiClient.get('/devices');

            if (data.status === 'success') {
                this.displayDevices(data.devices);
            }
        } catch (error) {
            console.error('Error loading devices:', error);
            this.showError(container, 'Error loading devices');
        }
    }

    displayDevices(devices) {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        if (devices.length === 0) {
            this.showLoading(container, 'No devices discovered');
            return;
        }

        container.innerHTML = `
            <table>
                <thead>
                    <tr>
                        <th>Instance</th>
                        <th>IP Addresses</th>
                        <th>MAC Addresses</th>
                        <th>MS/TP</th>
                        <th>Last Seen</th>
                        <th>Packets</th>
                    </tr>
                </thead>
                <tbody>
                    ${devices.map(device => this.renderDeviceRow(device)).join('')}
                </tbody>
            </table>
        `;
    }

    renderDeviceRow(device) {
        return `
            <tr>
                <td><strong>${device.instance_number}</strong></td>
                <td>${device.ip_addresses.join(', ') || 'N/A'}</td>
                <td>${device.mac_addresses.join(', ') || 'N/A'}</td>
                <td>${device.mstp_addresses.join(', ') || 'N/A'}</td>
                <td>${DateFormatter.formatTimestamp(device.last_seen)}</td>
                <td>${device.packet_count}</td>
            </tr>
        `;
    }

    refresh() {
        this.load();
    }
}

// ============================================================================
// Anomalies Controller
// ============================================================================
class AnomaliesController extends BaseViewController {
    constructor(apiClient, eventBus) {
        super(apiClient, eventBus);
        this.containerId = 'anomaliesTable';
        this.filterElementId = 'anomalyTypeFilter';
        this.limit = 100;
        this.initializeFilters();
    }

    initializeFilters() {
        const filterElement = document.getElementById(this.filterElementId);
        if (filterElement) {
            filterElement.addEventListener('change', () => this.load());
        }
    }

    async load() {
        const container = document.getElementById(this.containerId);
        this.showLoading(container, 'Loading anomalies...');

        const typeFilter = this.getFilterValue();
        const params = { limit: this.limit };
        if (typeFilter) params.anomaly_type = typeFilter;

        try {
            const data = await this.apiClient.get('/anomalies', params);

            if (data.status === 'success') {
                this.displayAnomalies(data.anomalies);
            }
        } catch (error) {
            console.error('Error loading anomalies:', error);
            this.showError(container, 'Error loading anomalies');
        }
    }

    getFilterValue() {
        const filterElement = document.getElementById(this.filterElementId);
        return filterElement ? filterElement.value : '';
    }

    displayAnomalies(anomalies) {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        if (anomalies.length === 0) {
            this.showLoading(container, 'No anomalies found');
            return;
        }

        container.innerHTML = `
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>Source File</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    ${anomalies.map(anomaly => this.renderAnomalyRow(anomaly)).join('')}
                </tbody>
            </table>
        `;
    }

    renderAnomalyRow(anomaly) {
        return `
            <tr>
                <td>${AnomalyFormatter.formatType(anomaly.anomaly_type)}</td>
                <td><span class="anomaly-severity severity-${anomaly.severity}">${anomaly.severity}</span></td>
                <td>${anomaly.description}</td>
                <td>${anomaly.source_file || 'N/A'}</td>
                <td>${DateFormatter.formatTimestamp(anomaly.timestamp)}</td>
            </tr>
        `;
    }

    refresh() {
        this.load();
    }
}

// ============================================================================
// Chat Controller
// ============================================================================
class ChatController extends BaseViewController {
    constructor(apiClient, eventBus) {
        super(apiClient, eventBus);
        this.inputId = 'chatInput';
        this.messagesContainerId = 'chatMessages';
        this.typingIndicatorCounter = 0;
        this.initializeInput();
        this.initializeMarkdown();
    }

    initializeMarkdown() {
        if (typeof marked !== 'undefined') {
            marked.setOptions({
                breaks: true,
                gfm: true,
                headerIds: false,
                mangle: false,
            });
            console.log('Markdown renderer initialized');
        } else {
            console.warn('marked.js not loaded — markdown will not be rendered');
        }
    }

    renderMarkdown(text) {
        if (typeof marked !== 'undefined' && typeof DOMPurify !== 'undefined') {
            const rawHtml = marked.parse(text);
            return DOMPurify.sanitize(rawHtml);
        }
        // Fallback: escape HTML and preserve newlines
        const escaped = text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
        return escaped.replace(/\n/g, '<br>');
    }

    initializeInput() {
        const input = document.getElementById(this.inputId);
        if (input) {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.sendMessage();
            });
        }
    }

    async sendMessage() {
        const input = document.getElementById(this.inputId);
        if (!input) return;

        const message = input.value.trim();
        if (!message) return;

        this.addMessage('user', message);
        input.value = '';

        // Create a streaming assistant bubble with a typing indicator
        const { messageDiv, textEl } = this.createStreamingBubble();
        const container = document.getElementById(this.messagesContainerId);

        let accumulatedText = '';
        let receivedFirstChunk = false;
        let lastIndex = 0;

        try {
            const response = await fetch('/api/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: message })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const chunks = buffer.split('\n\n');
                buffer = chunks.pop(); // keep the last incomplete chunk

                for (const chunk of chunks) {
                    const trimmed = chunk.trim();
                    if (!trimmed.startsWith('data: ')) continue;

                    try {
                        const data = JSON.parse(trimmed.slice(6));

                        if (data.type === 'tool_call') {
                            this.addToolCallMessage(data.tool_name, data.tool_args);

                            lastIndex = accumulatedText.length;

                        } else if (data.type === 'tool_response') {
                            this.addToolResponseMessage(data.tool_name);
                        } else if (data.type === 'text_chunk') {
                            if (!receivedFirstChunk) {
                                // Clear the typing indicator on first real text
                                receivedFirstChunk = true;
                            }
                            
                            const newText = data.text;
                            
                            if(newText.length >= accumulatedText.length - lastIndex) {
                                const endOfAccumulated = accumulatedText.slice(-newText.length);
                                if (endOfAccumulated === newText) {
                                    // Skip this chunk as it's already in accumulated text
                                    continue;
                                }
                                
                            }
                            
                            accumulatedText += newText;
                            textEl.innerHTML = this.renderMarkdown(accumulatedText);
                            if (container) container.scrollTop = container.scrollHeight;
                        } else if (data.type === 'final_response') {
                            // Only render final_response if we haven't accumulated text
                            if (!accumulatedText) {
                                textEl.innerHTML = this.renderMarkdown(data.response);
                            }
                            // Update timestamp
                            const timeEl = messageDiv.querySelector('.message-time');
                            if (timeEl) timeEl.textContent = new Date().toLocaleTimeString();
                            if (container) container.scrollTop = container.scrollHeight;
                        } else if (data.type === 'error') {
                            textEl.innerHTML = this.renderMarkdown(
                                'Sorry, an error occurred while processing your request.'
                            );
                        }
                    } catch (parseError) {
                        console.error('Error parsing SSE data:', parseError);
                    }
                }
            }

            // Safety net: if stream ended without a final_response, make sure
            // we render whatever we accumulated
            if (accumulatedText && !receivedFirstChunk) {
                textEl.innerHTML = this.renderMarkdown(accumulatedText);
            }

        } catch (error) {
            console.error('Error sending message:', error);
            textEl.innerHTML = this.renderMarkdown(
                'Sorry, I encountered an error processing your request.'
            );
        }
    }

    /**
     * Create an assistant message bubble pre-filled with a typing indicator.
     * Returns references to the outer div and the inner text element so
     * we can update them as text_chunk events arrive.
     */
    createStreamingBubble() {
        const container = document.getElementById(this.messagesContainerId);

        const messageDiv = document.createElement('div');
        messageDiv.className = 'chat-message agent streaming';

        const timestamp = new Date().toLocaleTimeString();

        messageDiv.innerHTML = `
            <div class="message-avatar">
                <i class="fas fa-robot"></i>
            </div>
            <div class="message-content">
                <div class="message-text markdown-body">
                    <span class="typing-dots">
                        <i class="fas fa-circle"></i>
                        <i class="fas fa-circle"></i>
                        <i class="fas fa-circle"></i>
                    </span>
                </div>
                <div class="message-time">${timestamp}</div>
            </div>
        `;

        if (container) {
            container.appendChild(messageDiv);
            container.scrollTop = container.scrollHeight;
        }

        const textEl = messageDiv.querySelector('.message-text');
        return { messageDiv, textEl };
    }

    addMessage(role, text) {
        const container = document.getElementById(this.messagesContainerId);
        if (!container) return;

        const timestamp = new Date().toLocaleTimeString();
        const renderedContent = role === 'agent'
            ? this.renderMarkdown(text)
            : this.escapeHtml(text);

        const messageDiv = document.createElement('div');
        messageDiv.className = `chat-message ${role}`;
        messageDiv.innerHTML = `
            <div class="message-avatar">
                <i class="fas fa-${role === 'user' ? 'user' : 'robot'}"></i>
            </div>
            <div class="message-content">
                <div class="message-text markdown-body">${renderedContent}</div>
                <div class="message-time">${timestamp}</div>
            </div>
        `;

        container.appendChild(messageDiv);
        container.scrollTop = container.scrollHeight;
    }

    addToolCallMessage(toolName, toolArgs) {
        const container = document.getElementById(this.messagesContainerId);
        if (!container) return;

        const argsDisplay = toolArgs && Object.keys(toolArgs).length > 0
            ? `\n> **Parameters:** \`${JSON.stringify(toolArgs)}\``
            : '';
        const mdContent = `🔧 **Calling tool:** \`${toolName}\`${argsDisplay}`;

        const messageDiv = document.createElement('div');
        messageDiv.className = 'chat-message agent tool-call';
        messageDiv.innerHTML = `
            <div class="message-avatar">
                <i class="fas fa-cog fa-spin"></i>
            </div>
            <div class="message-content">
                <div class="message-text markdown-body tool-call-body">${this.renderMarkdown(mdContent)}</div>
            </div>
        `;

        container.appendChild(messageDiv);
        container.scrollTop = container.scrollHeight;
    }

    addToolResponseMessage(toolName) {
        const container = document.getElementById(this.messagesContainerId);
        if (!container) return;

        const mdContent = `✅ **Response received** from \`${toolName}\``;

        const messageDiv = document.createElement('div');
        messageDiv.className = 'chat-message agent tool-response';
        messageDiv.innerHTML = `
            <div class="message-avatar">
                <i class="fas fa-check-circle"></i>
            </div>
            <div class="message-content">
                <div class="message-text markdown-body tool-response-body">${this.renderMarkdown(mdContent)}</div>
            </div>
        `;

        container.appendChild(messageDiv);
        container.scrollTop = container.scrollHeight;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    addTypingIndicator() {
        const container = document.getElementById(this.messagesContainerId);
        if (!container) return null;

        const id = `typing-${Date.now()}-${this.typingIndicatorCounter++}`;
        const typingDiv = document.createElement('div');
        typingDiv.id = id;
        typingDiv.className = 'chat-message agent typing-indicator';
        typingDiv.innerHTML = `
            <div class="message-avatar">
                <i class="fas fa-robot"></i>
            </div>
            <div class="message-content">
                <div class="message-text">
                    <i class="fas fa-circle"></i>
                    <i class="fas fa-circle"></i>
                    <i class="fas fa-circle"></i>
                </div>
            </div>
        `;

        container.appendChild(typingDiv);
        container.scrollTop = container.scrollHeight;

        return id;
    }

    removeTypingIndicator(id) {
        const element = document.getElementById(id);
        if (element) element.remove();
    }

    handleAnomalyWithAnalysis(agentAnalysis) {
        this.addMessage('agent', `🚨 **New Anomaly Detected:**\n\n${agentAnalysis}`);
    }
}

// ============================================================================
// Notification Manager
// ============================================================================
class NotificationManager {
    constructor(toastId) {
        this.toast = document.getElementById(toastId);
        this.messageElement = this.toast?.querySelector('.toast-message');
        this.autoHideDelay = 10000;
        this.currentTimeout = null;
    }

    show(message) {
        if (!this.toast || !this.messageElement) return;

        this.messageElement.textContent = message;
        this.toast.classList.add('show');

        this.clearAutoHide();
        this.currentTimeout = setTimeout(() => this.hide(), this.autoHideDelay);
    }

    hide() {
        if (this.toast) {
            this.toast.classList.remove('show');
        }
        this.clearAutoHide();
    }

    clearAutoHide() {
        if (this.currentTimeout) {
            clearTimeout(this.currentTimeout);
            this.currentTimeout = null;
        }
    }
}

// ============================================================================
// WhatsApp Panel Manager
// ============================================================================
class WhatsAppPanelManager {
    constructor(eventBus) {
        this.eventBus = eventBus;
        this.notifications = [];
        this.isCollapsed = false;
        this.maxNotifications = 50;
        this.panelId = 'whatsappPanel';
        this.messagesContainerId = 'whatsappMessages';
        this.badgeId = 'notificationBadge';
        this.toggleIconId = 'panelToggleIcon';
    }

    addNotification(anomaly) {
        this.notifications.unshift(anomaly);

        if (this.notifications.length > this.maxNotifications) {
            this.notifications = this.notifications.slice(0, this.maxNotifications);
        }

        this.render();
        this.updateBadge();
        this.pulseIfCollapsed();
    }

    setNotifications(notifications) {
        this.notifications = notifications.slice(0, this.maxNotifications);
        this.render();
        this.updateBadge();
    }

    render() {
        const container = document.getElementById(this.messagesContainerId);
        if (!container) return;

        if (this.notifications.length === 0) {
            container.innerHTML = this.renderEmptyState();
            return;
        }

        container.innerHTML = this.notifications
            .map(anomaly => this.renderNotification(anomaly))
            .join('');
    }

    renderEmptyState() {
        return `
            <div class="whatsapp-empty">
                <i class="fas fa-shield-alt"></i>
                <p>No anomalies detected</p>
                <small>You'll be notified here when anomalies are found</small>
            </div>
        `;
    }

    renderNotification(anomaly) {
        return `
            <div class="whatsapp-message ${anomaly.severity}" onclick="window.app.viewAnomalyDetails('${anomaly.id}')">
                <div class="whatsapp-message-header">
                    <div class="whatsapp-message-type">
                        <i class="fas fa-exclamation-triangle"></i>
                        ${AnomalyFormatter.formatType(anomaly.anomaly_type)}
                    </div>
                    <span class="whatsapp-message-severity severity-${anomaly.severity}">
                        ${anomaly.severity}
                    </span>
                </div>
                <div class="whatsapp-message-text">
                    ${anomaly.description}
                </div>
                <div class="whatsapp-message-footer">
                    <div class="whatsapp-message-time">
                        <i class="fas fa-clock"></i>
                        ${DateFormatter.formatTimeAgo(anomaly.timestamp)}
                    </div>
                    <div class="whatsapp-message-source" title="${anomaly.source_file || 'N/A'}">
                        <i class="fas fa-file"></i>
                        ${this.getFileName(anomaly.source_file)}
                    </div>
                </div>
            </div>
        `;
    }

    getFileName(filePath) {
        if (!filePath) return 'N/A';
        return filePath.split('/').pop();
    }

    updateBadge() {
        const badge = document.getElementById(this.badgeId);
        if (!badge) return;

        const count = this.notifications.length;

        if (count > 0) {
            badge.textContent = count > 99 ? '99+' : count;
            badge.style.display = 'inline-block';
        } else {
            badge.textContent = '0';
            badge.style.display = 'none';
        }
    }

    toggle() {
        const panel = document.getElementById(this.panelId);
        const icon = document.getElementById(this.toggleIconId);
        if (!panel || !icon) return;

        this.isCollapsed = !this.isCollapsed;

        if (this.isCollapsed) {
            panel.classList.add('collapsed');
            icon.classList.remove('fa-chevron-right');
            icon.classList.add('fa-chevron-left');
        } else {
            panel.classList.remove('collapsed');
            icon.classList.remove('fa-chevron-left');
            icon.classList.add('fa-chevron-right');
        }
    }

    pulseIfCollapsed() {
        if (!this.isCollapsed) return;

        const panel = document.getElementById(this.panelId);
        if (!panel) return;

        panel.classList.add('pulse-notification');
        setTimeout(() => panel.classList.remove('pulse-notification'), 1000);
    }
}

// ============================================================================
// Main Application
// ============================================================================
class Application {
    constructor() {
        this.eventBus = new EventBus();
        this.apiClient = new ApiClient('/api');
        this.wsManager = new WebSocketManager(this.eventBus);
        this.connectionStatus = new ConnectionStatusManager('connectionStatus', 'connectionText');
        this.navigationManager = new NavigationManager(this.eventBus);
        this.notificationManager = new NotificationManager('notificationToast');
        this.whatsappPanel = new WhatsAppPanelManager(this.eventBus);
        
        // Controllers
        this.dashboardController = new DashboardController(this.apiClient, this.eventBus);
        this.devicesController = new DevicesController(this.apiClient, this.eventBus);
        this.anomaliesController = new AnomaliesController(this.apiClient, this.eventBus);
        this.chatController = new ChatController(this.apiClient, this.eventBus);

        this.setupEventListeners();
        this.initialize();
    }

    setupEventListeners() {
        // WebSocket events
        this.eventBus.on('ws:connected', () => this.connectionStatus.setConnected());
        this.eventBus.on('ws:disconnected', () => this.connectionStatus.setDisconnected());
        this.eventBus.on('ws:anomaly', (data) => this.handleAnomalyNotification(data));

        // View change events
        this.eventBus.on('view:changed', (viewName) => this.handleViewChanged(viewName));
    }

    initialize() {
        this.wsManager.connect();
        this.navigationManager.showView('dashboard');
        //this.loadInitialNotifications();
    }

    handleViewChanged(viewName) {
        switch (viewName) {
            case 'dashboard':
                this.dashboardController.load();
                this.dashboardController.startAutoRefresh();
                break;
            case 'devices':
                this.dashboardController.stopAutoRefresh();
                this.devicesController.load();
                break;
            case 'anomalies':
                this.dashboardController.stopAutoRefresh();
                this.anomaliesController.load();
                break;
            case 'agent':
                this.dashboardController.stopAutoRefresh();
                break;
        }
    }

    handleAnomalyNotification(data) {
        const anomaly = data.anomaly;

        // Add to WhatsApp panel
        this.whatsappPanel.addNotification(anomaly);

        // Show toast notification
        this.notificationManager.show(anomaly.description);

        // Refresh dashboard if active
        if (this.navigationManager.getActiveView() === 'dashboard') {
            this.dashboardController.refresh();
        }

        // Add to chat if agent view is active and analysis is available
        if (this.navigationManager.getActiveView() === 'agent' && data.agent_analysis) {
            this.chatController.handleAnomalyWithAnalysis(data.agent_analysis);
        }
    }

    async loadInitialNotifications() {
        try {
            const data = await this.apiClient.get('/anomalies', { limit: 20 });

            if (data.status === 'success' && data.anomalies.length > 0) {
                this.whatsappPanel.setNotifications(data.anomalies);
            }
        } catch (error) {
            console.error('Error loading initial notifications:', error);
        }
    }

    viewAnomalyDetails(anomalyId) {
        this.navigationManager.showView('anomalies');
    }

    // Public methods for global access (called from HTML)
    refreshDashboard() {
        this.dashboardController.refresh();
    }

    refreshDevices() {
        this.devicesController.refresh();
    }

    refreshAnomalies() {
        this.anomaliesController.refresh();
    }

    filterAnomalies() {
        this.anomaliesController.load();
    }

    sendChatMessage() {
        this.chatController.sendMessage();
    }

    handleChatKeyPress(event) {
        if (event.key === 'Enter') {
            this.chatController.sendMessage();
        }
    }

    toggleWhatsAppPanel() {
        this.whatsappPanel.toggle();
    }

    closeToast() {
        this.notificationManager.hide();
    }
}

// ============================================================================
// Application Initialization
// ============================================================================
let app;

document.addEventListener('DOMContentLoaded', () => {
    app = new Application();
    window.app = app; // Make app globally accessible for inline event handlers
});
