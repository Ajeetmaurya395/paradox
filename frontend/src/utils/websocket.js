/* Paradox — WebSocket Connection Manager */

import { WS_BASE } from './constants';

export function createScanSocket(scanId, handlers = {}) {
  const url = `${WS_BASE}/ws/scan/${scanId}`;
  let ws = null;
  let reconnectAttempts = 0;
  const maxReconnects = 5;

  function connect() {
    ws = new WebSocket(url);

    ws.onopen = () => {
      reconnectAttempts = 0;
      handlers.onConnect?.();
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handlers.onEvent?.(data);

        // Route to specific handlers
        switch (data.event_type) {
          case 'scan_started': handlers.onScanStarted?.(data); break;
          case 'mode_started': handlers.onModeStarted?.(data); break;
          case 'attack_started': handlers.onAttackStarted?.(data); break;
          case 'check_passed': handlers.onCheckPassed?.(data); break;
          case 'finding': handlers.onFinding?.(data); break;
          case 'tracker_found': handlers.onTrackerFound?.(data); break;
          case 'graph_data': handlers.onGraphData?.(data); break;
          case 'attack_sent': handlers.onAttackSent?.(data); break;
          case 'attack_result': handlers.onAttackResult?.(data); break;
          case 'mode_completed': handlers.onModeCompleted?.(data); break;
          case 'scan_complete': handlers.onScanComplete?.(data); break;
          case 'error': handlers.onError?.(data); break;
          default: break;
        }
      } catch (e) {
        console.error('WebSocket parse error:', e);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      handlers.onError?.({ message: 'WebSocket connection error' });
    };

    ws.onclose = () => {
      handlers.onDisconnect?.();
      if (reconnectAttempts < maxReconnects) {
        reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 10000);
        setTimeout(connect, delay);
      }
    };
  }

  connect();

  return {
    send: (data) => ws?.send(typeof data === 'string' ? data : JSON.stringify(data)),
    close: () => { reconnectAttempts = maxReconnects; ws?.close(); },
    getState: () => ws?.readyState,
  };
}
