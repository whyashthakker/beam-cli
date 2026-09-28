// installService()/startService() (service.ts) only confirm a launchd plist / systemd unit was
// written and loaded -- not that the collector process it points at actually came up and bound
// its port. This is the real check: poll the collector's own unauthenticated "/" route (the
// studio shell, served before the auth check in server.ts) until it answers or the timeout
// elapses. A background process that crashes on startup (bad Node path, port conflict, ...) will
// never respond here, so callers can report the true state instead of a false "running".
export async function waitForCollectorUp(port: number, timeoutMs = 8000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1500) });
      if (response.ok) return true;
    } catch { /* not up yet, or not up at all -- keep polling until the deadline */ }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  return false;
}
