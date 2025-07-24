let intervalId; // To store the ID of the interval so we can clear it

// Listen for messages from the main thread
self.onmessage = function(event) {
    const data = event.data;

    if (data.command === 'startPolling') {
        const key = data.key;
        const interval = data.interval || 3000; // Default to 3 seconds if not provided

        // Clear any existing interval to prevent duplicates
        if (intervalId) {
            clearInterval(intervalId);
        }

        intervalId = setInterval(async () => {
            try {
                const response = await fetch(`/messages/${key}`);
                const messagesData = await response.json();
                if (response.ok && messagesData.messages) {
                    // Send the fetched messages back to the main thread
                    self.postMessage({ type: 'messages', messages: messagesData.messages });
                } else {
                    console.error("Worker: Error fetching messages:", messagesData.error || response.status);
                    self.postMessage({ type: 'error', message: messagesData.error || 'Unknown error fetching messages' });
                }
            } catch (error) {
                console.error("Worker: Fetch error:", error);
                self.postMessage({ type: 'error', message: `Network error: ${error.message}` });
            }
        }, interval);

        self.postMessage({ type: 'status', message: `Polling started for key ${key} every ${interval}ms.` });

    } else if (data.command === 'stopPolling') {
        if (intervalId) {
            clearInterval(intervalId);
            intervalId = null;
            self.postMessage({ type: 'status', message: 'Polling stopped.' });
        }
    }
};