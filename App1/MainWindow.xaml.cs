using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System.Text.Json;
using System.Threading.Tasks;
using System.Text;
using System.Threading;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text.Json.Serialization;

namespace App1
{
    public sealed partial class MainWindow : Window
    {
        private ClientWebSocket webSocketClient;
        private List<HttpRequestInfo> capturedRequests = new List<HttpRequestInfo>();
        private CancellationTokenSource cts;
        private const int maxRequestsToStore = 100; // Limit to prevent memory issues

        public MainWindow()
        {
            this.InitializeComponent();
        }
        private string TruncateUrl(string url, int maxLength)
        {
            if (string.IsNullOrEmpty(url)) return "unknown";
            return url.Length <= maxLength ? url : url.Substring(0, maxLength) + "...";
        }

        // Renamed class to reflect capturing all HTTP methods, not just PATCH
        public class HttpRequestInfo
        {
            public string Url { get; set; }
            public string Method { get; set; } // GET, POST, PATCH, DELETE, PUT, etc.
            public string CallingType { get; set; }
            public string InitiatorType { get; set; }
            public string StackTrace { get; set; }
            public string RawMessage { get; set; }
            public string Timestamp { get; set; }
            public string RequestId { get; set; }
            public string RequestBody { get; set; }

            public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();

            public override string ToString()
            {
                return $"[{Method}] {Url}\nCalling Type: {CallingType}";
            }
        }

        private async void myButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                myButton.Content = "Connecting...";

                // Cancel any previous monitoring
                if (cts != null)
                {
                    cts.Cancel();
                    cts.Dispose();
                }

                if (webSocketClient != null && webSocketClient.State == WebSocketState.Open)
                {
                    await webSocketClient.CloseAsync(WebSocketCloseStatus.NormalClosure, "User initiated disconnect", CancellationToken.None);
                }

                cts = new CancellationTokenSource();
                webSocketClient = new ClientWebSocket();

                // Setup the path to save the captured requests
                var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                var filePath = Path.Combine(documentsPath, "chrome_http_requests.json");

                // Initialize the file with an empty array if it doesn't exist
                if (!File.Exists(filePath))
                {
                    await File.WriteAllTextAsync(filePath, "[]");
                }
                else
                {
                    // Try to load existing captured requests
                    try
                    {
                        var existingJson = await File.ReadAllTextAsync(filePath);
                        var existingRequests = JsonSerializer.Deserialize<List<HttpRequestInfo>>(existingJson);
                        if (existingRequests != null && existingRequests.Count > 0)
                        {
                            capturedRequests = existingRequests;
                        }
                    }
                    catch
                    {
                        // If we can't read the file, just start fresh
                        capturedRequests = new List<HttpRequestInfo>();
                    }
                }

                // First, get the available tabs from Chrome
                using (var httpClient = new HttpClient())
                {
                    // Get the list of debugging sessions from Chrome
                    var response = await httpClient.GetStringAsync("http://localhost:9222/json");

                    // Log the response for debugging
                    System.Diagnostics.Debug.WriteLine("Chrome session info: " + response);

                    // Parse the JSON response
                    var sessionInfos = JsonSerializer.Deserialize<List<TabInfo>>(response);

                    if (sessionInfos == null || !sessionInfos.Any(s => !string.IsNullOrEmpty(s.webSocketDebuggerUrl)))
                    {
                        ShowErrorMessage("No Chrome tabs available. Make sure Chrome is running with remote debugging enabled.");
                        myButton.Content = "Failed";
                        return;
                    }

                    // Get the first tab with a valid debugging URL (prefer page type over others)
                    var firstTab = sessionInfos.FirstOrDefault(s => s.type == "page" && !string.IsNullOrEmpty(s.webSocketDebuggerUrl)) ??
                                   sessionInfos.First(s => !string.IsNullOrEmpty(s.webSocketDebuggerUrl));

                    myButton.Content = $"Connecting to {firstTab.title}...";

                    // Connect to the WebSocket
                    await webSocketClient.ConnectAsync(new Uri(firstTab.webSocketDebuggerUrl), cts.Token);

                    // Enable Network events
                    var enableNetworkMessage = JsonSerializer.Serialize(new
                    {
                        id = 1,
                        method = "Network.enable"
                    });

                    await SendWebSocketMessage(webSocketClient, enableNetworkMessage, cts.Token);

                    // Log to debug
                    System.Diagnostics.Debug.WriteLine("Connected to Chrome and enabled network monitoring");

                    // Create a background task to listen for messages
                    _ = Task.Run(async () =>
                    {
                        var buffer = new byte[65536]; // Large buffer for complex messages
                        try
                        {
                            while (webSocketClient.State == WebSocketState.Open && !cts.Token.IsCancellationRequested)
                            {
                                var result = await webSocketClient.ReceiveAsync(
                                    new ArraySegment<byte>(buffer), cts.Token);

                                if (result.MessageType == WebSocketMessageType.Text)
                                {
                                    var message = Encoding.UTF8.GetString(buffer, 0, result.Count);

                                    // Enhanced detection of all HTTP requests
                                    try
                                    {
                                        // Parse as a CDP event
                                        using (JsonDocument doc = JsonDocument.Parse(message))
                                        {
                                            // Check if it's a Network.requestWillBeSent event
                                            if (doc.RootElement.TryGetProperty("method", out JsonElement methodElement) &&
                                                methodElement.GetString() == "Network.requestWillBeSent")
                                            {
                                                // Try to extract the request method
                                                if (doc.RootElement.TryGetProperty("params", out JsonElement paramsElement) &&
                                                    paramsElement.TryGetProperty("request", out JsonElement requestElement) &&
                                                    requestElement.TryGetProperty("method", out JsonElement requestMethodElement))
                                                {
                                                    string requestMethod = requestMethodElement.GetString();

                                                    // Include all HTTP methods
                                                    // Create a new HttpRequestInfo to store details
                                                    var requestInfo = new HttpRequestInfo
                                                    {
                                                        Method = requestMethod,
                                                        Url = requestElement.TryGetProperty("url", out JsonElement urlElement) ?
                                                            urlElement.GetString() : "unknown",
                                                        Timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                                                        RawMessage = message
                                                    };

                                                    // Get request ID
                                                    requestInfo.RequestId = paramsElement.TryGetProperty("requestId", out JsonElement requestIdElement) ?
                                                        requestIdElement.GetString() : "";

                                                    // Extract headers
                                                    if (requestElement.TryGetProperty("headers", out JsonElement headersElement))
                                                    {
                                                        foreach (JsonProperty header in headersElement.EnumerateObject())
                                                        {
                                                            requestInfo.Headers[header.Name] = header.Value.ToString();
                                                        }
                                                    }

                                                    // Extract request body if available
                                                    if (requestElement.TryGetProperty("postData", out JsonElement postDataElement))
                                                    {
                                                        requestInfo.RequestBody = postDataElement.GetString();
                                                    }

                                                    // Extract initiator information (calling type)
                                                    if (paramsElement.TryGetProperty("initiator", out JsonElement initiatorElement))
                                                    {
                                                        // Get initiator type
                                                        requestInfo.InitiatorType = initiatorElement.TryGetProperty("type", out JsonElement typeElement) ?
                                                            typeElement.GetString() : "unknown";

                                                        // Set calling type based on initiator type
                                                        requestInfo.CallingType = requestInfo.InitiatorType;

                                                        // If there's a stack trace, extract the calling function
                                                        if (initiatorElement.TryGetProperty("stack", out JsonElement stackElement))
                                                        {
                                                            var callFrames = new StringBuilder();

                                                            if (stackElement.TryGetProperty("callFrames", out JsonElement callFramesElement))
                                                            {
                                                                foreach (var frame in callFramesElement.EnumerateArray().Take(3)) // Take top 3 frames
                                                                {
                                                                    string functionName = frame.TryGetProperty("functionName", out JsonElement funcNameElement) ?
                                                                        funcNameElement.GetString() : "";

                                                                    string scriptId = frame.TryGetProperty("scriptId", out JsonElement scriptIdElement) ?
                                                                        scriptIdElement.GetString() : "";

                                                                    string url = frame.TryGetProperty("url", out JsonElement frameUrlElement) ?
                                                                        frameUrlElement.GetString() : "";

                                                                    if (!string.IsNullOrEmpty(functionName))
                                                                    {
                                                                        callFrames.AppendLine($"{functionName} ({url})");
                                                                    }
                                                                }
                                                            }

                                                            requestInfo.StackTrace = callFrames.ToString();

                                                            // If we have a stack trace, use the first function as calling type
                                                            if (!string.IsNullOrEmpty(requestInfo.StackTrace))
                                                            {
                                                                var firstLine = requestInfo.StackTrace.Split('\n').FirstOrDefault();
                                                                if (!string.IsNullOrEmpty(firstLine))
                                                                {
                                                                    requestInfo.CallingType = firstLine.Trim();
                                                                }
                                                            }
                                                        }
                                                    }

                                                    // Update UI with request method highlighted
                                                    DispatcherQueue.TryEnqueue(() =>
                                                    {
                                                        var methodCounts = capturedRequests
                                                            .GroupBy(r => r.Method)
                                                            .Select(g => $"{g.Key}: {g.Count()}")
                                                            .ToList();

                                                        // Improved UI display with highlighted request methods
                                                        myButton.Content = $"HTTP Requests: {capturedRequests.Count}\n" +
                                                                          $"{string.Join(" | ", methodCounts)}\n" +
                                                                          $"Last: [{requestInfo.Method}] {TruncateUrl(requestInfo.Url, 30)}";

                                                        // Update the text block with more details
                                                        requestCountText.Text = $"Last Request Details:\n" +
                                                                               $"URL: {requestInfo.Url}\n" +
                                                                               $"Method: {requestInfo.Method}\n" +
                                                                               $"Calling Type: {requestInfo.CallingType}\n" +
                                                                               $"Time: {requestInfo.Timestamp}";
                                                    }); ;

                                                    // Capture the request
                                                    capturedRequests.Add(requestInfo);

                                                    // Limit the number of requests to prevent memory issues
                                                    if (capturedRequests.Count > maxRequestsToStore)
                                                    {
                                                        capturedRequests.RemoveRange(0, capturedRequests.Count - maxRequestsToStore);
                                                    }

                                                    // Save to file
                                                    await File.WriteAllTextAsync(filePath,
                                                        JsonSerializer.Serialize(capturedRequests,
                                                        new JsonSerializerOptions { WriteIndented = true }));

                                                    var requestsCopy = new List<HttpRequestInfo>(capturedRequests);
                                                    // Update UI with count by request method
                                                    DispatcherQueue.TryEnqueue(() =>
                                                    {
                                                        try
                                                        {
                                                            var methodCounts = requestsCopy
                                                                .GroupBy(r => r.Method)
                                                                .Select(g => $"{g.Key}: {g.Count()}")
                                                                .ToList();

                                                            // Update button with summary
                                                            myButton.Content = $"Requests: {requestsCopy.Count}\n{string.Join(", ", methodCounts)}";

                                                            // Create a StringBuilder for the detailed list
                                                            var detailedList = new StringBuilder();
                                                            detailedList.AppendLine($"Total Captured Requests: {requestsCopy.Count}");
                                                            detailedList.AppendLine($"Methods: {string.Join(", ", methodCounts)}");
                                                            detailedList.AppendLine();

                                                            // Show the most recent requests first (last 20)
                                                            foreach (var req in requestsCopy.OrderByDescending(r => r.Timestamp).Take(50))
                                                            {
                                                                detailedList.AppendLine($"[{req.Timestamp}] [{req.Method}] {req.Url}");
                                                                detailedList.AppendLine($"  Calling Type: {req.CallingType}");

                                                                if (!string.IsNullOrEmpty(req.RequestBody) && req.RequestBody.Length > 0)
                                                                {
                                                                    var truncatedBody = req.RequestBody.Length > 100
                                                                        ? req.RequestBody.Substring(0, 100) + "..."
                                                                        : req.RequestBody;
                                                                    detailedList.AppendLine($"  Body: {truncatedBody}");
                                                                }

                                                                detailedList.AppendLine(); // Add a blank line between requests
                                                            }

                                                            if (requestsCopy.Count > 50)
                                                            {
                                                                detailedList.AppendLine($"(Showing 50 most recent of {requestsCopy.Count} total requests)");
                                                            }

                                                            // Update the text block with all requests
                                                            requestCountText.Text = detailedList.ToString();
                                                        }
                                                        catch (Exception ex)
                                                        {
                                                            System.Diagnostics.Debug.WriteLine($"UI update error: {ex.Message}");
                                                        }
                                                    });
                                                }
                                            }
                                        }
                                    }
                                    catch (JsonException ex)
                                    {
                                        System.Diagnostics.Debug.WriteLine($"JSON parsing error: {ex.Message}");
                                    }
                                }
                                else if (result.MessageType == WebSocketMessageType.Close)
                                {
                                    DispatcherQueue.TryEnqueue(() =>
                                    {
                                        myButton.Content = "Connection closed";
                                    });
                                    break;
                                }
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            // Normal when cancellation is requested
                        }
                        catch (Exception ex)
                        {
                            DispatcherQueue.TryEnqueue(() =>
                            {
                                ShowErrorMessage($"Error in monitoring loop: {ex.Message}");
                                myButton.Content = "Monitoring failed";
                            });
                        }
                    }, cts.Token);

                    myButton.Content = "Monitoring All HTTP Requests";
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"Error: {ex.Message}");
                myButton.Content = "Failed";
            }
        }

        // Helper method to send a message over WebSocket
        private async Task SendWebSocketMessage(ClientWebSocket client, string message, CancellationToken token)
        {
            var bytes = Encoding.UTF8.GetBytes(message);
            await client.SendAsync(new ArraySegment<byte>(bytes),
                WebSocketMessageType.Text,
                true,
                token);
        }

        // Classes to deserialize Chrome DevTools Protocol messages
        public class TabInfo
        {
            public string id { get; set; }
            public string title { get; set; }
            public string type { get; set; }
            public string url { get; set; }
            public string devtoolsFrontendUrl { get; set; }
            public string webSocketDebuggerUrl { get; set; }
        }

        private async void ShowErrorMessage(string message)
        {
            ContentDialog errorDialog = new ContentDialog
            {
                Title = "Error",
                Content = message,
                CloseButtonText = "OK",
                XamlRoot = this.Content.XamlRoot
            };

            await errorDialog.ShowAsync();
        }
    }
}
