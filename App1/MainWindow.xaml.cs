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
    public class TabInfo
    {
        [JsonPropertyName("id")]
        public string id { get; set; }
        
        [JsonPropertyName("title")]
        public string title { get; set; }
        
        [JsonPropertyName("type")]
        public string type { get; set; }
        
        [JsonPropertyName("url")]
        public string url { get; set; }
        
        [JsonPropertyName("devtoolsFrontendUrl")]
        public string devtoolsFrontendUrl { get; set; }
        
        [JsonPropertyName("webSocketDebuggerUrl")]
        public string webSocketDebuggerUrl { get; set; }
        
        [JsonPropertyName("description")]
        public string description { get; set; }
    }

    public sealed partial class MainWindow : Window
    {
        private ClientWebSocket webSocketClient;
        private List<HttpRequestInfo> capturedRequests = new List<HttpRequestInfo>();
        private CancellationTokenSource cts;
        private const int maxRequestsToStore = 100; // Limit to prevent memory issues
        private string currentLogFilePath;
        private Dictionary<string, int> requestIdToIndex = new Dictionary<string, int>();
        private Dictionary<int, string> responseCommandIds = new Dictionary<int, string>(); // Track command IDs to requestIds
        private TextBlock statusTextBlock;
        private ListView requestListBox;
        private TextBlock methodCountTextBlock;

        // Update the MainWindow constructor to add the new TextBlock:
public MainWindow()
{
    this.InitializeComponent();
    
    // Setup the UI - assuming you have a Grid called "rootGrid" in your XAML
    var grid = new Grid();
    
    var rowDef1 = new RowDefinition();
    rowDef1.Height = new GridLength(50);
    var rowDef2 = new RowDefinition();
    rowDef2.Height = new GridLength(50);
    var rowDef3 = new RowDefinition();
    rowDef3.Height = new GridLength(1, GridUnitType.Star);
    // Add a new row for method counts
    var rowDef4 = new RowDefinition();
    rowDef4.Height = new GridLength(70);
    
    grid.RowDefinitions.Add(rowDef1);
    grid.RowDefinitions.Add(rowDef2);
    grid.RowDefinitions.Add(rowDef3);
    grid.RowDefinitions.Add(rowDef4);
    
    var myButton = new Button();
    myButton.Content = "Start Monitoring";
    myButton.HorizontalAlignment = HorizontalAlignment.Center;
    myButton.Click += myButton_Click;
    Grid.SetRow(myButton, 0);
    
    statusTextBlock = new TextBlock();
    statusTextBlock.Text = "Ready";
    statusTextBlock.HorizontalAlignment = HorizontalAlignment.Center;
    Grid.SetRow(statusTextBlock, 1);
    
    requestListBox = new ListView();
    requestListBox.Margin = new Thickness(10);
    Grid.SetRow(requestListBox, 2);
    
    // Add method count text block
    methodCountTextBlock = new TextBlock();
    methodCountTextBlock.Margin = new Thickness(10);
    methodCountTextBlock.HorizontalAlignment = HorizontalAlignment.Left;
    Grid.SetRow(methodCountTextBlock, 3);
    
    grid.Children.Add(myButton);
    grid.Children.Add(statusTextBlock);
    grid.Children.Add(requestListBox);
    grid.Children.Add(methodCountTextBlock);
    
    this.Content = grid;
}
// Add a method to count HTTP methods
private Dictionary<string, int> CountHttpMethods()
{
    var methodCounts = new Dictionary<string, int>();
    
    foreach (var request in capturedRequests)
    {
        if (string.IsNullOrEmpty(request.Method))
            continue;
        
        if (methodCounts.ContainsKey(request.Method))
            methodCounts[request.Method]++;
        else
            methodCounts[request.Method] = 1;
    }
    
    return methodCounts;
}

        private string TruncateUrl(string url, int maxLength)
        {
            if (string.IsNullOrEmpty(url)) return "unknown";
            return url.Length <= maxLength ? url : url.Substring(0, maxLength) + "...";
        }

        // Enhanced class to include response data
        public class HttpRequestInfo
        {
            // Request properties
            public string Url { get; set; }
            public string Method { get; set; } // GET, POST, PATCH, DELETE, PUT, etc.
            public string CallingType { get; set; }
            public string InitiatorType { get; set; }
            public string StackTrace { get; set; }
            public string RawRequestMessage { get; set; }
            public string RequestTimestamp { get; set; }
            public string RequestId { get; set; }
            public string RequestBody { get; set; }
            public Dictionary<string, string> RequestHeaders { get; set; } = new Dictionary<string, string>();

            // Response properties
            public bool HasResponse { get; set; } = false;
            public int StatusCode { get; set; }
            public string StatusText { get; set; }
            public string ResponseTimestamp { get; set; }
            public string ResponseBody { get; set; }
            public string RawResponseMessage { get; set; }
            public Dictionary<string, string> ResponseHeaders { get; set; } = new Dictionary<string, string>();
            public string MimeType { get; set; }
            public long ResponseSize { get; set; }

            public override string ToString()
            {
                return $"[{Method}] {Url}\nStatus: {(HasResponse ? $"{StatusCode} {StatusText}" : "No Response")}\nCalling Type: {CallingType}";
            }
        }

        private async void myButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var myButton = (Button)sender;
                myButton.Content = "Connecting...";
                statusTextBlock.Text = "Initializing...";

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
                requestIdToIndex.Clear();
                capturedRequests.Clear();
                responseCommandIds.Clear();

                // Setup the path to save the captured requests
                var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                currentLogFilePath = Path.Combine(documentsPath, $"chrome_http_requests_{timestamp}.json");

                // Initialize the file with an empty array
                await File.WriteAllTextAsync(currentLogFilePath, "[]");
                statusTextBlock.Text = $"Will save to: {currentLogFilePath}";

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
                    statusTextBlock.Text = $"Connecting to Chrome tab: {firstTab.title}";

                    // Connect to the WebSocket
                    await webSocketClient.ConnectAsync(new Uri(firstTab.webSocketDebuggerUrl), cts.Token);

                    // Enable Network events
                    var enableNetworkMessage = JsonSerializer.Serialize(new
                    {
                        id = 1,
                        method = "Network.enable",
                        @params = new
                        {
                            maxTotalBufferSize = 10000000, // Allow larger response sizes
                            maxResourceBufferSize = 5000000,
                            maxPostDataSize = 500000
                        }
                    });

                    await SendWebSocketMessage(webSocketClient, enableNetworkMessage, cts.Token);
                    
                    // Important: DO NOT enable request interception as it can freeze the browser
                    // if not handled properly

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
                                    System.Diagnostics.Debug.WriteLine($"Received message: {message.Substring(0, Math.Min(100, message.Length))}...");

                                    // Enhanced detection of all HTTP requests and responses
                                    try
                                    {
                                        // Parse as a CDP event
                                        using (JsonDocument doc = JsonDocument.Parse(message))
                                        {
                                            // Check if this is a response to our commands (has 'id' property)
                                            if (doc.RootElement.TryGetProperty("id", out JsonElement idElement))
                                            {
                                                int messageId = idElement.GetInt32();
                                                // Check if this is a response to our getResponseBody command
                                                if (responseCommandIds.ContainsKey(messageId) && 
                                                    doc.RootElement.TryGetProperty("result", out JsonElement resultElement))
                                                {
                                                    string requestId = responseCommandIds[messageId];
                                                    await HandleResponseBodyResult(requestId, resultElement);
                                                    // Remove the tracked command ID
                                                    responseCommandIds.Remove(messageId);
                                                }
                                            }
                                            // Check if it's a CDP event (has 'method' property)
                                            else if (doc.RootElement.TryGetProperty("method", out JsonElement methodElement))
                                            {
                                                string eventMethod = methodElement.GetString();

                                                // Handle request events
                                                if (eventMethod == "Network.requestWillBeSent")
                                                {
                                                    await HandleRequestEvent(doc.RootElement, message);
                                                }
                                                // Handle response events
                                                else if (eventMethod == "Network.responseReceived")
                                                {
                                                    await HandleResponseEvent(doc.RootElement, message);
                                                }
                                                // Handle response body events
                                                else if (eventMethod == "Network.loadingFinished")
                                                {
                                                    await HandleLoadingFinishedEvent(doc.RootElement);
                                                }
                                                // Handle intercepted requests (if any)
                                                else if (eventMethod == "Network.requestIntercepted")
                                                {
                                                    await HandleInterceptedRequest(doc.RootElement);
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
                                        statusTextBlock.Text = "Connection to Chrome closed";
                                    });
                                    break;
                                }
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            // Normal when cancellation is requested
                            System.Diagnostics.Debug.WriteLine("WebSocket operation was cancelled");
                        }
                        catch (Exception ex)
                        {
                            DispatcherQueue.TryEnqueue(() =>
                            {
                                ShowErrorMessage($"Error in monitoring loop: {ex.Message}");
                                myButton.Content = "Monitoring failed";
                                statusTextBlock.Text = $"Error: {ex.Message}";
                            });
                        }
                    }, cts.Token);

                    myButton.Content = "Monitoring HTTP Traffic";
                    statusTextBlock.Text = "Monitoring all HTTP requests & responses...";
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"Error: {ex.Message}");
                statusTextBlock.Text = $"Error: {ex.Message}";
                ((Button)sender).Content = "Failed";
            }
        }

        // Process request events
        private async Task HandleRequestEvent(JsonElement rootElement, string rawMessage)
        {
            try
            {
                if (rootElement.TryGetProperty("params", out JsonElement paramsElement) &&
                    paramsElement.TryGetProperty("request", out JsonElement requestElement) &&
                    requestElement.TryGetProperty("method", out JsonElement requestMethodElement))
                {
                    string requestMethod = requestMethodElement.GetString();

                    // Create a new HttpRequestInfo to store details
                    var requestInfo = new HttpRequestInfo
                    {
                        Method = requestMethod,
                        Url = requestElement.TryGetProperty("url", out JsonElement urlElement) ?
                            urlElement.GetString() : "unknown",
                        RequestTimestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                        RawRequestMessage = rawMessage
                    };

                    // Get request ID
                    requestInfo.RequestId = paramsElement.TryGetProperty("requestId", out JsonElement requestIdElement) ?
                        requestIdElement.GetString() : "";

                    // Extract headers
                    if (requestElement.TryGetProperty("headers", out JsonElement headersElement))
                    {
                        foreach (JsonProperty header in headersElement.EnumerateObject())
                        {
                            requestInfo.RequestHeaders[header.Name] = header.Value.ToString();
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

                    // Capture the request
                    capturedRequests.Add(requestInfo);

                    // Store the index for later response matching
                    if (!string.IsNullOrEmpty(requestInfo.RequestId))
                    {
                        requestIdToIndex[requestInfo.RequestId] = capturedRequests.Count - 1;
                    }

                    // Limit the number of requests to prevent memory issues
                    if (capturedRequests.Count > maxRequestsToStore)
                    {
                        var removeCount = capturedRequests.Count - maxRequestsToStore;
                        var removedIds = capturedRequests.Take(removeCount).Select(r => r.RequestId);
                        capturedRequests.RemoveRange(0, removeCount);

                        // Update indices in the dictionary
                        var updatedDict = new Dictionary<string, int>();
                        foreach (var kvp in requestIdToIndex)
                        {
                            if (!removedIds.Contains(kvp.Key))
                            {
                                updatedDict[kvp.Key] = kvp.Value - removeCount;
                            }
                        }
                        requestIdToIndex = updatedDict;
                    }

                    // Save to file
                    await SaveRequestsToFile();

                    // Update UI
                    UpdateUI();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error handling request event: {ex.Message}");
            }
        }

        // Process response events
        private async Task HandleResponseEvent(JsonElement rootElement, string rawMessage)
        {
            try
            {
                if (rootElement.TryGetProperty("params", out JsonElement paramsElement))
                {
                    string requestId = paramsElement.TryGetProperty("requestId", out JsonElement requestIdElement) ?
                        requestIdElement.GetString() : "";

                    if (string.IsNullOrEmpty(requestId) || !requestIdToIndex.ContainsKey(requestId))
                    {
                        return; // No matching request found
                    }

                    int index = requestIdToIndex[requestId];
                    if (index < 0 || index >= capturedRequests.Count)
                    {
                        return; // Index out of range
                    }

                    // Get the request info that this response belongs to
                    var requestInfo = capturedRequests[index];

                    // Extract response information
                    if (paramsElement.TryGetProperty("response", out JsonElement responseElement))
                    {
                        requestInfo.HasResponse = true;
                        requestInfo.StatusCode = responseElement.TryGetProperty("status", out JsonElement statusElement) ?
                            statusElement.GetInt32() : 0;
                        requestInfo.StatusText = responseElement.TryGetProperty("statusText", out JsonElement statusTextElement) ?
                            statusTextElement.GetString() : "";
                        requestInfo.ResponseTimestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                        requestInfo.RawResponseMessage = rawMessage;

                        // Extract headers
                        if (responseElement.TryGetProperty("headers", out JsonElement headersElement))
                        {
                            foreach (JsonProperty header in headersElement.EnumerateObject())
                            {
                                requestInfo.ResponseHeaders[header.Name] = header.Value.ToString();
                            }
                        }

                        // Extract MIME type and response size
                        requestInfo.MimeType = responseElement.TryGetProperty("mimeType", out JsonElement mimeTypeElement) ?
                            mimeTypeElement.GetString() : "";
                        requestInfo.ResponseSize = responseElement.TryGetProperty("encodedDataLength", out JsonElement encodedDataLengthElement) ?
                            encodedDataLengthElement.GetInt64() : 0;
                    }

                    // Save to file
                    await SaveRequestsToFile();

                    // Update UI
                    UpdateUI();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error handling response event: {ex.Message}");
            }
        }

        // Handle loading finished events to fetch response body
        private async Task HandleLoadingFinishedEvent(JsonElement rootElement)
        {
            try
            {
                if (rootElement.TryGetProperty("params", out JsonElement paramsElement))
                {
                    string requestId = paramsElement.TryGetProperty("requestId", out JsonElement requestIdElement) ?
                        requestIdElement.GetString() : "";

                    if (string.IsNullOrEmpty(requestId) || !requestIdToIndex.ContainsKey(requestId))
                    {
                        return; // No matching request found
                    }

                    int index = requestIdToIndex[requestId];
                    if (index < 0 || index >= capturedRequests.Count)
                    {
                        return; // Index out of range
                    }

                    var requestInfo = capturedRequests[index];
                    
                    // Only fetch response body for successful responses and appropriate content types
                    if (requestInfo.HasResponse && 
                        requestInfo.StatusCode >= 200 && requestInfo.StatusCode < 300 &&
                        !string.IsNullOrEmpty(requestInfo.MimeType) && 
                        (requestInfo.MimeType.Contains("json") || 
                         requestInfo.MimeType.Contains("text") || 
                         requestInfo.MimeType.Contains("xml") ||
                         requestInfo.MimeType.Contains("javascript")))
                    {
                        // Generate a unique command ID
                        int commandId = new Random().Next(1000, 9999);
                        
                        // Store the command ID mapping to request ID
                        responseCommandIds[commandId] = requestId;
                        
                        // Fetch the response body
                        var getResponseBodyMessage = JsonSerializer.Serialize(new
                        {
                            id = commandId,
                            method = "Network.getResponseBody",
                            @params = new
                            {
                                requestId = requestId
                            }
                        });

                        await SendWebSocketMessage(webSocketClient, getResponseBodyMessage, cts.Token);
                        System.Diagnostics.Debug.WriteLine($"Sent getResponseBody command with ID {commandId} for request {requestId}");
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error handling loading finished event: {ex.Message}");
            }
        }

        // Handle intercepted requests
        private async Task HandleInterceptedRequest(JsonElement rootElement)
        {
            try
            {
                if (rootElement.TryGetProperty("params", out JsonElement paramsElement) &&
                    paramsElement.TryGetProperty("interceptionId", out JsonElement interceptionIdElement))
                {
                    string interceptionId = interceptionIdElement.GetString();
                    if (!string.IsNullOrEmpty(interceptionId))
                    {
                        // Generate a unique command ID
                        int commandId = new Random().Next(10000, 19999);
                        
                        // Continue the intercepted request without modification
                        var continueRequestMessage = JsonSerializer.Serialize(new
                        {
                            id = commandId,
                            method = "Network.continueInterceptedRequest",
                            @params = new
                            {
                                interceptionId = interceptionId
                            }
                        });

                        await SendWebSocketMessage(webSocketClient, continueRequestMessage, cts.Token);
                        System.Diagnostics.Debug.WriteLine($"Continued intercepted request with ID {interceptionId}");
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error handling intercepted request: {ex.Message}");
            }
        }

        // Handle response body results
// Handle response body results
private async Task HandleResponseBodyResult(string requestId, JsonElement resultElement)
{
    try
    {
        if (string.IsNullOrEmpty(requestId) || !requestIdToIndex.ContainsKey(requestId))
        {
            return; // No matching request found
        }

        int index = requestIdToIndex[requestId];
        if (index < 0 || index >= capturedRequests.Count)
        {
            return; // Index out of range
        }

        var requestInfo = capturedRequests[index];
        
        string body = "";
        bool base64Encoded = false;
        
        if (resultElement.TryGetProperty("body", out JsonElement bodyElement))
        {
            body = bodyElement.GetString() ?? "";
        }
        
        if (resultElement.TryGetProperty("base64Encoded", out JsonElement base64Element))
        {
            base64Encoded = base64Element.GetBoolean();
        }

        if (base64Encoded && !string.IsNullOrEmpty(body))
        {
            // Try to decode the base64-encoded body if needed
            try
            {
                byte[] data = Convert.FromBase64String(body);
                
                // Try to convert to UTF-8, but if that fails, just note it's binary data
                try {
                    body = Encoding.UTF8.GetString(data);
                }
                catch {
                    body = "[Binary data, base64 encoded, length: " + data.Length + " bytes]";
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error decoding base64 response: {ex.Message}");
                body = "[Error decoding base64 data]";
            }
        }

        // Limit size of large response bodies to prevent issues with JSON serialization
        const int maxBodyLength = 1000000; // ~1MB text limit
        if (body?.Length > maxBodyLength)
        {
            body = body.Substring(0, maxBodyLength) + "\n\n[Response truncated due to size...]";
        }

        requestInfo.ResponseBody = body;
        System.Diagnostics.Debug.WriteLine($"Received response body for {requestInfo.Method} {TruncateUrl(requestInfo.Url, 30)}, size: {body?.Length ?? 0} chars, content type: {requestInfo.MimeType}");
        
        // Save updated request to file
        await SaveRequestsToFile();
        
        // Update UI
        UpdateUI();
    }
    catch (Exception ex)
    {
        System.Diagnostics.Debug.WriteLine($"Error handling response body: {ex.Message}");
    }
}

        // Send WebSocket message
        private async Task SendWebSocketMessage(ClientWebSocket webSocket, string message, CancellationToken token)
        {
            try
            {
                var messageBuffer = Encoding.UTF8.GetBytes(message);
                await webSocket.SendAsync(new ArraySegment<byte>(messageBuffer), WebSocketMessageType.Text, true, token);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error sending WebSocket message: {ex.Message}");
                throw;
            }
        }

        // Save captured requests to file
// Save captured requests to file
private async Task SaveRequestsToFile()
{
    try
    {
        // Count requests with response bodies for logging
        int requestsWithBodies = capturedRequests.Count(r => !string.IsNullOrEmpty(r.ResponseBody));
        
        var json = JsonSerializer.Serialize(capturedRequests, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            MaxDepth = 64 // Increase max depth for complex response bodies
        });
        
        await File.WriteAllTextAsync(currentLogFilePath, json);
        System.Diagnostics.Debug.WriteLine($"Saved {capturedRequests.Count} requests to file, {requestsWithBodies} with response bodies");
    }
    catch (Exception ex)
    {
        System.Diagnostics.Debug.WriteLine($"Error saving to file: {ex.Message}");
    }
}

        // Update UI
// Update the UpdateUI method to include method counts
private void UpdateUI()
{
    try
    {
        // Ensure we're on the UI thread
        DispatcherQueue.TryEnqueue(() =>
        {
            try
            {
                // Update the listbox if it exists
                if (requestListBox != null)
                {
                    requestListBox.ItemsSource = null; // Clear current binding
                    requestListBox.ItemsSource = capturedRequests.Select(r => 
                        $"{r.Method} {TruncateUrl(r.Url, 50)} - {(r.HasResponse ? $"Status: {r.StatusCode}" : "Pending")}");
                }
                
                // Update status text
                int responseCount = capturedRequests.Count(r => r.HasResponse);
                statusTextBlock.Text = $"Monitoring: {capturedRequests.Count} requests, {responseCount} responses";
                
                // Update HTTP method counts
                var methodCounts = CountHttpMethods();
                var sb = new StringBuilder("HTTP Methods: ");
                bool isFirst = true;
                foreach (var kvp in methodCounts.OrderByDescending(k => k.Value))
                {
                    if (!isFirst)
                        sb.Append(" | ");
                    sb.Append($"{kvp.Key}: {kvp.Value}");
                    isFirst = false;
                }
                methodCountTextBlock.Text = sb.ToString();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in UI update: {ex.Message}");
            }
        });
    }
    catch (Exception ex)
    {
        System.Diagnostics.Debug.WriteLine($"Error dispatching UI update: {ex.Message}");
    }
}

        // Show error message
        private void ShowErrorMessage(string message)
        {
            DispatcherQueue.TryEnqueue(async () =>
            {
                ContentDialog dialog = new ContentDialog();
                dialog.XamlRoot = this.Content.XamlRoot;
                dialog.Title = "Error";
                dialog.Content = message;
                dialog.CloseButtonText = "OK";
                await dialog.ShowAsync();
            });
            System.Diagnostics.Debug.WriteLine($"ERROR: {message}");
        }
    }
}