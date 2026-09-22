public class CacheRefreshService
{
    private readonly IKubernetes _client;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger _logger;
    private readonly string _namespace;
    private readonly string _appLabel;

    public CacheRefreshService(
        IKubernetes client,
        IHttpClientFactory httpClientFactory,
        ILogger<CacheRefreshService> logger)
    {
        _client = client;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        
        _namespace = GetNamespace();
        _appLabel = "cmc-contacts-ui"; // From your YAML
    }

    private string GetNamespace()
    {
        try
        {
            var path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
            if (File.Exists(path))
                return File.ReadAllText(path).Trim();
        }
        catch { }
        return "icg-isg-personid-170249"; // From your YAML
    }

    /// <summary>
    /// Refresh cache on all pods
    /// </summary>
    public async Task<RefreshSummary> RefreshCacheOnAllPodsAsync(string cacheKey = null)
    {
        var summary = new RefreshSummary();
        
        try
        {
            // Get all pods for the application
            var pods = await _client.CoreV1.ListNamespacedPodAsync(
                namespaceParameter: _namespace,
                labelSelector: $"app={_appLabel}"
            );

            var runningPods = pods.Items
                .Where(p => p.Status.Phase == "Running" && !string.IsNullOrEmpty(p.Status.PodIP))
                .ToList();

            _logger.LogInformation($"Found {runningPods.Count} running pods");

            // Get current pod name from hostname
            var currentPodName = Environment.GetEnvironmentVariable("HOSTNAME");
            
            var tasks = new List<Task<PodRefreshResult>>();
            
            foreach (var pod in runningPods)
            {
                // Skip current pod if we want to handle it separately
                if (pod.Metadata.Name == currentPodName)
                    continue;
                    
                tasks.Add(RefreshPodCacheAsync(pod, cacheKey));
            }

            // Also refresh current pod locally
            if (!string.IsNullOrEmpty(currentPodName))
            {
                tasks.Add(RefreshCurrentPodCacheAsync(cacheKey));
            }

            var results = await Task.WhenAll(tasks);
            
            summary.TotalPods = runningPods.Count;
            summary.SuccessfulPods = results.Count(r => r.Success);
            summary.FailedPods = results.Count(r => !r.Success);
            summary.Success = summary.FailedPods == 0;
            summary.Results = results.ToList();

            return summary;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh cache on all pods");
            summary.Success = false;
            summary.Error = ex.Message;
            return summary;
        }
    }

    private async Task<PodRefreshResult> RefreshPodCacheAsync(V1Pod pod, string cacheKey)
    {
        var result = new PodRefreshResult
        {
            PodName = pod.Metadata.Name,
            PodIP = pod.Status.PodIP
        };

        try
        {
            // Use standard port 80 (or your service port)
            var port = "80";
            
            // Check for custom port in annotation
            if (pod.Metadata.Annotations != null && 
                pod.Metadata.Annotations.TryGetValue("cache-refresh-port", out var customPort))
            {
                port = customPort;
            }

            var url = $"http://{pod.Status.PodIP}:{port}/api/cache/refresh";
            
            var payload = new { key = cacheKey };
            var content = new StringContent(
                JsonSerializer.Serialize(payload),
                System.Text.Encoding.UTF8,
                "application/json"
            );

            var client = _httpClientFactory.CreateClient("PodRefresh");
            client.Timeout = TimeSpan.FromSeconds(10);

            var response = await client.PostAsync(url, content);
            
            result.Success = response.IsSuccessStatusCode;
            result.StatusCode = (int)response.StatusCode;

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("✓ Cache refreshed on pod {PodName} ({PodIP})", 
                    pod.Metadata.Name, pod.Status.PodIP);
            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                result.Error = $"HTTP {response.StatusCode}: {error}";
                _logger.LogWarning("✗ Failed to refresh pod {PodName}: {Error}", 
                    pod.Metadata.Name, result.Error);
            }
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            _logger.LogError(ex, "✗ Error refreshing pod {PodName}", pod.Metadata.Name);
        }

        return result;
    }

    private async Task<PodRefreshResult> RefreshCurrentPodCacheAsync(string cacheKey)
    {
        // This should call your local cache refresh logic
        // For example, inject your cache service and call it
        
        return new PodRefreshResult
        {
            PodName = Environment.GetEnvironmentVariable("HOSTNAME") ?? "current",
            PodIP = "local",
            Success = true
        };
    }
}

public class RefreshSummary
{
    public bool Success { get; set; }
    public int TotalPods { get; set; }
    public int SuccessfulPods { get; set; }
    public int FailedPods { get; set; }
    public string Error { get; set; }
    public List<PodRefreshResult> Results { get; set; } = new();
}

public class PodRefreshResult
{
    public string PodName { get; set; }
    public string PodIP { get; set; }
    public bool Success { get; set; }
    public int? StatusCode { get; set; }
    public string Error { get; set; }
}
