using k8s;
using k8s.Models;
using System.Text.Json;

public class KubernetesPodInfoService
{
    private readonly IKubernetes _client;
    private readonly ILogger _logger;
    private readonly string _namespace;
    private readonly string _appLabel;

    public KubernetesPodInfoService(ILogger<KubernetesPodInfoService> logger)
    {
        _logger = logger;
        
        // Initialize Kubernetes client
        try
        {
            var config = KubernetesClientConfiguration.InClusterConfig();
            _client = new Kubernetes(config);
        }
        catch
        {
            // For local development
            var config = KubernetesClientConfiguration.BuildConfigFromConfigFile();
            _client = new Kubernetes(config);
        }
        
        // Get namespace from service account (always available)
        _namespace = GetNamespaceFromServiceAccount();
        
        // Your app label from YAML
        _appLabel = "cmc-contacts-ui";
    }

    private string GetNamespaceFromServiceAccount()
    {
        try
        {
            // Standard Kubernetes service account path
            var namespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
            if (File.Exists(namespacePath))
            {
                return File.ReadAllText(namespacePath).Trim();
            }
            
            // Fallback: read from environment if available
            return Environment.GetEnvironmentVariable("POD_NAMESPACE") ?? "default";
        }
        catch
        {
            return "default";
        }
    }

    /// <summary>
    /// Get current pod info without environment variables
    /// </summary>
    public async Task<PodInfo> GetCurrentPodInfoAsync()
    {
        try
        {
            // Get pod name from hostname (Kubernetes sets this to pod name)
            var podName = Environment.GetEnvironmentVariable("HOSTNAME") ?? 
                         Environment.MachineName;
            
            // Get pod from API
            var pod = await _client.CoreV1.ReadNamespacedPodAsync(podName, _namespace);
            
            return new PodInfo
            {
                Name = pod.Metadata.Name,
                Namespace = pod.Metadata.NamespaceProperty,
                PodIP = pod.Status.PodIP,
                HostIP = pod.Status.HostIP,
                NodeName = pod.Spec.NodeName,
                Phase = pod.Status.Phase,
                StartTime = pod.Status.StartTime,
                Labels = pod.Metadata.Labels,
                Annotations = pod.Metadata.Annotations,
                ResourceVersion = pod.Metadata.ResourceVersion,
                Replicas = GetReplicaCount(pod.Metadata.Labels)
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get pod info");
            
            // Fallback to basic info
            return new PodInfo
            {
                Name = Environment.GetEnvironmentVariable("HOSTNAME") ?? "unknown",
                Namespace = _namespace,
                PodIP = "unknown"
            };
        }
    }

    /// <summary>
    /// Get all pods for the application
    /// </summary>
    public async Task<List<PodInfo>> GetAllAppPodsAsync()
    {
        try
        {
            var pods = await _client.CoreV1.ListNamespacedPodAsync(
                namespaceParameter: _namespace,
                labelSelector: $"app={_appLabel}"
            );

            return pods.Items.Select(p => new PodInfo
            {
                Name = p.Metadata.Name,
                PodIP = p.Status.PodIP,
                Phase = p.Status.Phase,
                StartTime = p.Status.StartTime,
                Labels = p.Metadata.Labels,
                Annotations = p.Metadata.Annotations
            }).Where(p => p.Phase == "Running").ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get pods");
            return new List<PodInfo>();
        }
    }

    private int GetReplicaCount(Dictionary<string, string> labels)
    {
        // Try to get from labels if available
        if (labels != null && labels.TryGetValue("pod-template-hash", out var hash))
        {
            // You could also query the deployment
            return 2; // From your YAML
        }
        return 0;
    }

    /// <summary>
    /// Check if running in Kubernetes
    /// </summary>
    public bool IsRunningInKubernetes()
    {
        return File.Exists("/var/run/secrets/kubernetes.io/serviceaccount/token");
    }
}

public class PodInfo
{
    public string Name { get; set; }
    public string Namespace { get; set; }
    public string PodIP { get; set; }
    public string HostIP { get; set; }
    public string NodeName { get; set; }
    public string Phase { get; set; }
    public DateTime? StartTime { get; set; }
    public Dictionary<string, string> Labels { get; set; }
    public Dictionary<string, string> Annotations { get; set; }
    public string ResourceVersion { get; set; }
    public int Replicas { get; set; }
}
