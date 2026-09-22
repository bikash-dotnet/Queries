[ApiController]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    private readonly CacheRefreshService _refreshService;
    private readonly KubernetesPodInfoService _podInfoService;
    private readonly ILogger _logger;

    public AdminController(
        CacheRefreshService refreshService,
        KubernetesPodInfoService podInfoService,
        ILogger<AdminController> logger)
    {
        _refreshService = refreshService;
        _podInfoService = podInfoService;
        _logger = logger;
    }

    [HttpGet("pods")]
    public async Task<IActionResult> GetPods()
    {
        var pods = await _podInfoService.GetAllAppPodsAsync();
        var currentPod = await _podInfoService.GetCurrentPodInfoAsync();
        
        return Ok(new
        {
            CurrentPod = currentPod,
            AllPods = pods,
            TotalPods = pods.Count
        });
    }

    [HttpPost("refresh-cache")]
    public async Task<IActionResult> RefreshCache([FromBody] RefreshAllRequest request)
    {
        _logger.LogInformation("Manual cache refresh triggered for all pods");
        
        var result = await _refreshService.RefreshCacheOnAllPodsAsync(request?.Key);
        
        return Ok(new
        {
            Status = result.Success ? "Success" : "Partial Failure",
            TotalPods = result.TotalPods,
            SuccessfulPods = result.SuccessfulPods,
            FailedPods = result.FailedPods,
            Key = request?.Key ?? "ALL",
            Timestamp = DateTime.UtcNow,
            Details = result.Results,
            Error = result.Error
        });
    }

    [HttpPost("refresh-cache/{key}")]
    public async Task<IActionResult> RefreshCacheKey(string key)
    {
        return await RefreshCache(new RefreshAllRequest { Key = key });
    }
}

public class RefreshAllRequest
{
    public string Key { get; set; }
}
