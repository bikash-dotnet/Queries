[ApiController]
[Route("api/cache")]
public class CacheController : ControllerBase
{
    private readonly ICacheService _cacheService;
    private readonly ILogger _logger;
    private readonly string _podName;

    public CacheController(ICacheService cacheService, ILogger<CacheController> logger)
    {
        _cacheService = cacheService;
        _logger = logger;
        
        // HOSTNAME is automatically set by Kubernetes
        _podName = Environment.GetEnvironmentVariable("HOSTNAME") ?? "unknown";
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshCache([FromBody] RefreshRequest request)
    {
        try
        {
            _logger.LogInformation("Cache refresh on {PodName} for key: {Key}", 
                _podName, request?.Key ?? "ALL");

            if (string.IsNullOrEmpty(request?.Key))
            {
                // Refresh all cache
                await _cacheService.RefreshAllAsync();
            }
            else
            {
                // Refresh specific cache
                await _cacheService.RefreshAsync(request.Key);
            }

            return Ok(new
            {
                Pod = _podName,
                Status = "Refreshed",
                Timestamp = DateTime.UtcNow,
                Key = request?.Key ?? "ALL"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Cache refresh failed on {PodName}", _podName);
            return StatusCode(500, new { Error = ex.Message });
        }
    }
}

public class RefreshRequest
{
    public string Key { get; set; }
}
