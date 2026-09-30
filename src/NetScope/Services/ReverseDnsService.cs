using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace NetScope.Services;

/// <summary>
/// F30：反向 DNS，异步 20s 超时、每 IP 仅查一次、fire-and-forget 不阻塞扫描/监听。
/// 并发闸门限制同时进行的 DNS 查询数：大扫描一次性发现大量 IP 时，
/// 不创建数千个挂着 20s 定时器的任务，超出部分在队列上排队。
/// </summary>
public class ReverseDnsService
{
    private const int MaxConcurrency = 32;
    private readonly ConcurrentDictionary<IPAddress, byte> _queried = new();
    private readonly SemaphoreSlim _gate = new(MaxConcurrency);

    public event Action<IPAddress, string?>? HostResolved;

    public bool Enabled { get; set; } = true;

    public void Enqueue(IPAddress ip)
    {
        if (!Enabled) return;
        if (!_queried.TryAdd(ip, 0)) return; // 每 IP 仅查一次
        _ = Task.Run(async () =>
        {
            await _gate.WaitAsync();
            try
            {
                string? name = null;
                try
                {
                    var task = Dns.GetHostEntryAsync(ip);
                    // .NET 8 无 IPAddress+CancellationToken 重载，用 WhenAny 实现 20s 超时
                    var done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20))).ConfigureAwait(false);
                    if (done == task && task.Status == TaskStatus.RanToCompletion)
                        name = task.Result.HostName;
                }
                catch { /* 失败静默 */ }
                HostResolved?.Invoke(ip, name);
            }
            finally
            {
                _gate.Release();
            }
        });
    }

    public void ClearCache() => _queried.Clear();
}
