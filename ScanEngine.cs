// ScanEngine.cs - Full single-file implementation
// Channel-based MAC producer/consumer system with robust lifecycle management

using System;
using System.Buffers;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Scanner;

#region Stubs for External Types (if not available)

// Stub for DB if external DB class is unavailable
public static class DB
{
    public static void SaveResult(ScanResult result)
    {
        // Fallback: synchronous save
        Console.WriteLine($"[DB.SaveResult] MAC={result.MAC}, Status={result.Status}");
    }
}

// Stub for HitWriter if external class is unavailable
public static class HitWriter
{
    public static void SaveRawResponse(string mac, string? rawResponse)
    {
        Console.WriteLine($"[HitWriter.SaveRawResponse] MAC={mac}");
    }
}

// Stub for ScanResult
public class ScanResult
{
    public string MAC { get; set; } = string.Empty;
    public string Portal { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? RawResponse { get; set; }
    public DateTime ScannedAt { get; set; } = DateTime.UtcNow;
    public double LatencyMs { get; set; }
    public string? Error { get; set; }
    public string? XtreamUser { get; set; }
    public string? XtreamPass { get; set; }
    public string? ExpDate { get; set; }
    public int? ActiveCons { get; set; }
    public int? MaxCons { get; set; }
    public bool IsRestreamer { get; set; }
    public List<string>? Channels { get; set; }
}

// Stub for ScanOptions
public class ScanOptions
{
    public int WorkerCount { get; set; } = 8;
    public int ChannelCapacity { get; set; } = 1000;
    public int TimeoutMs { get; set; } = 10000;
    public int RetryCount { get; set; } = 2;
    public int NegativeCacheSeconds { get; set; } = 300;
    public int Variant1ConcurrencyLimit { get; set; } = 10;
    public bool EnableMetrics { get; set; } = true;
    public int MetricsPort { get; set; } = 9191;
    public int RecentSetCapacity { get; set; } = 10000;
    public List<string>? Proxies { get; set; }
    public string? ProxyFilePath { get; set; }
}

// Stub for MacItem
public class MacItem
{
    public string MAC { get; set; } = string.Empty;
    public string Portal { get; set; } = string.Empty;
    public string? Proxy { get; set; }
}

#endregion

#region Helper Classes

/// <summary>
/// Thread-safe bounded hash set for deduplication with LRU-like eviction.
/// </summary>
public sealed class RecentSet<T> where T : notnull
{
    private readonly LinkedHashSet<T> _set;
    private readonly int _capacity;
    private readonly object _lock = new();

    public RecentSet(int capacity)
    {
        _capacity = capacity > 0 ? capacity : 10000;
        _set = new LinkedHashSet<T>(_capacity);
    }

    /// <summary>
    /// Adds item if new. Returns true if added, false if already present.
    /// </summary>
    public bool AddIfNew(T item)
    {
        lock (_lock)
        {
            if (_set.Contains(item))
            {
                return false;
            }
            
            // Evict oldest if at capacity
            while (_set.Count >= _capacity)
            {
                var oldest = _set.First();
                _set.Remove(oldest);
            }
            
            _set.Add(item);
            return true;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _set.Clear();
        }
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _set.Count;
            }
        }
    }
}

/// <summary>
/// A linked hash set that maintains insertion order with O(1) operations.
/// </summary>
public sealed class LinkedHashSet<T> : IEnumerable<T> where T : notnull
{
    private readonly Dictionary<T, LinkedListNode<T>> _dict;
    private readonly LinkedList<T> _list;

    public LinkedHashSet(int capacity = 16)
    {
        _dict = new Dictionary<T, LinkedListNode<T>>(capacity);
        _list = new LinkedList<T>();
    }

    public int Count => _dict.Count;

    public bool Contains(T item) => _dict.ContainsKey(item);

    public bool Add(T item)
    {
        if (_dict.ContainsKey(item))
            return false;
        
        var node = _list.AddLast(item);
        _dict[item] = node;
        return true;
    }

    public bool Remove(T item)
    {
        if (!_dict.TryGetValue(item, out var node))
            return false;
        
        _dict.Remove(item);
        _list.Remove(node);
        return true;
    }

    public T First()
    {
        if (_list.First == null)
            throw new InvalidOperationException("Set is empty");
        return _list.First.Value;
    }

    public void Clear()
    {
        _dict.Clear();
        _list.Clear();
    }

    public IEnumerator<T> GetEnumerator() => _list.GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>
/// Extension methods for JsonElement.
/// </summary>
public static class JsonElementExtensions
{
    public static string? GetStringOrNull(this JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out var prop))
        {
            return prop.ValueKind == JsonValueKind.String ? prop.GetString() : prop.ToString();
        }
        return null;
    }

    public static int? GetIntOrNull(this JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out var prop))
        {
            if (prop.ValueKind == JsonValueKind.Number && prop.TryGetInt32(out var val))
                return val;
            if (prop.ValueKind == JsonValueKind.String && int.TryParse(prop.GetString(), out var parsed))
                return parsed;
        }
        return null;
    }

    public static bool GetBoolOrDefault(this JsonElement element, string propertyName, bool defaultValue = false)
    {
        if (element.TryGetProperty(propertyName, out var prop))
        {
            if (prop.ValueKind == JsonValueKind.True) return true;
            if (prop.ValueKind == JsonValueKind.False) return false;
            if (prop.ValueKind == JsonValueKind.String)
            {
                var s = prop.GetString()?.ToLowerInvariant();
                return s == "true" || s == "1" || s == "yes";
            }
            if (prop.ValueKind == JsonValueKind.Number)
                return prop.GetInt32() != 0;
        }
        return defaultValue;
    }

    public static T? GetPropertyOrDefault<T>(this JsonElement element, string propertyName, T? defaultValue = default)
    {
        if (!element.TryGetProperty(propertyName, out var prop))
            return defaultValue;

        try
        {
            return JsonSerializer.Deserialize<T>(prop.GetRawText());
        }
        catch
        {
            return defaultValue;
        }
    }
}

/// <summary>
/// Probe helpers for trying multiple endpoints.
/// </summary>
public static class ProbeHelpers
{
    /// <summary>
    /// Tries multiple async tasks tagged with a key, returns first successful result.
    /// </summary>
    public static async Task<(TKey? Key, TResult? Result, bool Success)> FirstSuccessfulTaggedAsync<TKey, TResult>(
        IEnumerable<(TKey Key, Func<CancellationToken, Task<TResult?>> Factory)> probes,
        CancellationToken ct = default)
        where TResult : class
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var tasks = new List<Task<(TKey Key, TResult? Result)>>();

        foreach (var (key, factory) in probes)
        {
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var result = await factory(linkedCts.Token).ConfigureAwait(false);
                    return (key, result);
                }
                catch
                {
                    return (key, default(TResult));
                }
            }, linkedCts.Token));
        }

        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks).ConfigureAwait(false);
            tasks.Remove(completed);

            try
            {
                var (key, result) = await completed.ConfigureAwait(false);
                if (result != null)
                {
                    linkedCts.Cancel();
                    return (key, result, true);
                }
            }
            catch
            {
                // Ignore and continue
            }
        }

        return (default, default, false);
    }
}

#endregion

#region MetricsService

/// <summary>
/// Simple metrics service exposing Prometheus-style metrics on a configurable port.
/// </summary>
public sealed class MetricsService : IDisposable
{
    private readonly HttpListener? _listener;
    private readonly CancellationTokenSource _cts = new();
    private Task? _listenTask;
    private readonly Func<MetricsSnapshot> _snapshotProvider;
    private bool _disposed;

    public class MetricsSnapshot
    {
        public long PendingMacs { get; set; }
        public long ProcessedAll { get; set; }
        public double AvgLatencyMs { get; set; }
        public long BgDbWriterCount { get; set; }
        public long BgFileWriterCount { get; set; }
    }

    public MetricsService(int port, Func<MetricsSnapshot> snapshotProvider)
    {
        _snapshotProvider = snapshotProvider ?? throw new ArgumentNullException(nameof(snapshotProvider));

        try
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://+:{port}/metrics/");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MetricsService] Failed to create listener on port {port}: {ex.Message}");
            _listener = null;
        }
    }

    public void Start()
    {
        if (_listener == null) return;

        try
        {
            _listener.Start();
            _listenTask = Task.Run(ListenLoop);
            Console.WriteLine($"[MetricsService] Started");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MetricsService] Failed to start: {ex.Message}");
        }
    }

    private async Task ListenLoop()
    {
        while (!_cts.IsCancellationRequested && _listener != null && _listener.IsListening)
        {
            try
            {
                var context = await _listener.GetContextAsync().ConfigureAwait(false);
                _ = Task.Run(() => HandleRequest(context));
            }
            catch (HttpListenerException) when (_cts.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[MetricsService] Error: {ex.Message}");
            }
        }
    }

    private void HandleRequest(HttpListenerContext context)
    {
        try
        {
            var snapshot = _snapshotProvider();
            var sb = new StringBuilder();
            sb.AppendLine("# HELP scanner_pending_macs Number of MACs pending in the channel");
            sb.AppendLine("# TYPE scanner_pending_macs gauge");
            sb.AppendLine($"scanner_pending_macs {snapshot.PendingMacs}");
            sb.AppendLine("# HELP scanner_processed_all Total processed MACs");
            sb.AppendLine("# TYPE scanner_processed_all counter");
            sb.AppendLine($"scanner_processed_all {snapshot.ProcessedAll}");
            sb.AppendLine("# HELP scanner_avg_latency_ms Average latency in milliseconds");
            sb.AppendLine("# TYPE scanner_avg_latency_ms gauge");
            sb.AppendLine($"scanner_avg_latency_ms {snapshot.AvgLatencyMs:F2}");
            sb.AppendLine("# HELP scanner_bg_db_writer_count Background DB writer queue count");
            sb.AppendLine("# TYPE scanner_bg_db_writer_count gauge");
            sb.AppendLine($"scanner_bg_db_writer_count {snapshot.BgDbWriterCount}");
            sb.AppendLine("# HELP scanner_bg_file_writer_count Background file writer queue count");
            sb.AppendLine("# TYPE scanner_bg_file_writer_count gauge");
            sb.AppendLine($"scanner_bg_file_writer_count {snapshot.BgFileWriterCount}");

            var buffer = Encoding.UTF8.GetBytes(sb.ToString());
            context.Response.ContentType = "text/plain; charset=utf-8";
            context.Response.ContentLength64 = buffer.Length;
            context.Response.OutputStream.Write(buffer, 0, buffer.Length);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MetricsService] HandleRequest error: {ex.Message}");
        }
        finally
        {
            try { context.Response.Close(); } catch { }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();
        try { _listener?.Stop(); } catch { }
        try { _listener?.Close(); } catch { }
        _cts.Dispose();
    }
}

#endregion

#region Background Writers

/// <summary>
/// Background writer for database operations.
/// </summary>
public sealed class BackgroundDbWriter : IDisposable
{
    private readonly Channel<ScanResult> _channel;
    private readonly Task _writerTask;
    private readonly CancellationTokenSource _cts = new();
    private long _count;
    private bool _disposed;

    public long Count => Interlocked.Read(ref _count);

    public BackgroundDbWriter(int capacity = 1000)
    {
        _channel = Channel.CreateBounded<ScanResult>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
        _writerTask = Task.Run(WriteLoop);
    }

    public bool TryEnqueue(ScanResult result)
    {
        if (_channel.Writer.TryWrite(result))
        {
            Interlocked.Increment(ref _count);
            return true;
        }
        return false;
    }

    public async ValueTask EnqueueAsync(ScanResult result, CancellationToken ct = default)
    {
        await _channel.Writer.WriteAsync(result, ct).ConfigureAwait(false);
        Interlocked.Increment(ref _count);
    }

    private async Task WriteLoop()
    {
        await foreach (var result in _channel.Reader.ReadAllAsync(_cts.Token))
        {
            try
            {
                DB.SaveResult(result);
                Interlocked.Decrement(ref _count);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BackgroundDbWriter] Error saving result: {ex.Message}");
                Interlocked.Decrement(ref _count);
            }
        }
    }

    public async Task FlushAsync()
    {
        _channel.Writer.TryComplete();
        await _writerTask.ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();
        _channel.Writer.TryComplete();
        _cts.Dispose();
    }
}

/// <summary>
/// Background writer for file operations (raw responses).
/// </summary>
public sealed class BackgroundFileWriter : IDisposable
{
    private readonly Channel<(string Mac, string? RawResponse)> _channel;
    private readonly Task _writerTask;
    private readonly CancellationTokenSource _cts = new();
    private long _count;
    private bool _disposed;

    public long Count => Interlocked.Read(ref _count);

    public BackgroundFileWriter(int capacity = 1000)
    {
        _channel = Channel.CreateBounded<(string, string?)>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
        _writerTask = Task.Run(WriteLoop);
    }

    public bool TryEnqueue(string mac, string? rawResponse)
    {
        if (_channel.Writer.TryWrite((mac, rawResponse)))
        {
            Interlocked.Increment(ref _count);
            return true;
        }
        return false;
    }

    public async ValueTask EnqueueAsync(string mac, string? rawResponse, CancellationToken ct = default)
    {
        await _channel.Writer.WriteAsync((mac, rawResponse), ct).ConfigureAwait(false);
        Interlocked.Increment(ref _count);
    }

    private async Task WriteLoop()
    {
        await foreach (var (mac, rawResponse) in _channel.Reader.ReadAllAsync(_cts.Token))
        {
            try
            {
                HitWriter.SaveRawResponse(mac, rawResponse);
                Interlocked.Decrement(ref _count);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BackgroundFileWriter] Error saving response: {ex.Message}");
                Interlocked.Decrement(ref _count);
            }
        }
    }

    public async Task FlushAsync()
    {
        _channel.Writer.TryComplete();
        await _writerTask.ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();
        _channel.Writer.TryComplete();
        _cts.Dispose();
    }
}

#endregion

#region ScanEngine

/// <summary>
/// Main scan engine with channel-based MAC producer/consumer system.
/// </summary>
public sealed class ScanEngine : IDisposable, IAsyncDisposable
{
    private readonly ScanOptions _options;
    private Channel<MacItem>? _macChannel;
    private CancellationTokenSource? _producerCts;
    private CancellationTokenSource? _runCts;
    private Task? _producerTask;
    private Task[]? _workerTasks;
    
    // Volatile stopping flag - set to false at run start, true at StopAsync start
    private volatile bool _stopping;
    
    // Pending counter - incremented after successful channel write, decremented on successful read
    private long _pendingMacs;
    
    // Metrics
    private long _processedAll;
    private double _totalLatencyMs;
    private readonly object _latencyLock = new();
    
    // Dedup
    private readonly RecentSet<string> _recentSet;
    
    // Variant1 controls
    private readonly SemaphoreSlim _variant1Semaphore;
    private readonly ConcurrentDictionary<string, DateTime> _variant1NegativeCache = new();
    
    // Background writers
    private BackgroundDbWriter? _bgDbWriter;
    private BackgroundFileWriter? _bgFileWriter;
    
    // Metrics service
    private MetricsService? _metricsService;
    
    // Proxy pool
    private List<string> _proxyPool = new();
    private int _proxyIndex;
    
    // HTTP client factory
    private readonly Func<string?, HttpClient> _httpClientFactory;
    
    public ScanEngine(ScanOptions options, Func<string?, HttpClient>? httpClientFactory = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _recentSet = new RecentSet<string>(options.RecentSetCapacity);
        _variant1Semaphore = new SemaphoreSlim(options.Variant1ConcurrencyLimit, options.Variant1ConcurrencyLimit);
        _httpClientFactory = httpClientFactory ?? (proxy => CreateDefaultHttpClient(proxy));
    }

    public long PendingMacs => Interlocked.Read(ref _pendingMacs);
    public long ProcessedAll => Interlocked.Read(ref _processedAll);
    public bool IsStopping => _stopping;

    public double AvgLatencyMs
    {
        get
        {
            lock (_latencyLock)
            {
                var processed = Interlocked.Read(ref _processedAll);
                return processed > 0 ? _totalLatencyMs / processed : 0;
            }
        }
    }

    #region Initialization

    /// <summary>
    /// Initialize the engine (proxy pool, background writers, metrics).
    /// </summary>
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        // Build proxy pool
        _proxyPool = await BuildProxyPoolAsync(_options.Proxies, _options.ProxyFilePath, ct).ConfigureAwait(false);
        Console.WriteLine($"[ScanEngine] Loaded {_proxyPool.Count} proxies");

        // Initialize background writers
        _bgDbWriter = new BackgroundDbWriter();
        _bgFileWriter = new BackgroundFileWriter();

        // Initialize metrics service
        if (_options.EnableMetrics)
        {
            _metricsService = new MetricsService(_options.MetricsPort, () => new MetricsService.MetricsSnapshot
            {
                PendingMacs = PendingMacs,
                ProcessedAll = ProcessedAll,
                AvgLatencyMs = AvgLatencyMs,
                BgDbWriterCount = _bgDbWriter?.Count ?? 0,
                BgFileWriterCount = _bgFileWriter?.Count ?? 0
            });
            _metricsService.Start();
        }
    }

    #endregion

    #region Start/Stop

    /// <summary>
    /// Start the scan engine with an enumerable source of MAC items.
    /// </summary>
    public Task StartAsync(IEnumerable<MacItem> source, CancellationToken ct = default)
    {
        return StartAsync(source.ToAsyncEnumerable(), ct);
    }

    /// <summary>
    /// Start the scan engine with an async enumerable source of MAC items.
    /// </summary>
    public async Task StartAsync(IAsyncEnumerable<MacItem> source, CancellationToken ct = default)
    {
        if (_producerTask != null || _workerTasks != null)
        {
            throw new InvalidOperationException("Engine is already running. Call StopAsync first.");
        }

        // Reset stopping flag at start of each run
        _stopping = false;

        // Create channel
        _macChannel = Channel.CreateBounded<MacItem>(new BoundedChannelOptions(_options.ChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = true
        });

        // Create CTS
        _producerCts = new CancellationTokenSource();
        _runCts = CancellationTokenSource.CreateLinkedTokenSource(ct, _producerCts.Token);

        // Start producer task
        _producerTask = ProducerLoopAsync(source, _runCts.Token);

        // Start worker tasks
        _workerTasks = new Task[_options.WorkerCount];
        for (int i = 0; i < _options.WorkerCount; i++)
        {
            int workerId = i;
            _workerTasks[i] = WorkerLoopAsync(workerId, _runCts.Token);
        }

        // Wait for all tasks to complete
        await Task.WhenAll(_workerTasks.Prepend(_producerTask)).ConfigureAwait(false);
    }

    /// <summary>
    /// Stop the scan engine gracefully.
    /// </summary>
    public async Task StopAsync()
    {
        // Set stopping flag immediately
        _stopping = true;

        // Cancel producer CTS
        if (_producerCts != null)
        {
            try { _producerCts.Cancel(); }
            catch { /* ignore */ }
        }

        // Cancel run CTS
        if (_runCts != null)
        {
            try { _runCts.Cancel(); }
            catch { /* ignore */ }
        }

        // Complete the channel
        _macChannel?.Writer.TryComplete();

        // Wait for producer to finish
        if (_producerTask != null)
        {
            try { await _producerTask.ConfigureAwait(false); }
            catch (OperationCanceledException) { /* expected */ }
            catch (Exception ex) { Console.WriteLine($"[ScanEngine] Producer error: {ex.Message}"); }
        }

        // Wait for workers to finish
        if (_workerTasks != null)
        {
            try { await Task.WhenAll(_workerTasks).ConfigureAwait(false); }
            catch (OperationCanceledException) { /* expected */ }
            catch (Exception ex) { Console.WriteLine($"[ScanEngine] Worker error: {ex.Message}"); }
        }

        // Dispose CTS objects
        _producerCts?.Dispose();
        _producerCts = null;
        _runCts?.Dispose();
        _runCts = null;

        // Clear dedup set
        _recentSet.Clear();

        // Reset pending counter
        Interlocked.Exchange(ref _pendingMacs, 0);

        // Reset task references
        _producerTask = null;
        _workerTasks = null;
        _macChannel = null;

        Console.WriteLine("[ScanEngine] Stopped");
    }

    #endregion

    #region Producer/Consumer

    private async Task ProducerLoopAsync(IAsyncEnumerable<MacItem> source, CancellationToken ct)
    {
        var writer = _macChannel!.Writer;

        try
        {
            await foreach (var item in source.WithCancellation(ct))
            {
                if (_stopping || ct.IsCancellationRequested)
                    break;

                // Normalize MAC
                var normalizedMac = NormalizeMacString(item.MAC);
                if (string.IsNullOrEmpty(normalizedMac))
                    continue;

                // Dedup check
                if (!_recentSet.AddIfNew(normalizedMac))
                    continue;

                item.MAC = normalizedMac;

                // Assign proxy if not set
                if (string.IsNullOrEmpty(item.Proxy) && _proxyPool.Count > 0)
                {
                    var idx = Interlocked.Increment(ref _proxyIndex) % _proxyPool.Count;
                    item.Proxy = _proxyPool[idx];
                }

                // Try to write to channel
                if (writer.TryWrite(item))
                {
                    // Increment pending counter AFTER successful write
                    Interlocked.Increment(ref _pendingMacs);
                }
                else
                {
                    // Wait and write
                    await writer.WriteAsync(item, ct).ConfigureAwait(false);
                    // Increment pending counter AFTER successful write
                    Interlocked.Increment(ref _pendingMacs);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on cancellation
        }
        catch (ChannelClosedException)
        {
            // Channel was closed
        }
        finally
        {
            writer.TryComplete();
        }
    }

    private async Task WorkerLoopAsync(int workerId, CancellationToken ct)
    {
        var reader = _macChannel!.Reader;

        while (!_stopping && !ct.IsCancellationRequested)
        {
            try
            {
                if (!await reader.WaitToReadAsync(ct).ConfigureAwait(false))
                    break;

                while (reader.TryRead(out var item))
                {
                    if (_stopping || ct.IsCancellationRequested)
                        break;

                    // Decrement pending counter on successful read
                    Interlocked.Decrement(ref _pendingMacs);

                    try
                    {
                        await ProcessMacItemAsync(item, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        Console.WriteLine($"[Worker-{workerId}] Error processing {item.MAC}: {ex.Message}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ChannelClosedException)
            {
                break;
            }
        }
    }

    private async Task ProcessMacItemAsync(MacItem item, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        ScanResult? result = null;

        try
        {
            result = await ScanMacAsync(item, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = new ScanResult
            {
                MAC = item.MAC,
                Portal = item.Portal ?? "",
                Status = "Error",
                Error = ex.Message
            };
        }

        sw.Stop();

        if (result != null)
        {
            result.LatencyMs = sw.Elapsed.TotalMilliseconds;
            result.ScannedAt = DateTime.UtcNow;

            // Update metrics
            Interlocked.Increment(ref _processedAll);
            lock (_latencyLock)
            {
                _totalLatencyMs += result.LatencyMs;
            }

            // Save result using background writers (fallback to sync if unavailable)
            if (_bgDbWriter != null)
            {
                if (!_bgDbWriter.TryEnqueue(result))
                {
                    DB.SaveResult(result);
                }
            }
            else
            {
                DB.SaveResult(result);
            }

            // Save raw response if hit
            if (result.Status == "Hit" && !string.IsNullOrEmpty(result.RawResponse))
            {
                if (_bgFileWriter != null)
                {
                    if (!_bgFileWriter.TryEnqueue(item.MAC, result.RawResponse))
                    {
                        HitWriter.SaveRawResponse(item.MAC, result.RawResponse);
                    }
                }
                else
                {
                    HitWriter.SaveRawResponse(item.MAC, result.RawResponse);
                }
            }
        }
    }

    #endregion

    #region Scanning

    private async Task<ScanResult> ScanMacAsync(MacItem item, CancellationToken ct)
    {
        // Try Variant1 first with controls
        var variant1Result = await RunVariant1WithControlsAsync(item, ct).ConfigureAwait(false);
        if (variant1Result != null && variant1Result.Status == "Hit")
        {
            return variant1Result;
        }

        // Fallback to standard scan
        return await StandardScanAsync(item, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Variant1 fallback wrapper with concurrency limiting, negative cache, and disposable handlers.
    /// </summary>
    private async Task<ScanResult?> RunVariant1WithControlsAsync(MacItem item, CancellationToken ct)
    {
        // Check negative cache
        var cacheKey = $"{item.Portal}:{item.MAC}";
        if (_variant1NegativeCache.TryGetValue(cacheKey, out var cachedAt))
        {
            if ((DateTime.UtcNow - cachedAt).TotalSeconds < _options.NegativeCacheSeconds)
            {
                return null; // Skip - recently failed
            }
            _variant1NegativeCache.TryRemove(cacheKey, out _);
        }

        // Limit concurrency
        await _variant1Semaphore.WaitAsync(ct).ConfigureAwait(false);
        HttpMessageHandler? handler = null;

        try
        {
            // Create disposable handler with proxy
            handler = CreateHandlerWithProxy(item.Proxy);
            using var client = new HttpClient(handler, disposeHandler: true);
            client.Timeout = TimeSpan.FromMilliseconds(_options.TimeoutMs);

            var result = await Variant1ScanAsync(client, item, ct).ConfigureAwait(false);

            // Cache negative result
            if (result == null || result.Status != "Hit")
            {
                _variant1NegativeCache[cacheKey] = DateTime.UtcNow;
            }

            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Cache as negative
            _variant1NegativeCache[cacheKey] = DateTime.UtcNow;
            return null;
        }
        finally
        {
            _variant1Semaphore.Release();
            // Handler is disposed by HttpClient
        }
    }

    private async Task<ScanResult?> Variant1ScanAsync(HttpClient client, MacItem item, CancellationToken ct)
    {
        // Example Variant1 implementation - adjust based on actual requirements
        var portal = item.Portal ?? "";
        var mac = item.MAC;

        try
        {
            var url = $"{portal.TrimEnd('/')}/portal.php?type=stb&action=handshake&prehash=0&token=&JsHttpRequest=1-xml";
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Cookie", $"mac={WebUtility.UrlEncode(mac)}; stb_lang=en; timezone=Europe/London");

            var response = await SendWithTimeoutAndRetryAsync(client, request, _options.TimeoutMs, _options.RetryCount, ct).ConfigureAwait(false);
            if (response == null || !response.IsSuccessStatusCode)
                return null;

            var content = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var handshakeText = content ?? "";

            // Try to parse token from handshake
            var token = TryFindJsonValue(handshakeText, "token");
            if (string.IsNullOrEmpty(token))
                return null;

            // Get profile
            var profileUrl = $"{portal.TrimEnd('/')}/portal.php?type=stb&action=get_profile&token={token}&JsHttpRequest=1-xml";
            var profileRequest = new HttpRequestMessage(HttpMethod.Get, profileUrl);
            profileRequest.Headers.Add("Cookie", $"mac={WebUtility.UrlEncode(mac)}; stb_lang=en; timezone=Europe/London");
            profileRequest.Headers.Add("Authorization", $"Bearer {token}");

            var profileResponse = await SendWithTimeoutAndRetryAsync(client, profileRequest, _options.TimeoutMs, _options.RetryCount, ct).ConfigureAwait(false);
            if (profileResponse == null || !profileResponse.IsSuccessStatusCode)
                return null;

            var profileContent = await profileResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            return new ScanResult
            {
                MAC = mac,
                Portal = portal,
                Status = "Hit",
                RawResponse = profileContent
            };
        }
        catch
        {
            return null;
        }
    }

    private async Task<ScanResult> StandardScanAsync(MacItem item, CancellationToken ct)
    {
        using var client = _httpClientFactory(item.Proxy);
        client.Timeout = TimeSpan.FromMilliseconds(_options.TimeoutMs);

        var portal = item.Portal ?? "";
        var mac = item.MAC;

        try
        {
            // Handshake
            var handshakeUrl = $"{portal.TrimEnd('/')}/portal.php?type=stb&action=handshake&prehash=0&token=&JsHttpRequest=1-xml";
            var request = new HttpRequestMessage(HttpMethod.Get, handshakeUrl);
            request.Headers.Add("Cookie", $"mac={WebUtility.UrlEncode(mac)}; stb_lang=en; timezone=Europe/London");

            var response = await SendWithTimeoutAndRetryAsync(client, request, _options.TimeoutMs, _options.RetryCount, ct).ConfigureAwait(false);
            if (response == null)
            {
                return new ScanResult { MAC = mac, Portal = portal, Status = "NoResponse" };
            }

            if (!response.IsSuccessStatusCode)
            {
                return new ScanResult { MAC = mac, Portal = portal, Status = "HttpError", Error = $"HTTP {(int)response.StatusCode}" };
            }

            var content = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var handshakeText = content ?? "";

            // Parse token
            var token = TryFindJsonValue(handshakeText, "token");
            if (string.IsNullOrEmpty(token))
            {
                return new ScanResult { MAC = mac, Portal = portal, Status = "NoToken" };
            }

            // Get profile
            var profileUrl = $"{portal.TrimEnd('/')}/portal.php?type=stb&action=get_profile&token={token}&JsHttpRequest=1-xml";
            var profileRequest = new HttpRequestMessage(HttpMethod.Get, profileUrl);
            profileRequest.Headers.Add("Cookie", $"mac={WebUtility.UrlEncode(mac)}; stb_lang=en; timezone=Europe/London");
            profileRequest.Headers.Add("Authorization", $"Bearer {token}");

            var profileResponse = await SendWithTimeoutAndRetryAsync(client, profileRequest, _options.TimeoutMs, _options.RetryCount, ct).ConfigureAwait(false);
            if (profileResponse == null || !profileResponse.IsSuccessStatusCode)
            {
                return new ScanResult { MAC = mac, Portal = portal, Status = "ProfileFailed" };
            }

            var profileContent = await profileResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            // Parse profile
            var result = ParseProfileResponse(mac, portal, profileContent ?? "");
            result.RawResponse = profileContent;

            // Try to fetch Xtream credentials if available
            var (xtreamUser, xtreamPass) = TryExtractXtreamCredsFromText(profileContent ?? "");
            result.XtreamUser = xtreamUser;
            result.XtreamPass = xtreamPass;

            return result;
        }
        catch (TaskCanceledException)
        {
            return new ScanResult { MAC = mac, Portal = portal, Status = "Timeout" };
        }
        catch (Exception ex)
        {
            return new ScanResult { MAC = mac, Portal = portal, Status = "Error", Error = ex.Message };
        }
    }

    private ScanResult ParseProfileResponse(string mac, string portal, string profileContent)
    {
        var result = new ScanResult
        {
            MAC = mac,
            Portal = portal,
            Status = "Unknown"
        };

        if (string.IsNullOrEmpty(profileContent))
        {
            result.Status = "EmptyProfile";
            return result;
        }

        try
        {
            using var doc = JsonDocument.Parse(profileContent);
            var root = doc.RootElement;

            // Check for js property
            if (root.TryGetProperty("js", out var js))
            {
                // Extract exp_date
                result.ExpDate = js.GetStringOrNull("exp_date");
                result.ActiveCons = js.GetIntOrNull("active_cons");
                result.MaxCons = js.GetIntOrNull("max_cons");
                result.IsRestreamer = js.GetBoolOrDefault("is_restreamer");

                result.Status = "Hit";
            }
            else
            {
                result.Status = "NoJsProperty";
            }
        }
        catch (JsonException)
        {
            result.Status = "InvalidJson";
        }

        return result;
    }

    #endregion

    #region Helper Methods

    public static string? NormalizeMacString(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac))
            return null;

        // Remove common prefixes and whitespace
        var normalized = mac.Trim().ToUpperInvariant();
        
        // Handle various MAC formats
        normalized = Regex.Replace(normalized, @"[^0-9A-F]", "");
        
        if (normalized.Length != 12)
            return null;

        // Format as XX:XX:XX:XX:XX:XX
        return string.Join(":", Enumerable.Range(0, 6).Select(i => normalized.Substring(i * 2, 2)));
    }

    public static HttpMessageHandler CreateHandlerWithProxy(string? proxyString)
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            UseCookies = false,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5
        };

        if (!string.IsNullOrEmpty(proxyString))
        {
            var normalized = TryNormalizeProxy(proxyString);
            if (normalized != null)
            {
                handler.Proxy = new WebProxy(normalized);
                handler.UseProxy = true;
            }
        }

        return handler;
    }

    public static HttpClient CreateDefaultHttpClient(string? proxy)
    {
        var handler = CreateHandlerWithProxy(proxy);
        return new HttpClient(handler, disposeHandler: true);
    }

    public static async Task<HttpResponseMessage?> SendWithTimeoutAndRetryAsync(
        HttpClient client,
        HttpRequestMessage request,
        int timeoutMs,
        int retryCount,
        CancellationToken ct)
    {
        for (int i = 0; i <= retryCount; i++)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);

                // Clone request for retries
                var clonedRequest = i == 0 ? request : CloneRequest(request);
                return await client.SendAsync(clonedRequest, cts.Token).ConfigureAwait(false);
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                if (i == retryCount)
                    return null;
                await Task.Delay(100 * (i + 1), ct).ConfigureAwait(false);
            }
            catch (HttpRequestException)
            {
                if (i == retryCount)
                    return null;
                await Task.Delay(100 * (i + 1), ct).ConfigureAwait(false);
            }
        }

        return null;
    }

    private static HttpRequestMessage CloneRequest(HttpRequestMessage original)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);
        foreach (var header in original.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        return clone;
    }

    public static async Task<List<string>> BuildProxyPoolAsync(
        List<string>? initialProxies,
        string? proxyFilePath,
        CancellationToken ct)
    {
        var proxies = new List<string>();

        // Add initial proxies
        if (initialProxies != null)
        {
            foreach (var proxy in initialProxies)
            {
                var normalized = TryNormalizeProxy(proxy);
                if (normalized != null)
                    proxies.Add(normalized);
            }
        }

        // Load from file if specified
        if (!string.IsNullOrEmpty(proxyFilePath) && File.Exists(proxyFilePath))
        {
            try
            {
                var lines = await File.ReadAllLinesAsync(proxyFilePath, ct).ConfigureAwait(false);
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    var normalized = TryNormalizeProxy(line.Trim());
                    if (normalized != null && !proxies.Contains(normalized))
                        proxies.Add(normalized);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BuildProxyPoolAsync] Error reading proxy file: {ex.Message}");
            }
        }

        return proxies;
    }

    public static string? TryNormalizeProxy(string? proxy)
    {
        if (string.IsNullOrWhiteSpace(proxy))
            return null;

        proxy = proxy.Trim();

        // Handle various formats
        if (!proxy.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !proxy.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
            !proxy.StartsWith("socks4://", StringComparison.OrdinalIgnoreCase) &&
            !proxy.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase))
        {
            proxy = "http://" + proxy;
        }

        try
        {
            var uri = new Uri(proxy);
            return uri.ToString().TrimEnd('/');
        }
        catch
        {
            return null;
        }
    }

    public static string MaskProxy(string? proxy)
    {
        if (string.IsNullOrEmpty(proxy))
            return "[no proxy]";

        try
        {
            var uri = new Uri(proxy);
            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                var parts = uri.UserInfo.Split(':');
                var firstPart = parts.Length > 0 && !string.IsNullOrEmpty(parts[0]) ? parts[0] : "";
                var maskedUser = !string.IsNullOrEmpty(firstPart) ? firstPart.Substring(0, Math.Min(2, firstPart.Length)) + "***" : "***";
                var maskedPass = parts.Length > 1 ? "***" : "";
                var userInfo = string.IsNullOrEmpty(maskedPass) ? maskedUser : $"{maskedUser}:{maskedPass}";
                return $"{uri.Scheme}://{userInfo}@{uri.Host}:{uri.Port}";
            }
            return $"{uri.Scheme}://{uri.Host}:{uri.Port}";
        }
        catch
        {
            return "[invalid proxy]";
        }
    }

    public static string[]? SplitMulti(string? input, params char[] separators)
    {
        if (string.IsNullOrEmpty(input))
            return null;

        return input.Split(separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    public static string? TryFindJsonValue(string? json, string key)
    {
        if (string.IsNullOrEmpty(json))
            return null;

        try
        {
            using var doc = JsonDocument.Parse(json);
            return FindJsonValueRecursive(doc.RootElement, key);
        }
        catch
        {
            // Fallback to regex
            var pattern = $"\"{Regex.Escape(key)}\"\\s*:\\s*\"([^\"]+)\"";
            var match = Regex.Match(json, pattern);
            return match.Success ? match.Groups[1].Value : null;
        }
    }

    private static string? FindJsonValueRecursive(JsonElement element, string key)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in element.EnumerateObject())
            {
                if (prop.Name.Equals(key, StringComparison.OrdinalIgnoreCase))
                {
                    return prop.Value.ValueKind == JsonValueKind.String
                        ? prop.Value.GetString()
                        : prop.Value.ToString();
                }

                var nested = FindJsonValueRecursive(prop.Value, key);
                if (nested != null)
                    return nested;
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var nested = FindJsonValueRecursive(item, key);
                if (nested != null)
                    return nested;
            }
        }

        return null;
    }

    public static Dictionary<string, string> ParseQueryString(string? queryString)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrEmpty(queryString))
            return result;

        // Remove leading ?
        if (queryString.StartsWith("?"))
            queryString = queryString.Substring(1);

        foreach (var part in queryString.Split('&'))
        {
            var idx = part.IndexOf('=');
            if (idx > 0)
            {
                var key = WebUtility.UrlDecode(part.Substring(0, idx));
                var value = WebUtility.UrlDecode(part.Substring(idx + 1));
                result[key] = value;
            }
        }

        return result;
    }

    public static string? NormalizeGetPhpWithNestedPassword(string? url)
    {
        if (string.IsNullOrEmpty(url))
            return null;

        try
        {
            var uri = new Uri(url);
            var query = ParseQueryString(uri.Query);

            // Look for nested password parameter
            if (query.TryGetValue("password", out var password) && password.Contains("&"))
            {
                var nestedParams = ParseQueryString(password);
                foreach (var (key, value) in nestedParams)
                {
                    if (!query.ContainsKey(key))
                        query[key] = value;
                }
                // Update password to be just the password value
                var passwordParts = password.Split('&');
                query["password"] = passwordParts.Length > 0 && !string.IsNullOrEmpty(passwordParts[0]) ? passwordParts[0] : password;
            }

            var sb = new StringBuilder();
            sb.Append($"{uri.Scheme}://{uri.Host}");
            if (!uri.IsDefaultPort)
                sb.Append($":{uri.Port}");
            sb.Append(uri.AbsolutePath);
            sb.Append("?");
            sb.Append(string.Join("&", query.Select(kv => $"{WebUtility.UrlEncode(kv.Key)}={WebUtility.UrlEncode(kv.Value)}")));

            return sb.ToString();
        }
        catch
        {
            return url;
        }
    }

    public static int? ExtractDaysFromCombinedText(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return null;

        // Look for patterns like "30 days", "365days", "30d"
        var match = Regex.Match(text, @"(\d+)\s*(?:days?|d\b)", RegexOptions.IgnoreCase);
        if (match.Success && int.TryParse(match.Groups[1].Value, out var days))
            return days;

        return null;
    }

    public static DateTime? TryParseDateFlexible(string? dateString)
    {
        if (string.IsNullOrEmpty(dateString))
            return null;

        // Try Unix timestamp
        if (long.TryParse(dateString, out var unixTimestamp))
        {
            if (unixTimestamp > 0 && unixTimestamp < 253402300800) // Valid range
            {
                return DateTimeOffset.FromUnixTimeSeconds(unixTimestamp).UtcDateTime;
            }
        }

        // Try various date formats
        string[] formats = new[]
        {
            "yyyy-MM-dd",
            "yyyy-MM-dd HH:mm:ss",
            "dd-MM-yyyy",
            "dd/MM/yyyy",
            "MM/dd/yyyy",
            "yyyy/MM/dd",
            "dd.MM.yyyy",
            "yyyy.MM.dd"
        };

        foreach (var format in formats)
        {
            if (DateTime.TryParseExact(dateString, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                return dt;
        }

        // Try general parse
        if (DateTime.TryParse(dateString, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
            return parsed;

        return null;
    }

    public static List<string>? ExtractLiveListFromCombined(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return null;

        var results = new List<string>();

        // Look for comma or newline separated lists
        var parts = text.Split(new[] { ',', '\n', '\r', '|' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            if (!string.IsNullOrEmpty(trimmed))
                results.Add(trimmed);
        }

        return results.Count > 0 ? results : null;
    }

    public static (string? User, string? Pass) TryExtractXtreamCredsFromText(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return (null, null);

        // Try JSON approach first
        try
        {
            using var doc = JsonDocument.Parse(text);
            var user = FindJsonValueRecursive(doc.RootElement, "username");
            var pass = FindJsonValueRecursive(doc.RootElement, "password");
            if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(pass))
                return (user, pass);
        }
        catch { }

        // Regex fallback
        var userMatch = Regex.Match(text, @"username[""']?\s*[:=]\s*[""']?([^""'\s,}]+)", RegexOptions.IgnoreCase);
        var passMatch = Regex.Match(text, @"password[""']?\s*[:=]\s*[""']?([^""'\s,}]+)", RegexOptions.IgnoreCase);

        var extractedUser = userMatch.Success ? userMatch.Groups[1].Value : null;
        var extractedPass = passMatch.Success ? passMatch.Groups[1].Value : null;

        return (extractedUser, extractedPass);
    }

    public static async Task<string?> FetchXtreamPlayerApiAsync(
        HttpClient client,
        string baseUrl,
        string username,
        string password,
        CancellationToken ct)
    {
        try
        {
            var url = $"{baseUrl.TrimEnd('/')}/player_api.php?username={WebUtility.UrlEncode(username)}&password={WebUtility.UrlEncode(password)}";
            var response = await client.GetAsync(url, ct).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            }
        }
        catch
        {
            // Ignore errors
        }

        return null;
    }

    #endregion

    #region Disposal

    public void Dispose()
    {
        // Set stopping flag and perform synchronous cleanup
        _stopping = true;
        _producerCts?.Cancel();
        _runCts?.Cancel();
        _macChannel?.Writer.TryComplete();
        _recentSet.Clear();
        Interlocked.Exchange(ref _pendingMacs, 0);

        _producerCts?.Dispose();
        _runCts?.Dispose();
        _bgDbWriter?.Dispose();
        _bgFileWriter?.Dispose();
        _metricsService?.Dispose();
        _variant1Semaphore.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);

        if (_bgDbWriter != null)
        {
            await _bgDbWriter.FlushAsync().ConfigureAwait(false);
            _bgDbWriter.Dispose();
        }

        if (_bgFileWriter != null)
        {
            await _bgFileWriter.FlushAsync().ConfigureAwait(false);
            _bgFileWriter.Dispose();
        }

        _metricsService?.Dispose();
        _variant1Semaphore.Dispose();
    }

    #endregion
}

#endregion

#region AsyncEnumerable Extension

public static class AsyncEnumerableExtensions
{
#pragma warning disable CS1998 // Async method lacks 'await' operators
    public static async IAsyncEnumerable<T> ToAsyncEnumerable<T>(this IEnumerable<T> source)
#pragma warning restore CS1998
    {
        foreach (var item in source)
        {
            yield return item;
        }
    }
}

#endregion
