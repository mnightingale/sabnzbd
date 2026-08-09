# Grafana dashboard for the instrumentation runs

Live view of a measurement run: write amplification, cache saturation, device I/O,
RSS, and CPU split by thread role.

Grafana cannot scrape a `/metrics` endpoint on its own, so the chain is:

```
SABnzbd  --mode=instrumentation-->  instrumentation_poll.py  --/metrics-->  Prometheus  -->  Grafana
```

## 1. SABnzbd

Enable the `instrumentation` special (Config > Special), or:

```bash
curl 'http://127.0.0.1:8080/api?mode=set_config&section=misc&keyword=instrumentation&value=1&apikey=KEY'
```

## 2. Poller

```bash
python tools/instrumentation_poll.py --apikey KEY --out run1 --interval 1 --prometheus-port 9109
```

`--interval` only controls how often the poller refreshes its view. Because the
counters are exported raw, Prometheus may scrape faster or slower without distorting
anything: an unchanged counter scraped twice contributes nothing.

## 3. Prometheus

```yaml
# prometheus.yml
global:
  scrape_interval: 1s        # 15s default is too coarse for a dev run
  evaluation_interval: 1s

scrape_configs:
  - job_name: sabnzbd
    static_configs:
      - targets: ["127.0.0.1:9109"]
```

```bash
prometheus --config.file=prometheus.yml --storage.tsdb.retention.time=7d
```

Docker, if you would rather not install it:

```bash
docker run --rm -p 9090:9090 \
  -v "$PWD/prometheus.yml:/etc/prometheus/prometheus.yml" \
  --add-host host.docker.internal:host-gateway \
  prom/prometheus
```

with the target changed to `host.docker.internal:9109`.

## 4. Grafana

Add a Prometheus data source pointing at `http://127.0.0.1:9090`, then import
`sabnzbd-instrumentation.json` (Dashboards > New > Import) and pick that data source
when prompted.

**Refresh rate.** The dashboard ships at 5s because Grafana clamps to
`min_refresh_interval`, which defaults to 5s. For a dev run, set it lower:

```ini
# grafana.ini
[dashboards]
min_refresh_interval = 1s
```

Restart Grafana, then pick 1s from the refresh dropdown. Without that change Grafana
silently keeps 5s rather than reporting an error.

**Rate window.** Panels use `$__rate_interval`, which Grafana derives from the scrape
interval and the panel width. On a 1s scrape it resolves to a few seconds, which is
responsive but noisy; widen the time range to smooth it without re-running anything.
That flexibility is the reason the poller exports counters rather than rates.

## Reading it

- **Amplification** is the headline. 1.0 means every decoded byte was written once.
  Above that is the article cache overflowing to the admin directory and reading it
  straight back, so the payload lands on the download disk twice.
- **Cache saturation and spill onset** is the causal chart: spill should begin exactly
  as cache usage reaches 100%. Spill starting below 100% means something other than
  cache pressure is forcing articles out.
- **Device I/O vs decoded payload** proves the amplification from the kernel rather
  than from SABnzbd's own counters. A sustained gap between the two is the extra write.
- **CPU by role**: receive-thread cost is the figure that matters. After
  `decoder.process()` returns, that thread holds the GIL through `save_article` and
  assembler admission, which serialises across every receive thread.

## Not seeing any spill?

The overflow regime needs the cache to be unable to drain. Reaching it does not need
slow hardware: shrink `misc.cache_limit`, since overflow is only
`cache_used + article > cache_limit`. To throttle the disk itself on Linux, run
SABnzbd under `systemd-run -p IOWriteBandwidthMax=...`.

Device panels are Linux and macOS only, and utilisation is Linux only — macOS exposes
no equivalent of `io_ticks`.
