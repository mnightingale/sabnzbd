#!/usr/bin/python3 -OO
# Copyright 2007-2026 by The SABnzbd-Team (sabnzbd.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
sabnzbd.pipelining - how many requests a server is worth having in flight

Depth only pays for itself while it covers the gap between finishing one article and the
next one starting to arrive. One round trip of gap needs one extra request to cover it,
so the depth worth holding follows from the round trip and how long an article takes:

    1 + ceil(round trip / transfer time)

Above that, the requests are not waiting on the network, they are waiting on each other,
and all the extra depth buys is articles committed to a server earlier than they need to
be. Below it, the connection sits idle between articles.
"""

import logging
import math
import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import sabctools

import sabnzbd
from sabnzbd.decorators import synchronized

# Seconds between reconsidering the depths
SAMPLE_INTERVAL = 2.0
# Weight of the newest reading in the smoothed figures
EMA_ALPHA = 0.3
# Responses a window needs before it is allowed to say anything
MIN_RESPONSES = 8
# Seconds a round trip measurement stays worth believing
RTT_WINDOW = 120.0
# Consecutive windows agreeing before the depth is lowered, and before it is raised.
# Raising is the safe direction, so it takes less convincing.
LOWER_AFTER = 3
RAISE_AFTER = 2
# Seconds at a depth before it may move again
DWELL = 15.0
# Seconds before a deeper pipeline is tried again regardless of what the numbers say
REPROBE_INTERVAL = 300.0
# Throughput a probe has to gain to be kept
REPROBE_GAIN = 0.03
# Share of a downloader pass spent on the sockets above which the receive threads, not
# the network, are what the connections are waiting for
BUSY_FRACTION_LIMIT = 0.8


@dataclass(slots=True)
class PipelineSample:
    """What one server did over one window"""

    now: float
    configured: int
    responses: int
    # Mean seconds from an article's first byte to its last
    transfer_time: float
    # wait_time of responses whose request went out to an idle connection
    round_trips: list[float] = field(default_factory=list)
    # Round trip of last resort, from the TCP handshake
    connect_time: Optional[float] = None
    # Connection time spent waiting rather than receiving, as a fraction
    idle_fraction: float = 0.0
    throughput: float = 0.0
    # The downloader was holding the connections back itself
    receiver_limited: bool = False


class ServerPipelineController:
    """Holds one server's depth at what its measurements say is worth having"""

    def __init__(self, configured: int):
        self.depth: int = configured
        self.transfer_time: Optional[float] = None
        self.idle_fraction: Optional[float] = None
        self.round_trips: list[tuple[float, float]] = []
        self.want: Optional[int] = None
        self.agreed: int = 0
        self.settled_at: float = 0.0
        self.probe_at: Optional[float] = None
        self.probing_from: Optional[int] = None
        self.probe_throughput: float = 0.0
        self.tcp: Optional[dict] = None

    def reset(self):
        """Forget what was measured, for a server that stopped downloading"""
        self.transfer_time = None
        self.idle_fraction = None
        self.round_trips.clear()
        self.want = None
        self.agreed = 0
        self.probing_from = None

    def sample(self, sample: PipelineSample) -> int:
        """Fold in one window and return the depth to use"""
        self.depth = min(self.depth, sample.configured)

        # A window that measured nothing usable neither confirms nor overturns anything
        if sample.receiver_limited or sample.responses < MIN_RESPONSES or sample.transfer_time <= 0:
            return self.depth

        self.transfer_time = self.smooth(self.transfer_time, sample.transfer_time)
        self.idle_fraction = self.smooth(self.idle_fraction, sample.idle_fraction)
        self.record_round_trips(sample)

        if self.finish_probe(sample):
            return self.depth

        if (cover := self.round_trip(sample)) is None:
            return self.depth

        want = min(max(1 + math.ceil(cover / self.transfer_time), 1), sample.configured)
        self.want = want

        if self.start_probe(sample):
            return self.depth

        return self.move_towards(want, sample)

    @staticmethod
    def smooth(current: Optional[float], reading: float) -> float:
        if current is None:
            return reading
        return EMA_ALPHA * reading + (1 - EMA_ALPHA) * current

    def record_round_trips(self, sample: PipelineSample):
        """Keep the round trips seen recently, dropping the ones that have aged out"""
        self.round_trips.extend((sample.now, value) for value in sample.round_trips if value > 0)
        cutoff = sample.now - RTT_WINDOW
        self.round_trips = [entry for entry in self.round_trips if entry[0] >= cutoff]

    def round_trip(self, sample: PipelineSample) -> Optional[float]:
        """What one idle round trip currently costs.

        The median rather than the minimum: the gap a shallow pipeline leaves is a round
        trip at today's latency, and taking the floor would understate it and so
        understate the depth needed."""
        if self.round_trips:
            return statistics.median(value for _, value in self.round_trips)
        return sample.connect_time

    def start_probe(self, sample: PipelineSample) -> bool:
        """Occasionally go a step deeper to check the measurements are not stuck low"""
        if self.probe_at is None:
            self.probe_at = sample.now + REPROBE_INTERVAL
            return False
        if self.probing_from is not None or sample.now < self.probe_at:
            return False
        if self.depth >= sample.configured or sample.throughput <= 0:
            self.probe_at = sample.now + REPROBE_INTERVAL
            return False

        self.probing_from = self.depth
        self.probe_throughput = sample.throughput
        self.depth += 1
        self.settled_at = sample.now
        self.agreed = 0
        logging.debug("Trying pipelining depth %d to see whether it is worth holding", self.depth)
        return True

    def finish_probe(self, sample: PipelineSample) -> bool:
        """Keep the deeper pipeline only if it actually moved more data"""
        if self.probing_from is None:
            return False
        if sample.now - self.settled_at < DWELL:
            return True

        gained = sample.throughput >= self.probe_throughput * (1 + REPROBE_GAIN)
        if not gained:
            self.depth = self.probing_from
        logging.debug(
            "Pipelining depth %d %s, staying at %d",
            self.probing_from + 1,
            "paid off" if gained else "gained nothing",
            self.depth,
        )
        self.probing_from = None
        self.probe_at = sample.now + REPROBE_INTERVAL
        self.settled_at = sample.now
        self.agreed = 0
        return True

    def move_towards(self, want: int, sample: PipelineSample) -> int:
        """Step one towards the wanted depth, once enough windows have agreed"""
        if want == self.depth:
            self.agreed = 0
            return self.depth

        needed = RAISE_AFTER if want > self.depth else LOWER_AFTER
        self.agreed += 1
        if self.agreed < needed or sample.now - self.settled_at < DWELL:
            return self.depth

        self.depth += 1 if want > self.depth else -1
        self.agreed = 0
        self.settled_at = sample.now
        return self.depth


class PipeliningMonitor:
    """Reads what the connections measured and tells each server what depth to hold"""

    def __init__(self):
        self.lock = threading.RLock()
        self.sampled_at: float = 0.0

    @synchronized()
    def sample(self):
        """Called every downloader tick, acts on its own slower interval"""
        now = time.monotonic()
        if now - self.sampled_at < SAMPLE_INTERVAL:
            return
        self.sampled_at = now

        limited = self.receiver_limited()
        for server in sabnzbd.Downloader.servers:
            self.sample_server(server, now, limited)

    @synchronized()
    def reset(self):
        """Drop what was measured, for servers that stopped downloading"""
        for server in sabnzbd.Downloader.servers:
            server.pipeline_controller.reset()

    @staticmethod
    def receiver_limited() -> bool:
        """Whether the downloader was holding the connections back itself.

        Any of these inflate the measurements without the pipeline having anything to do
        with it, so a window that saw one is not evidence either way."""
        if sabnzbd.Assembler.delay() > 0:
            return True
        downloader = sabnzbd.Downloader
        if downloader.bandwidth_limit and sabnzbd.BPSMeter.bps >= downloader.bandwidth_limit:
            return True
        return downloader.receive_busy_fraction() > BUSY_FRACTION_LIMIT

    @staticmethod
    def tcp_snapshot(server) -> Optional[dict]:
        """What the kernel says about one of this server's connections.

        One is enough: they share a path, and the figures are for looking at rather than
        for the controller to act on."""
        for nw in server.busy_threads:
            if nw.nntp and (info := sabctools.tcp_info(nw.nntp.sock)):
                return info
        return None

    def sample_server(self, server, now: float, limited: bool):
        """Take one window from a server's connections and apply the answer"""
        responses = 0
        transfer_total = 0.0
        idle_total = 0.0
        round_trips = []

        for nw in tuple(server.busy_threads) + tuple(server.idle_threads):
            # Read and clear rather than tracking deltas; a response landing between the
            # two only costs this window a little accuracy
            responses += nw.responses_seen
            transfer_total += nw.transfer_total
            idle_total += nw.idle_total
            if nw.round_trip_count:
                round_trips.append(nw.round_trip_total / nw.round_trip_count)
            nw.responses_seen = 0
            nw.transfer_total = 0.0
            nw.idle_total = 0.0
            nw.round_trip_total = 0.0
            nw.round_trip_count = 0

        engaged = transfer_total + idle_total
        sample = PipelineSample(
            now=now,
            configured=server.pipelining_requests(),
            responses=responses,
            transfer_time=transfer_total / responses if responses else 0.0,
            round_trips=round_trips,
            connect_time=server.addrinfo.connection_time if server.addrinfo else None,
            idle_fraction=idle_total / engaged if engaged else 0.0,
            throughput=sabnzbd.BPSMeter.server_bps.get(server.id, 0.0),
            receiver_limited=limited,
        )

        server.pipeline_controller.tcp = self.tcp_snapshot(server)

        depth = server.pipeline_controller.sample(sample)
        if depth != server.effective_pipelining:
            logging.info(
                "Pipelining depth for %s now %d of %d (round trip %s, article %s, idle %.0f%%)",
                server.host,
                depth,
                sample.configured,
                to_time(server.pipeline_controller.round_trip(sample)),
                to_time(server.pipeline_controller.transfer_time),
                (server.pipeline_controller.idle_fraction or 0.0) * 100,
            )
            log_tcp_info(server.host, server.pipeline_controller.tcp)
            server.effective_pipelining = depth


def to_time(seconds: Optional[float]) -> str:
    if seconds is None:
        return "unknown"
    return "%.0f ms" % (seconds * 1000)


def log_tcp_info(host: str, info: Optional[dict]):
    """Put the kernel's own view alongside a depth change, where there is one"""
    if not info:
        return
    logging.debug(
        "%s: kernel reports rtt %s, minimum %s, receive window %s, reordered %s, retransmitted %s (%s)",
        host,
        to_micros(info["rtt"]),
        to_micros(info["min_rtt"]),
        info["rcv_wnd"],
        info["bytes_reordered"] if info["bytes_reordered"] is not None else info["packets_reordered"],
        info["bytes_retrans_out"],
        info["source"],
    )


def to_micros(value: Optional[int]) -> str:
    if value is None:
        return "unknown"
    return "%.1f ms" % (value / 1000)
