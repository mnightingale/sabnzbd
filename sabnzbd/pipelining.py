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
from dataclasses import dataclass, field
from typing import Optional

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
